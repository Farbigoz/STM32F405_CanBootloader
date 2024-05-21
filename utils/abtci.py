import enum
import random
import struct

from typing import Union

from crc import GetCrc8, GetCrc16


class abtci_can_id:
    interface: int
    number: int
    command: int
    type: int

    def __init__(self, interface: int, number: int, command: int, type: int):
        self.interface = interface
        self.number = number
        self.command = command
        self.type = type

    def to_id(self) -> int:
        id = 0

        id |= (self.interface & 0b111      ) << (0)
        id |= (self.number    & 0b11111111 ) << (3)
        id |= (self.command   & 0b111111111) << (3 + 8)
        id |= (self.type      & 0b111111111) << (3 + 8 + 9)

        return id

    @classmethod
    def from_id(cls, id: int) -> "abtci_can_id":
        interface  = (id >> (0))            & 0b111
        number     = (id >> (3))            & 0b11111111
        command    = (id >> (3 + 8))        & 0b111111111
        type       = (id >> (3 + 8 + 9))    & 0b111111111

        return cls(interface, number, command, type)
    

class abtci_type(enum.IntEnum):
    kip         = 0
    mu          = 1
    mpp         = 2
    gks_out     = 3
    gks_in      = 4
    gks_ars     = 5
    mec         = 7
    mus         = 8
    mss         = 11
    mdc_kidx    = 12
    marm        = 13

    btl_cu     = 0x20
    btl_mpp    = 0x21
    btl_gks    = 0x22
    btl_ktrc   = 0x23
    btl_mec_v2 = 0x24
    btl_cc_1   = 0x25
    btl_cc_2   = 0x26
    btl_cc_3   = 0x27
    btl_cc_4   = 0x28
    btl_cc_5   = 0x29


class abtci_interface(enum.IntEnum):
    sys_a = 0  # < Системный А
    sys_b = 1  # < Системный Б
    inf_a = 2  # < Информационно - Диагностический А
    inf_b = 3  # < Информационно - Диагностический Б
    out_a = 4  # < Межсистемный А
    out_b = 5  # < Межсистемный Б


class abtci_btl_cmd(enum.IntEnum):
# Команды информирования
    btl_inf                 = 10    #< Информация бутлодера
    btl_damaged             = 11    #< Бутлодер неисправен
    btl_wrong_msg           = 12    #< Неправильное сообщение (Неверная длина данных)
    btl_no_space_available  = 13    #< Нет свободного места
    btl_fw_damaged          = 17    #< Прошивка повреждена (Ошибка контрольной суммы)
    blt_fw_run              = 18    #< Запуск прошивки
    btl_safe_cell_fault     = 19    #< Повреждение ячейки безопасности (Отсутствуют прерывания)
# Команды управления
    btl_erase               = 20    #< Удаление прошивки
    btl_flash               = 21    #< Блок прошивки
    btl_request             = 22    #< Запрос блока прошивки
    btl_force_run           = 23    #< Принудительный запуск прошивки
    btl_halt                = 24    #< Остановка в бутлоадере



class abtci_btl_cmd_inf:
    version:    int
    size:       int
    checksum:   int

    def __init__(self):
        self.version = 0
        self.size = 0
        self.checksum = 0

    @classmethod
    def from_data(self, data: bytes) -> Union["abtci_btl_cmd_inf", None]:
        if len(data) != 8:
            return None
        
        inst = abtci_btl_cmd_inf()

        unpkacked = struct.unpack("!B3BL", data)
        
        inst.version = unpkacked[0]
        inst.size |= unpkacked[1] << 16
        inst.size |= unpkacked[2] << 8
        inst.size |= unpkacked[3] << 0
        inst.checksum |= unpkacked[4]

        return inst


class abtci_btl_cmd_erase:
    def to_data(self) -> bytes:
        random_num = random.randint(0x00000000, 0xffffffff)
        return struct.pack("!LL", random_num, (~random_num) & 0xffffffff)


class abtci_btl_cmd_ctrl_data:
    def to_data(self, btl_ver: int) -> bytes:
        random_num = random.randint(0x0000, 0xffff)
        data = struct.pack("!BBHH", btl_ver, 0, random_num, (~random_num) & 0xffff)
        data += struct.pack("!H", GetCrc16(data))
        return data


class abtci_btl_cmd_flash:
    def to_data(self, number: int, data: bytes) -> bytes:
        number_24 = [0]*3
        number_24[2] = (number >> 0) & 0xFF
        number_24[1] = (number >> 8) & 0xFF
        number_24[0] = (number >> 16) & 0xFF

        checksum = GetCrc8([number_24[0], number_24[1], number_24[2]] + list(data))

        return struct.pack("!B3B", checksum, *number_24) + data
    

class abtci_btl_cmd_request:
    number:   int

    def __init__(self):
        self.number = 0

    @classmethod
    def from_data(self, data: bytes) -> Union["abtci_btl_cmd_request", None]:
        if len(data) != 3:
            return None
        
        inst = abtci_btl_cmd_request()

        unpkacked = struct.unpack("!3B", data)
        
        inst.number |= unpkacked[2] << 0
        inst.number |= unpkacked[1] << 8
        inst.number |= unpkacked[0] << 16

        return inst
    

# Значения из abtci_protocol.hpp
MODULE_TYPES = {
    "cu"    : abtci_type.btl_cu,
    "mpp"   : abtci_type.btl_mpp,
    "gks"   : abtci_type.btl_gks,
    "ktrc"  : abtci_type.btl_ktrc,
    "mec-v2": abtci_type.btl_mec_v2,
    "cc-1"  : abtci_type.btl_cc_1,
    "cc-2"  : abtci_type.btl_cc_2,
    "cc-3"  : abtci_type.btl_cc_3,
    "cc-4"  : abtci_type.btl_cc_4,
    "cc-5"  : abtci_type.btl_cc_5,
}

MODULE_NAME = {
    abtci_type.btl_cu:     "КУ",
    abtci_type.btl_mpp:    "МПП",
    abtci_type.btl_gks:    "ГКС",
    abtci_type.btl_ktrc:   "КТРЦ",
    abtci_type.btl_mec_v2: "МЭЦ",
    abtci_type.btl_cc_1:   "КС 1",
    abtci_type.btl_cc_2:   "КС 2",
    abtci_type.btl_cc_3:   "КС 3",
    abtci_type.btl_cc_4:   "КС 4",
    abtci_type.btl_cc_5:   "КС 5",
}

COMMAND_DESCR = {
    abtci_btl_cmd.btl_inf:                "Информация",
    abtci_btl_cmd.btl_damaged:            "Бутлодер повреждён (Ошибка контрольной суммы)",
    abtci_btl_cmd.btl_fw_damaged:         "Прошивка повреждена (Ошибка контрольной суммы)",
    abtci_btl_cmd.blt_fw_run:             "Запуск прошивки",
    abtci_btl_cmd.btl_safe_cell_fault:    "Неисправность ячейки безопасности",
    abtci_btl_cmd.btl_wrong_msg:          "Неправильное сообщение (Неверная длина данных)",
    abtci_btl_cmd.btl_no_space_available: "Нет свободного места",
    abtci_btl_cmd.btl_erase:              "Стирание прошивки",
    abtci_btl_cmd.btl_flash:              "Запись блока прошивки",
    abtci_btl_cmd.btl_request:            "Запрос блока прошивки",
}

INTERFACE_NAME = {
    abtci_interface.sys_a: "СИС-А",
    abtci_interface.sys_b: "СИС-Б",
    abtci_interface.inf_a: "ИНФ-А",
    abtci_interface.inf_b: "ИНФ-Б"
}

