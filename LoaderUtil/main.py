import os
import sys
import time
import threading

from typing import List, Optional

from libs.CAN import CanChannel, CanMessage
from libs.CAN.CHAI import FindChaiLib, ChaiLib, FrameFormat, BaudSpeed, ChaiChannel

from libs.CRC.crc import GetCrc32


FIRMWARE_PACKET_SIZE = 4

CAN_SPEED = BaudSpeed.BCI_100K

DEVICE_TYPES = {
    "DEBUG": 0xdb,
    "KRC": 0x81,
}


# CAN команды
class COMMAND:
    BOOTLOADER_WAIT = 0x11  # Состояние ожидания
    BOOTLOADER_BAD_CHECKSUM = 0x12  # Неверная контрольная сумма бутлоадера

    FIRMWARE_START = 0x21  # Начало прошивания
    FIRMWARE_PACKET = 0x22  # Пакет прошивки
    FIRMWARE_REQUEST_PACKET = 0x23  # Запрос пакета прошивки (под определённым номером)
    FIRMWARE_FINISH = 0x24  # Окончание прошивания
    FIRMWARE_OK = 0x25  # Прошивка успешно завершена
    FIRMWARE_BAD = 0x26  # Прошивка завершена с ошибками (TODO: Возврат кода ошибки)

    PROGRAM_START = 0x31  # Запуск основной программы
    PROGRAM_BAD_CHECKSUM = 0x32  # Неверная контрольная сумма основной программы


# Глобальные переменные
class VAR:
    # Выбранный тип устройства
    DEVICE_TYPE: int = DEVICE_TYPES["KRC"]

    # Текущий номер пакета прошивки
    FIRMWARE_PACKET_NUMBER: int = 0

    # Выбранный канал CAN
    CAN_CHANNEL: CanChannel = None

    # Файл прошивки
    FIRMWARE_FILE: "FirmwareFile" = None

    # Процесс прошивания
    FIRMWARE_PROCESS: bool = False

    #
    START_FIRMWARE_TIME: int = 0
    END_FIRMWARE_TIME: int = 0


# Декодер айди CAN сообщения
class CanMessageId:
    interface: int  = 0
    moduleId: int   = 0
    command: int    = 0
    moduleType: int = 0

    def ToInt(self) -> int:
        id_: int = 0

        id_ |= self.moduleType & 0b111111111

        id_ <<= 9
        id_ |= self.command & 0b111111111

        id_ <<= 8
        id_ |= self.moduleId & 0b11111111

        id_ <<= 3
        id_ |= self.interface & 0b111

        return id_

    @classmethod
    def FromInt(cls, id_: int) -> "CanMessageId":
        inst = cls()

        inst.interface = id_ & 0b111
        id_ >>= 3

        inst.moduleId = id_ & 0b11111111
        id_ >>= 8

        inst.command = id_ & 0b111111111
        id_ >>= 9

        inst.moduleType = id_ & 0b111111111

        return inst


# Файл прошивки
class FirmwareFile:
    _binPath: str
    _cheksum: int
    _raw: bytes

    def __init__(self, binPath: str):
        if not binPath.endswith(".bin"):
            Exception(f"Данный формат прошивки не поддерживается")

        if not (os.path.exists(binPath) and os.path.isfile(binPath)):
            Exception(f"Файл прошивки \"{binPath}\" не существует!")

        self._binPath = binPath

        with open(self._binPath, "rb") as f:
            self._raw = f.read()

        self._cheksum = GetCrc32(self._raw)

    @property
    def checksum(self) -> int:
        return self._cheksum

    @property
    def size(self) -> int:
        return len(self._raw)

    def getPacketData(self, packetDataSize: int, packetNumber: int) -> List[int]:
        data = [0] * packetDataSize

        for i in range(packetDataSize):
            byteNum = packetNumber * packetDataSize + i

            if byteNum >= self.size:
                break

            data[i] = self._raw[byteNum]

        return data


def List_to_Uint32(list: List[int]) -> int:
    uint32 = 0
    uint32 |= list[0]
    uint32 |= list[1] << 8
    uint32 |= list[2] << 16
    uint32 |= list[3] << 24
    return uint32


def Uint32_to_List(uint32: int) -> List[int]:
    out = [0] * 4
    out[0] = (uint32 >> 0) & 0xff
    out[1] = (uint32 >> 8) & 0xff
    out[2] = (uint32 >> 16) & 0xff
    out[3] = (uint32 >> 24) & 0xff
    return out


# Работа с CAN-ом

def GetCanId(command: int) -> int:
    inst = CanMessageId()
    inst.interface = 0x0
    inst.moduleId = 0x0
    inst.command = command
    inst.moduleType = VAR.DEVICE_TYPE
    return inst.ToInt()


def PrintCanMessage(type: str, msg: CanMessage):
    msgId = CanMessageId.FromInt(msg.ID)

    if msgId.command == COMMAND.BOOTLOADER_WAIT:
        print(f"[{type}] Бутлоадер в состоянии ожидания")

    elif msgId.command == COMMAND.BOOTLOADER_BAD_CHECKSUM:
        print(f"[{type}] Неверная контрольная сумма бутлоадера")

    elif msgId.command == COMMAND.FIRMWARE_START:
        print(f"[{type}] Начало прошивания")

    #elif msgId.command == COMMAND.FIRMWARE_PACKET:
    #    print(f"[{type}] Пакет прошивки")

    elif msgId.command == COMMAND.FIRMWARE_REQUEST_PACKET:
        print(f"[{type}] Запрос пакета прошивки: {List_to_Uint32(msg.data)}")

    elif msgId.command == COMMAND.FIRMWARE_FINISH:
        print(f"[{type}] Окончание прошивания")

    elif msgId.command == COMMAND.FIRMWARE_OK:
        print(f"[{type}] Прошивка успешно завершена")

    elif msgId.command == COMMAND.FIRMWARE_BAD:
        print(f"[{type}] Прошивка завершена с ошибками")

    elif msgId.command == COMMAND.PROGRAM_START:
        print(f"[{type}] Запуск основной программы")

    elif msgId.command == COMMAND.PROGRAM_BAD_CHECKSUM:
        print(f"[{type}] Неверная контрольная сумма основной программы")


def SendCommand(command: int, data: Optional[List[int]] = None):
    if data is None:
        data = []

    msg = CanMessage()
    msg.ID = GetCanId(command)
    msg.length = len(data)
    msg.data = data

    VAR.CAN_CHANNEL.Send(msg)

    PrintCanMessage("TX", msg)


def CanHandler():
    while 1:
        message = VAR.CAN_CHANNEL.GetReceived()
        if message is None:
            time.sleep(0.001)
            continue

        msgId = CanMessageId.FromInt(message.ID)

        if msgId.moduleType != VAR.DEVICE_TYPE:
            continue

        PrintCanMessage("RX", message)

        if msgId.command == COMMAND.BOOTLOADER_WAIT:
            msgData = []
            msgData += Uint32_to_List(VAR.FIRMWARE_FILE.size)
            msgData += Uint32_to_List(VAR.FIRMWARE_FILE.checksum)

            SendCommand(COMMAND.FIRMWARE_START, msgData)

            print(f"[!]  Размер прошивки: {VAR.FIRMWARE_FILE.size} байт")

            VAR.START_FIRMWARE_TIME = time.time()

        elif msgId.command == COMMAND.FIRMWARE_REQUEST_PACKET:
            packetNumber = List_to_Uint32(message.data)

            VAR.FIRMWARE_PACKET_NUMBER = packetNumber

            if packetNumber == 0 and not VAR.FIRMWARE_PROCESS:
                VAR.FIRMWARE_PROCESS = True
                threading.Thread(target=FirmwareProcess, daemon=True).start()

        elif msgId.command in [COMMAND.FIRMWARE_OK, COMMAND.FIRMWARE_BAD]:
            VAR.FIRMWARE_PROCESS = False

            VAR.END_FIRMWARE_TIME = time.time()

            firmwareTime = VAR.END_FIRMWARE_TIME - VAR.START_FIRMWARE_TIME
            print(f"[!]  Общее время прошивки: {firmwareTime:.3f} сек")
            print()


def FirmwareProcess():
    totalPackets = (VAR.FIRMWARE_FILE.size // FIRMWARE_PACKET_SIZE) + 1

    print(f"[!]  Количество пакетов прошивки: {totalPackets}")

    packetPeriod = 2

    lastSendTime = 0
    while VAR.FIRMWARE_PROCESS:
        if ((time.time() - lastSendTime) * 1000) >= packetPeriod:
            lastSendTime = time.time()

            sendPacketNumber = VAR.FIRMWARE_PACKET_NUMBER
            VAR.FIRMWARE_PACKET_NUMBER = sendPacketNumber + 1

            firmwareData = VAR.FIRMWARE_FILE.getPacketData(FIRMWARE_PACKET_SIZE, sendPacketNumber)

            msgData = []
            msgData += Uint32_to_List(sendPacketNumber)
            msgData += firmwareData

            SendCommand(COMMAND.FIRMWARE_PACKET, msgData)

            if sendPacketNumber > 0 and sendPacketNumber % 100 == 0:
                print(f"[TX] Отправлен пакет под номером: {sendPacketNumber}.\t[{100*sendPacketNumber/totalPackets:.2f}%]")

            if sendPacketNumber >= totalPackets:
                SendCommand(COMMAND.FIRMWARE_FINISH, Uint32_to_List(totalPackets))
                time.sleep(1)   # Не выходим из цикла, вдруг какой пакет не дошёл до получателя и будет запрошен


# Конфигурация прошивальщика

def SelectCan() -> CanChannel:
    ChaiLibPath = FindChaiLib()

    if ChaiLibPath is None:
        raise Exception("Библиотека CHAI (Marathon) не найдена")

    Chai = ChaiLib(ChaiLibPath)
    channels = Chai.findChannels()

    if len(channels) == 0:
        raise Exception("Нет доступных каналов CAN")

    print("Доступные каналы CAN:")
    for n, channel in enumerate(channels):
        print(f"{n + 1}. {channel.getName()}")

    while 1:
        selectedChannelNumber = input(">>> Выберите канал: ")

        if not selectedChannelNumber.isdigit():
            continue

        selectedChannelNumber = int(selectedChannelNumber)

        if selectedChannelNumber > len(channels) or selectedChannelNumber < 1:
            continue

        selectedChannel = channels[selectedChannelNumber-1]

        selectedChannel.setFrameFormat(FrameFormat.CIO_CAN29)
        selectedChannel.setBaudSpeed(CAN_SPEED)
        selectedChannel.used = True

        if not (selectedChannel.open() and selectedChannel.start()):
            raise Exception("Не удалось открыть канал")

        Chai.start()

        return selectedChannel


def SelectFirmwareFile() -> FirmwareFile:
    while 1:
        binPath = input(">>> Путь до прошивки (.bin): ")
        #binPath = r"D:\repos\KRC_APM32f407RGT6\cmake-build-release-bootloader\KRC_APM32f407RGT6.bin"
        #binPath = r"D:\repos\apm32f405_krc_example\cmake-build-debug\apm32f405_krc_example.bin"

        return FirmwareFile(binPath)


def SelectDeviceType() -> int:
    deviceTypes = []

    print("Доступные типы устройства:")
    for n, deviceType in enumerate(DEVICE_TYPES):
        print(f"{n + 1}. {deviceType}")
        deviceTypes.append(deviceType)

    while 1:
        selectedDeviceType = input(">>> Выберите тип устройства: ")

        if not selectedDeviceType.isdigit():
            continue

        selectedDeviceType = int(selectedDeviceType)

        if selectedDeviceType > len(deviceTypes) or selectedDeviceType < 1:
            continue

        return DEVICE_TYPES[deviceTypes[selectedDeviceType - 1]]


if __name__ == "__main__":
    VAR.CAN_CHANNEL = SelectCan()
    VAR.FIRMWARE_FILE = SelectFirmwareFile()
    VAR.DEVICE_TYPE = SelectDeviceType()

    print("[! ] Параметры определены. Ожидание CAN сообщений...")

    CanHandler()
