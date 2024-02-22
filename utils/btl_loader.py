import os
import io
import sys
import time
import argparse
import threading

from typing import Union, List

from crc import GetCrc32
from can import can_msg, can_channel, can_socket
from elf import get_flash_content
from abtci import *

import lief

if sys.platform.startswith("win"):
    import candle_driver



# Отступ от начала флеш памяти, где расположен бутлодер
FLASH_OFFSET = 0x8000


CAN_SPEED = 50000


def print_can_msg(msg_id: abtci_can_id, data: bytes):
    if msg_id.interface not in INTERFACE_NAME:
        return

    if msg_id.type not in MODULE_NAME:
        return

    if msg_id.command not in COMMAND_DESCR:
        return

    interface_name = INTERFACE_NAME.get(msg_id.interface)
    module_name = MODULE_NAME.get(msg_id.type)
    cmd_descr = COMMAND_DESCR.get(msg_id.command)

    if msg_id.command == abtci_btl_cmd.btl_inf:
        inf = abtci_btl_cmd_inf.from_data(data)
        cmd_descr += f". Версия бутлодера: {inf.version}; размер прошивки: {inf.size}; КС прошивки: 0x{inf.checksum:08x}"

    elif msg_id.command == abtci_btl_cmd.btl_request:
        request = abtci_btl_cmd_request.from_data(data)
        cmd_descr += f". Номер блока: {request.number}"

    print(f"[{interface_name:5s}] <{module_name:5s}> - {cmd_descr}")


class btl_loader:
    def __init__(self, fw_raw: bytes, module_type: abtci_type, can: can_channel, force: bool):
        self.can = can

        self.module_type = module_type

        self.force = force

        self.fw_checksum = GetCrc32(fw_raw)
        self.fw_stream = io.BytesIO(fw_raw)

        self.block_number = -1
        self.total_blocks = (len(fw_raw) + 3) // 4

        self.interface = None
        self.flasher_run = False

        self.receiver_thread = threading.Thread(target=self._receiver, daemon=True)
        self.flasher_thread = threading.Thread(target=self._flasher, daemon=True)

        self.flash_lock = threading.Lock()

    def start(self):
        self.can.start()
        self.receiver_thread.start()

    def join(self):
        self.receiver_thread.join()

    def _start_flash(self):
        out_msg_id = abtci_can_id(self.interface.value,
                                  0,
                                  abtci_btl_cmd.btl_erase.value,
                                  self.module_type.value)
        out_data = abtci_btl_cmd_erase()
        out_msg = can_msg(out_msg_id.to_id(), out_data.to_data())
        self.can.send_msg(out_msg)

        if not self.flasher_run:
            self.flasher_run = True
            self.flasher_thread.start()

    def _receiver(self):
        print("Ожидание информационного сообщения от бутлодера...")

        while 1:
            msg = self.can.recv_msg()
            while msg is not None:
                msg_id = abtci_can_id.from_id(msg.id)

                if msg_id.type == self.module_type:
                    if self.interface is None:
                        self.interface = abtci_interface(msg_id.interface)

                    print_can_msg(msg_id, msg.data)

                    if msg_id.command == abtci_btl_cmd.btl_fw_damaged:
                        print(f"[{INTERFACE_NAME.get(self.interface):5s}]: "
                              "Прошивка повреждена."
                              "Запуск процесса перепрошивки...")

                        self._start_flash()

                    elif msg_id.command == abtci_btl_cmd.btl_inf:
                        inf = abtci_btl_cmd_inf.from_data(msg.data)

                        if inf.checksum != self.fw_checksum:
                            print(f"[{INTERFACE_NAME.get(self.interface):5s}]: "
                                  "Контрольная сумма прошивок не совпадает. "
                                  "Запуск процесса перепрошивки...")

                            self._start_flash()

                        elif (inf.checksum == self.fw_checksum) and (not self.flasher_run) and (self.force):
                            print(f"[{INTERFACE_NAME.get(self.interface):5s}]: "
                                  "Контрольная сумма прошивок совпадает. "
                                  "Принудительный запуск процесса перепрошивки...")

                            self._start_flash()

                        elif (inf.checksum == self.fw_checksum) and (not self.flasher_run):
                            print(f"[{INTERFACE_NAME.get(self.interface):5s}]: "
                                  "Контрольная сумма прошивок совпадает.")

                            #out_msg_id = abtci_can_id(self.interface.value,
                            #                          0,
                            #                          abtci_btl_cmd.btl_force_run.value,
                            #                          self.module_type.value)
                            #out_msg = can_msg(out_msg_id.to_id(), b'')
                            #self.can.send_msg(out_msg)

                        elif (inf.checksum == self.fw_checksum) and (self.flasher_run):
                            print(f"[{INTERFACE_NAME.get(self.interface):5s}]: "
                                  "Контрольная сумма прошивок совпадает. "
                                  "Требуется перезагрузка модуля/модулей.")

                    elif msg_id.command == abtci_btl_cmd.btl_request:
                        with self.flash_lock:
                            request = abtci_btl_cmd_request.from_data(msg.data)

                            self.fw_stream.seek(request.number * 4, os.SEEK_SET)
                            self.block_number = request.number

                msg = self.can.recv_msg()

            time.sleep(0.001)

    def _flasher(self):
        prev_block_number = self.block_number
        while 1:
            #input("...\n")

            while (self.block_number < 0) or (self.block_number > self.total_blocks):
                pass

            if prev_block_number >= self.block_number:
                time.sleep(0.1)

            with self.flash_lock:
                out_msg_id = abtci_can_id(self.interface.value,
                                          0,
                                          abtci_btl_cmd.btl_flash.value,
                                          self.module_type.value)
                out_data = abtci_btl_cmd_flash()

                fw_block = self.fw_stream.read(4)
                out_msg = can_msg(out_msg_id.to_id(), out_data.to_data(self.block_number, fw_block))
                self.can.send_msg(out_msg)

                print(f"[{INTERFACE_NAME.get(self.interface):5s}]: "
                      f"{self.block_number*4:>7d} / {self.total_blocks*4:<7d} "
                      f"({round(100*self.block_number/self.total_blocks, 1)}%)")

                prev_block_number = self.block_number
                self.block_number += 1

                #if len(fw_block) < 4:
                #    while self.block_number >= self.total_blocks:
                #        pass
                #    #break

            time.sleep(0.004)
            #time.sleep(0.01)

def auto_int(x):
    return int(x, 0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='KTRC/MEC platform bootloader flasher util.')

    parser.add_argument('fw',
                        type=str,
                        help='Firmware (.elf)')
    
    #parser.add_argument('--flash-addr',
    #                    type=auto_int,
    #                    default=0x08000000,
    #                    help="Firmware physycal address.")
    #
    #parser.add_argument('--flash-size',
    #                    type=auto_int,
    #                    default=0x100000,
    #                    help="Available physycal space.")
    
    #parser.add_argument('--flash-offset',
    #                    type=auto_int,
    #                    default=0x8000)

    parser.add_argument('--can-a',
                        type=str,
                        default=None,
                        help="CAN interface name for SYS A abtci interface")
    
    parser.add_argument('--can-b',
                        type=str,
                        default=None,
                        help="CAN interface name for SYS B abtci interface")
    
    parser.add_argument('--module-type',
                        type=str,
                        default="ktrc",
                        help='Module type (cu, mpp, gks, ktrc, mec_v2, ... (see \"abtci_protocol.hpp\"))')
    
    parser.add_argument('--gap-fill',
                        type=auto_int,
                        default=0x00)

    parser.add_argument('--force',
                        action='store_true',
                        help="Force flash")
    
    args = parser.parse_args()

    if args.module_type not in MODULE_TYPES:
        raise ValueError(f"Unknown module type: \"{args.module_type}\"")

    module_type = MODULE_TYPES.get(args.module_type)

    binary: lief.ELF.Binary = lief.parse(args.fw)
    fw_raw: bytes = get_flash_content(binary)
    fw_raw = fw_raw[FLASH_OFFSET:]

    fw_raw = fw_raw

    checksum = GetCrc32(fw_raw)

    print(f"Размер прошивки: {len(fw_raw)}")
    print(f"Контрольная сумма прошивки: 0x{checksum:08x}")

    #fw_stream = io.BytesIO(fw_raw)

    loaders = []

    for can in [args.can_a, args.can_b]:
        if can is None:
            continue

        loader = btl_loader(fw_raw, module_type, can_socket(can), args.force)
        loaders.append(loader)

    for loader in loaders:
        loader.start()

    for loader in loaders:
        loader.join()



