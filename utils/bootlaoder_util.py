import os
import io
import sys
import enum
import socket

import lief

from typing import List, Union
from PySide2.QtWidgets import QMainWindow, QApplication, QWidget, QFileDialog
from PySide2.QtCore import QTimer, Slot, Signal
from PySide2.QtGui import QTextCursor

from ui_main_window import Ui_MainWindow
from ui_cpu_widget_2 import Ui_cpu_2

from abtci import *
from crc import GetCrc32, GetCrc16
from elf import get_flash_content
from can import can_channel, can_socket, can_msg


FLASH_OFFSET = 0x8000


# /mnt/d/repos/GKS_KTRC/cmake-build-release-ktrc-btl-gks/KTRC_GKS_normal.elf
# socket.if_nameindex()


class BootloaderVersion(enum.IntEnum):
    V_1 = 0x01


class CpuType(enum.IntEnum):
    CPU_A = 0x00
    CPU_B = 0x01


class CpuUi(QWidget):
    cpu_type: CpuType
    module_type: abtci_type
    version: BootloaderVersion
    fw_path: str
    fw_stream: Union[io.BytesIO, None]
    interfaces: List[str]
    interface: Union[can_channel, None]
    process_flag: bool

    block_number: int
    total_blocks: int

    log_message = Signal(CpuType, str)
    fw_path_change = Signal(str)

    def __init__(self, cpu_type: CpuType):
        super().__init__()

        self.ui = Ui_cpu_2()
        self.ui.setupUi(self)

        self.process_timer = QTimer()

        self.cpu_type = cpu_type
        self.version = BootloaderVersion.V_1
        self.fw_path = ""
        self.fw_stream = None
        self.interfaces = []
        self.interface = None
        self.byte_buff = None

        self.block_number = -1
        self.total_blocks = 0

        if self.cpu_type == CpuType.CPU_A:
            self.ui.root_box.setTitle("Процессор А")
        elif self.cpu_type == CpuType.CPU_B:
            self.ui.root_box.setTitle("Процессор Б")

        self.ui.fw_file_path.textChanged.connect(self.on_fw_path_changed)
        self.ui.select_fw_file.clicked.connect(self.on_select_fw_file)
        self.ui.reload_fw_file.clicked.connect(self.on_reload_fw_file)

        self.ui.update_interfaces.clicked.connect(self.on_update_interfaces)
        self.ui.interfaces.currentIndexChanged.connect(self.on_interface_changed)

        self.process_timer.timeout.connect(self.on_process)

        self.on_update_interfaces()

        self.process_timer.setInterval(4)
        self.process_timer.start()

    def on_bootloader_ver_changed(self, version: BootloaderVersion):
        self.version = version
        self.update_fw()

    def on_module_type_changed(self, module_type: abtci_type):
        self.module_type = module_type

    def on_select_fw_file(self):
        fw_path, filter = QFileDialog.getOpenFileName(self, 'Open file', None, "Firmware (*.elf *.bin *hex)")
        if fw_path:
            self.set_fw_path(fw_path)

    def on_fw_path_changed(self, fw_path: str):
        # print(fw_path)
        self.fw_path = fw_path
        self.update_fw()
        self.fw_path_change.emit(self.fw_path)

    def on_reload_fw_file(self):
        self.update_fw()
        self.fw_path_change.emit(self.fw_path)

    def on_update_interfaces(self):
        self.ui.interfaces.clear()
        self.interfaces.clear()

        for (idx, name) in socket.if_nameindex():
            if "can" in name:
                self.interfaces.append(name)
                self.ui.interfaces.addItem(name)

    def on_interface_changed(self, idx: int):
        interface_name = self.interfaces[idx]

        if self.interface is not None:
            self.interface.stop()

        self.interface = can_socket(interface_name)
        self.interface.start()

    def on_process(self):
        if self.interface is None:
            return

        while self.interface.recv_available():
            msg = self.interface.recv_msg()
            msg_id = abtci_can_id.from_id(msg.id)

            if msg_id.type != self.module_type:
                continue

            if (self.cpu_type == CpuType.CPU_A) and (msg_id.interface != abtci_interface.sys_a):
                continue

            if (self.cpu_type == CpuType.CPU_B) and (msg_id.interface != abtci_interface.sys_b):
                continue

            if msg_id.command == abtci_btl_cmd.btl_inf:
                inf = abtci_btl_cmd_inf.from_data(msg.data)

                message = (f"Инфо: "
                           f"Версия бутлоадера \"{inf.version}\", "
                           f"размер программы: \"{inf.size}\", "
                           f"контрольная сумма программы: 0x{inf.checksum:08x}.")
                self.log_message.emit(self.cpu_type, message)

                if inf.version != self.version.value:
                    continue

                # todo: halt

                self.ui.btl_version.setValue(inf.version)
                self.ui.btl_fw_size.setValue(inf.size)
                self.ui.btl_fw_checksum.setText(f"0x{inf.checksum:08x}")

                # Остановка
                self.on_halt()

            elif msg_id.command == abtci_btl_cmd.btl_damaged:
                message = f"Бутлоадер повреждён."
                self.log_message.emit(self.cpu_type, message)

            elif msg_id.command == abtci_btl_cmd.btl_wrong_msg:
                message = f"Неизвестное сообщение."
                self.log_message.emit(self.cpu_type, message)

            elif msg_id.command == abtci_btl_cmd.btl_no_space_available:
                message = f"Нет свободного пространства."
                self.log_message.emit(self.cpu_type, message)

            elif msg_id.command == abtci_btl_cmd.btl_fw_damaged:
                message = f"Прошивка повреждена."
                self.log_message.emit(self.cpu_type, message)

            elif msg_id.command == abtci_btl_cmd.blt_fw_run:
                message = f"Запуск прошивки."
                self.log_message.emit(self.cpu_type, message)

            elif msg_id.command == abtci_btl_cmd.btl_safe_cell_fault:
                message = f"Повреждение ячейки безопасности (Отсутствуют прерывания)."
                self.log_message.emit(self.cpu_type, message)

            elif msg_id.command == abtci_btl_cmd.btl_request:
                request = abtci_btl_cmd_request.from_data(msg.data)

                message = f"Запрос пакета \"{request.number}\""
                self.log_message.emit(self.cpu_type, message)

                self.fw_stream.seek(request.number * 4, os.SEEK_SET)
                self.block_number = request.number

        if (self.block_number >= 0) and (self.block_number <= self.total_blocks):

            out_msg_id = abtci_can_id(abtci_interface.sys_a.value if self.cpu_type == CpuType.CPU_A else abtci_interface.sys_b.value,
                                      0,
                                      abtci_btl_cmd.btl_flash.value,
                                      self.module_type.value)
            out_data = abtci_btl_cmd_flash()

            fw_block = self.fw_stream.read(4)
            out_msg = can_msg(out_msg_id.to_id(), out_data.to_data(self.block_number, fw_block))
            self.interface.send_msg(out_msg)

            self.ui.progress.setValue(int(100*self.block_number/self.total_blocks))

            #print(f"[{INTERFACE_NAME.get(self.interface):5s}]: "
            #      f"{self.block_number*4:>7d} / {self.total_blocks*4:<7d} "
            #      f"({round(100*self.block_number/self.total_blocks, 1)}%)")

            self.block_number += 1

    def on_run_fw(self):
        out_msg_id = abtci_can_id(abtci_interface.sys_a.value if self.cpu_type == CpuType.CPU_A else abtci_interface.sys_b.value,
                                  0,
                                  abtci_btl_cmd.btl_force_run.value,
                                  self.module_type.value)

        out_data = abtci_btl_cmd_ctrl_data()
        out_msg = can_msg(out_msg_id.to_id(), out_data.to_data(self.version.value))
        self.interface.send_msg(out_msg)

    def on_halt(self):
        out_msg_id = abtci_can_id(abtci_interface.sys_a.value if self.cpu_type == CpuType.CPU_A else abtci_interface.sys_b.value,
                                  0,
                                  abtci_btl_cmd.btl_halt.value,
                                  self.module_type.value)

        out_data = abtci_btl_cmd_ctrl_data()
        out_msg = can_msg(out_msg_id.to_id(), out_data.to_data(self.version.value))
        self.interface.send_msg(out_msg)

    def on_upload_fw(self):
        if self.fw_stream is None:
            return

        out_msg_id = abtci_can_id(abtci_interface.sys_a.value if self.cpu_type == CpuType.CPU_A else abtci_interface.sys_b.value,
                                  0,
                                  abtci_btl_cmd.btl_erase.value,
                                  self.module_type.value)

        out_data = abtci_btl_cmd_ctrl_data()
        out_msg = can_msg(out_msg_id.to_id(), out_data.to_data(self.version.value))
        self.interface.send_msg(out_msg)

    def set_disabled_file(self, dis: bool):
        self.ui.file_box.setDisabled(dis)

    def set_fw_path(self, fw_path: str):
        self.ui.fw_file_path.setText(fw_path)

    def get_fw_path(self) -> str:
        return self.fw_path

    def update_fw(self):
        def reset_fw_file():
            self.ui.fw_file_size.setValue(0)
            self.ui.fw_file_checksum.setText(f"0x{0:08x}")
            self.fw_stream = None

        if not os.path.exists(self.fw_path) and not os.path.isfile(self.fw_path):
            reset_fw_file()
            return

        if self.fw_path.endswith(".elf"):
            binary: lief.ELF.Binary = lief.parse(self.fw_path)
            fw_raw = get_flash_content(binary)
            fw_raw = fw_raw[FLASH_OFFSET:]
        elif self.fw_path.endswith(".bin"):
            with open(self.fw_path, "rb") as f:
                fw_raw = f.read()
        else:
            reset_fw_file()
            return

        if self.version in [BootloaderVersion.V_1]:
            fw_checksum = GetCrc32(fw_raw)
            self.fw_stream = io.BytesIO(fw_raw)
            self.block_number = -1
            self.total_blocks = (len(fw_raw) + 3) // 4

            self.ui.fw_file_size.setValue(len(fw_raw))
            self.ui.fw_file_checksum.setText(f"0x{fw_checksum:08x}")

        else:
            reset_fw_file()
            return


class BootloaderUtilUi(QMainWindow):
    module_type_ids: List[abtci_type]
    btl_versions: list

    cpu_b_fw_path: str

    def __init__(self):
        super().__init__()

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        self.cpu_a = CpuUi(CpuType.CPU_A)
        self.cpu_b = CpuUi(CpuType.CPU_B)

        self.module_type_ids = []
        self.btl_versions = []

        self.cpu_b_fw_path = ""

        self.ui.module_type.clear()
        for key, id in MODULE_TYPES.items():
            self.module_type_ids.append(id)
            self.ui.module_type.addItem(MODULE_NAME.get(id))

        self.ui.bootloader_version.clear()
        for ver in BootloaderVersion:
            self.btl_versions.append(ver)
            self.ui.bootloader_version.addItem(f"{ver.value}")

        self.ui.cpu_frame.layout().addWidget(self.cpu_a)
        self.ui.cpu_frame.layout().addWidget(self.cpu_b)

        self.ui.module_type.currentIndexChanged.connect(self.on_module_type_changed)
        self.ui.bootloader_version.currentIndexChanged.connect(self.on_bootloader_ver_changed)
        self.ui.same_firmware.clicked.connect(self.on_same_firmware_state_changed)
        self.ui.upload_fw.clicked.connect(self.on_upload_fw)
        self.ui.force_run_fw.clicked.connect(self.on_run_fw)
        self.ui.clear.clicked.connect(self.on_clear)

        self.cpu_a.fw_path_change.connect(self.on_fw_path_change)

        self.cpu_a.log_message.connect(self.on_log_message)
        self.cpu_b.log_message.connect(self.on_log_message)

        self.on_module_type_changed(0)
        self.on_bootloader_ver_changed(0)

    def on_same_firmware_state_changed(self, state: bool):
        if state:
            self.cpu_b_fw_path = self.cpu_b.get_fw_path()
            self.cpu_b.set_fw_path(self.cpu_a.get_fw_path())
        else:
            self.cpu_b.set_fw_path(self.cpu_b_fw_path)

        self.cpu_b.set_disabled_file(state)

    def on_fw_path_change(self, fw_path):
        if self.ui.same_firmware.isChecked():
            self.cpu_b.set_fw_path("")
            self.cpu_b.set_fw_path(fw_path)

    def on_module_type_changed(self, idx: int):
        self.cpu_a.on_module_type_changed(self.module_type_ids[idx])
        self.cpu_b.on_module_type_changed(self.module_type_ids[idx])

    def on_bootloader_ver_changed(self, idx: int):
        self.cpu_a.on_bootloader_ver_changed(self.btl_versions[idx])
        self.cpu_b.on_bootloader_ver_changed(self.btl_versions[idx])

    def on_upload_fw(self):
        self.cpu_a.on_upload_fw()
        self.cpu_b.on_upload_fw()

    def on_run_fw(self):
        self.cpu_a.on_run_fw()
        self.cpu_b.on_run_fw()

    def on_clear(self):
        self.ui.log.clear()

    def on_log_message(self, cpu_type: CpuType, message: str):
        if not message.endswith("\n"):
            message = message + "\n"

        if cpu_type == CpuType.CPU_A:
            message = "[ПРОЦ-А]: " + message
        elif cpu_type == CpuType.CPU_B:
            message = "[ПРОЦ-Б]: " + message

        print(message, end="")

        prev_cursor = self.ui.log.textCursor()
        self.ui.log.moveCursor(QTextCursor.End)
        self.ui.log.insertPlainText(message)
        self.ui.log.setTextCursor(prev_cursor)


if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = BootloaderUtilUi()
    window.show()

    sys.exit(app.exec_())
