import socket
import struct
import threading

from typing import Union, List


class can_msg:
    def __init__(self, id: int, data: bytes):
        self.id = id
        self.data = data

    def text(self) -> str:
        data = " ".join(list(map(lambda x: f"{x:02x}", self.data))) + " "*23
        return f"{self.id:08x} [{len(self.data)}] {data:23}"

    def __repr__(self) -> str:
        return self.text()
    


class can_channel:
    def start(self):
        pass

    def stop(self):
        pass

    def state(self) -> bool:
        return False

    def recv_available(self) -> bool:
        pass

    def send_msg(self, msg: can_msg):
        pass

    def recv_msg(self) -> Union[None, can_msg]:
        return None
    

class can_socket(can_channel):
    can_frame_fmt = "=IB3x8s"

    def __init__(self, interface: str):
        self._run = False

        self.interface = interface
        self.socket: socket.socket = None
        self.tx_messages: List[can_msg] = []
        self.rx_messages: List[can_msg] = []

    def _build_can_frame(self, can_id, data):
        can_dlc = len(data)
        data = data.ljust(8, b'\x00')
        return struct.pack(self.can_frame_fmt, can_id, can_dlc, data)

    def _dissect_can_frame(self, frame):
        can_id, can_dlc, data = struct.unpack(self.can_frame_fmt, frame)
        return (can_id, can_dlc, data[:can_dlc])
    
    def state(self) -> bool:
        return self._run
    
    def start(self):
        if self._run:
            return

        self._run = True

        self.socket = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        self.socket.bind((self.interface,))

        threading.Thread(target=self._receiver, args=(self.socket,)).start()
        #threading.Thread(target=self._sender, args=(s,))

    def stop(self):
        if not self._run:
            return

        if self.socket is None:
            return

        self.socket.close()

    def _receiver(self, s: socket.socket):
        while self.state() and not threading._main_thread._is_stopped:
            if not self._run:
                break

            try:
                cf, addr = s.recvfrom(16)
            except OSError:
                self._run = False
                break

            can_id, can_dlc, data = self._dissect_can_frame(cf)
            self.rx_messages.append(can_msg(can_id & 0x1FFFFFFF, data))

    def recv_available(self) -> bool:
        return len(self.rx_messages) != 0

    def send_msg(self, msg: can_msg):
        try:
            self.socket.send(self._build_can_frame(msg.id | 0x80000000, msg.data))
        except OSError:
            pass

    def recv_msg(self) -> Union[None, can_msg]:
        if len(self.rx_messages) == 0:
            return None

        return self.rx_messages.pop(0)
