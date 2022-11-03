import time

from typing import List, Union, Optional


def Hex(data: Union[bytes, List[int]], sep=" ") -> str:
    out = ""
    for k in data:
        out += f"{k.to_bytes(1, 'big').hex().upper()}{sep}"
    return out


class CanMessage:
    ID: int
    data: Union[bytes, List[int]]
    timeStamp: int
    length: int

    def __init__(self):
        self.ID = 0
        self.data = [0] * 8
        self.timeStamp = int(time.time() * 1000)
        self.length = 0

    def __repr__(self):
        return f"ID: {self.getHexID()}  |  " \
               f"LEN: {self.length}  |  " \
               f"DATA: {self.getHexData()}" \
            # f"TS: {self.timeStamp}"

    def getHexID(self) -> str:
        return self.ID.to_bytes(4, 'big').hex().upper()

    def getHexData(self) -> str:
        return Hex(self.data[:self.length])

    def getBytes(self) -> bytes:
        return self.ID.to_bytes(4, "little") + \
               bytearray(self.data) + (b"\x00" * (8-len(self.data))) + \
               (self.timeStamp & 0xffff).to_bytes(2, "little") + \
               self.length.to_bytes(1, "little")

    @classmethod
    def fromData(cls, ID: int, data: Union[bytes, List[int]], length: int,
                 timeStamp: Optional[int] = None) -> "CanMessage":
        inst = cls()

        inst.ID = ID
        inst.data = data
        inst.length = length

        if timeStamp is not None:
            inst.timeStamp = timeStamp

        return inst

    @classmethod
    def fromBytes(cls, a_bytes: bytes) -> "CanMessage":
        inst = cls()

        # Ужас
        inst.ID = int.from_bytes(a_bytes[:4], "little")
        inst.data = a_bytes[4:4+8]
        inst.timeStamp = int.from_bytes(a_bytes[4+8:4+8+2], "little")
        inst.length = int.from_bytes(a_bytes[4+8+2:4+8+2+1], "little")

        return inst

    @classmethod
    def bytesSize(cls) -> int:
        # (uint32_t)ID + (uint8_t[8])DATA + (uint16_t)TIMESTAMP + (uint8_t)LENGTH
        return 4 + 8 + 2 + 1
