import threading

from typing import List

from .defines import *
from ..message import CanMessage
from ..channel import CanChannel

# Annotations
if False:
    from .chai import ChaiLib


ChaiChannelsUpdateEvent = threading.Event()


class ChaiChannel(CanChannel):
    chaiInstance: "ChaiLib"

    device: str
    channel: int

    used: bool
    state: bool

    frameFormatFlag: FrameFormatFlag    = FrameFormatFlag.IDENT_EFF
    frameFormat: FrameFormat            = FrameFormat.CIO_CAN11 | FrameFormat.CIO_CAN29
    baudSpeed: BaudSpeed                = BaudSpeed.BCI_50K

    def __init__(self, chaiInstance: "ChaiLib", device: str, channel: int):
        CanChannel.__init__(self)

        self.chaiInstance = chaiInstance
        self.device = device
        self.channel = channel

        self.used = False
        self.state = False

    def __repr__(self):
        return f"<ChaiChannel: {self.channel}>"

    def getName(self):
        return f"ChaiChannel: {self.channel}"

    def setFrameFormat(self, frameFormat: FrameFormat):
        self.frameFormat = frameFormat

    def setBaudSpeed(self, baudSpeed: BaudSpeed):
        self.baudSpeed = baudSpeed

    def open(self) -> bool:
        """Open channel and set baud speed

        :return: True - OK, False - Error
        """

        # TODO: Errors
        openResult = ctypes.c_int16(self.chaiInstance.CiOpen(self.channel, self.frameFormat)).value
        if openResult < 0:
            return False

        setBaudResult = ctypes.c_int16(self.chaiInstance.CiSetBaud(self.channel, *self.baudSpeed.value)).value
        if setBaudResult < 0:
            return False

        setFilterResult = ctypes.c_int16(self.chaiInstance.CiSetFilter(self.channel, 0xffff, 0x0)).value
        if setFilterResult < 0:
            return False

        #ChaiChannelsUpdateEvent.set()

        return True

    def start(self) -> bool:
        startResult = ctypes.c_int16(self.chaiInstance.CiStart(self.channel)).value
        if startResult == 0:
            self.state = True
            ChaiChannelsUpdateEvent.set()
            return True

        return False

    def stop(self) -> bool:
        self.state = False
        ChaiChannelsUpdateEvent.set()
        return ctypes.c_int16(self.chaiInstance.CiStop(self.channel)).value == 0

    def close(self) -> bool:
        self.state = False
        #ChaiChannelsUpdateEvent.set()
        return ctypes.c_int16(self.chaiInstance.CiClose(self.channel)).value == 0

    def Send(self, message: CanMessage) -> bool:
        _canmsg_t_array = (canmsg_t * 1)()
        _canmsg_t_array[0].id = message.ID
        _canmsg_t_array[0].len = message.length
        _canmsg_t_array[0].flags = self.frameFormatFlag.value | self.frameFormat
        _canmsg_t_array[0].ts = message.timeStamp
        for n, byte in enumerate(message.data):
            _canmsg_t_array[0].data[n] = byte

        transmitResult = ctypes.c_int16(self.chaiInstance.CiTransmit(self.channel, _canmsg_t_array)).value
        return transmitResult == 0

    def SendMany(self, messages: List[CanMessage]) -> bool:
        count = len(messages)
        _canmsg_t_array = (canmsg_t * count)()
        chaierr = (ctypes.c_int * 1)()

        for i, message in enumerate(messages):
            _canmsg_t_array[i].id = message.ID
            _canmsg_t_array[i].len = message.length
            _canmsg_t_array[i].flags = self.frameFormatFlag.value | self.frameFormat
            _canmsg_t_array[i].ts = message.timeStamp
            for n, byte in enumerate(message.data):
                _canmsg_t_array[i].data[n] = byte

        transmitResult = ctypes.c_int16(
            self.chaiInstance.CiTransmitSeries(self.channel, _canmsg_t_array, ctypes.c_int(count), chaierr)
        ).value

        if chaierr[0] > 0 or transmitResult < count:
            print(chaierr[0], transmitResult, count)
            return False

        return True
