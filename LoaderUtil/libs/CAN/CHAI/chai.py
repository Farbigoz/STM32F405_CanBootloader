import time
import threading

from typing import List, Dict

from .defines import *
from .channel import ChaiChannel

from ..message import CanMessage


BUFFER_SIZE = 64


class ChaiLib:
    channelsMap: Dict[int, ChaiChannel] = {}

    started = False

    closedEvent = threading.Event()

    errors = canerrs_t()

    def __init__(self, chaiLibPath: str):
        self.chaiLib = ctypes.WinDLL(chaiLibPath)
        self.CiInit()

    def __getattr__(self, item):
        return self.chaiLib[item]

    def findChannels(self) -> List[ChaiChannel]:
        # ChannelNum: DeviceName
        channels: Dict[int, str] = {}

        # Поиск каналов
        for i in range(8):
            binfo = canboard_t()
            binfo.brdnum = i
            result = ctypes.c_int16(self.CiBoardInfo(ctypes.byref(binfo))).value

            if result >= 0:
                for chip in binfo.chip:
                    if chip >= 0:
                        channels[chip] = binfo.name.decode("UTF-8")

        # Если каналы ещё не добавлены, добавляем
        for channel in (set(channels) - set(self.channelsMap)):
            self.channelsMap[channel] = ChaiChannel(self, channels[channel], channel)

        return list(self.channelsMap.values())

    def start(self) -> bool:
        if self.started:
            return False

        self.started = True
        threading.Thread(target=self.reader, daemon=True).start()

    def close(self):
        self.started = False
        
        for chan in self.channelsMap.values():
            chan.stop()
            chan.close()

        self.channelsMap.clear()

    def reader(self):
        self.closedEvent.clear()

        while self.started:
            channels = [channelInstance.channel for channelInstance in self.channelsMap.values()
                        if channelInstance.used]

            # Если ни один канал не запущен ждём и пропускаем цикл
            if not channels:
                time.sleep(1)
                continue

            cw = (canwait_t * len(channels))()
            for n, channel in enumerate(channels):
                cw[n].chan = channel
                cw[n].wflags = CI_WAIT_RC | CI_WAIT_ER

            ret = ctypes.c_int16(self.CiWaitEvent(cw, len(cw), 200))
            if ret.value > 0:
                for i in range(len(cw)):
                    if cw[i].rflags & CI_WAIT_RC:
                        rxMessages = (canmsg_t * BUFFER_SIZE)()
                        readResult = ctypes.c_int16(self.CiRead(cw[i].chan, rxMessages, BUFFER_SIZE))
                        if readResult.value > 0:
                            for rxMessage in rxMessages:
                                rxMessage: canmsg_t
                                if rxMessage.flags == 0:
                                    continue

                                channelInstance = self.channelsMap.get(int(cw[i].chan))
                                if channelInstance is not None:
                                    channelInstance._receivedNewMessage(
                                        CanMessage.fromData(
                                            ID=rxMessage.id,
                                            data=[byte for byte in rxMessage.data],
                                            length=rxMessage.len,
                                            timeStamp=rxMessage.ts
                                        )
                                    )
                        else:
                            print("ОШИБКА ЧТЕНИЯ:", readResult)

                    elif cw[i].rflags & CI_WAIT_ER:
                        errs = (canerrs_t * 1)()
                        if ctypes.c_int16(self.CiErrsGetClear(cw[i].chan, errs)).value >= 0:
                            self.errors.ewl = errs[0].ewl
                            self.errors.boff = errs[0].boff
                            self.errors.hwovr = errs[0].hwovr
                            self.errors.swovr = errs[0].swovr
                            self.errors.wtout = errs[0].wtout

                            print(f"Ошибки ввода-вывода. "
                                  f"EWL: {errs[0].ewl} "
                                  f"BOFF: {errs[0].boff} "
                                  f"HOVR: {errs[0].hwovr} "
                                  f"SOVR: {errs[0].swovr} "
                                  f"WTOUT: {errs[0].wtout}")
                        else:
                            print("Ошибка чтения ошибок")

            elif ret.value < 0:
                # error
                print("CHAI ERROR:", ret.value)
                pass
            else:
                # timeout
                pass

        self.closedEvent.set()

        print("CHAI THREAD STOP")

        #if threading._main_thread._is_stopped:
        #    self.exit()

