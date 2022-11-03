import threading

from typing import List, Union

from .message import CanMessage


ChannelsNewMessageEvent = threading.Event()


class CanChannel:
    rxMessageBuffer: List[CanMessage]

    def __init__(self):
        self.rxMessageBuffer = []

    def __repr__(self):
        return f"<BaseCanChannel>"

    def getName(self):
        return f"BaseCanChannel"

    def open(self) -> bool:
        return False

    def start(self) -> bool:
        return False

    def stop(self) -> bool:
        return False

    def close(self) -> bool:
        return False

    def _receivedNewMessage(self, message: CanMessage):
        ChannelsNewMessageEvent.set()
        self.rxMessageBuffer.append(message)

    def GetReceived(self) -> Union[CanMessage, None]:
        if len(self.rxMessageBuffer) > 0:
            return self.rxMessageBuffer.pop(0)

        return None

    def Send(self, message: CanMessage) -> bool:
        return False

    def txMessages(self, message: List[CanMessage]) -> bool:
        return False

