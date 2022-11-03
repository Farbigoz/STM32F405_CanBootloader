import enum
import ctypes

"""
    predefined baud rates (recommended by CiA)
    Phillips SJA1000 (16 MHz)
"""
BCI_1M_bt0   = 0x00
BCI_1M_bt1   = 0x14
BCI_800K_bt0 = 0x00
BCI_800K_bt1 = 0x16
BCI_500K_bt0 = 0x00
BCI_500K_bt1 = 0x1c
BCI_250K_bt0 = 0x01
BCI_250K_bt1 = 0x1c
BCI_125K_bt0 = 0x03
BCI_125K_bt1 = 0x1c
BCI_100K_bt0 = 0x04
BCI_100K_bt1 = 0x1c
BCI_50K_bt0  = 0x09
BCI_50K_bt1  = 0x1c
BCI_20K_bt0  = 0x18
BCI_20K_bt1  = 0x1c
BCI_10K_bt0  = 0x31
BCI_10K_bt1  = 0x1c


class BaudSpeed(enum.Enum):
    BCI_1M  = BCI_1M_bt0, BCI_1M_bt1
    BCI_800K = BCI_800K_bt0, BCI_800K_bt1
    BCI_500K = BCI_500K_bt0, BCI_500K_bt1
    BCI_250K = BCI_250K_bt0, BCI_250K_bt1
    BCI_125K = BCI_125K_bt0, BCI_125K_bt1
    BCI_100K = BCI_100K_bt0, BCI_100K_bt1
    BCI_50K  = BCI_50K_bt0, BCI_50K_bt1
    BCI_20K  = BCI_20K_bt0, BCI_20K_bt1
    BCI_10K  = BCI_10K_bt0, BCI_10K_bt1


"""
    Flags for CiWaitEvent
"""
CI_WAIT_RC = 0x1
CI_WAIT_TR = 0x2
CI_WAIT_ER = 0x4


"""
    Frame type
"""
CM_FRAME_RX = 0x1
CM_FRAME_TX = 0x2


class FrameFormatFlag(enum.IntEnum):
    IDENT_SFF = 0x1
    IDENT_EFF = 0x2


class FrameFormat(enum.IntEnum):
    CIO_CAN11 = 0x2
    CIO_CAN29 = 0x4



class canboard_t(ctypes.Structure):
    _fields_ = [
        ("brdnum", ctypes.c_uint8),
        ("hwver", ctypes.c_uint32),
        ("chip", ctypes.c_int16 * 4),
        ("name", ctypes.c_char * 64),
        ("manufact", ctypes.c_char * 64)
    ]

    brdnum: ctypes.c_uint8
    hwver: ctypes.c_uint32
    chip: ctypes.c_uint16 * 4
    name: ctypes.c_char * 64
    manufact: ctypes.c_char * 64


class canwait_t(ctypes.Structure):
    _fields_ = [
        ("chan", ctypes.c_uint8),
        ("wflags", ctypes.c_uint8),
        ("rflags", ctypes.c_uint8)
    ]

    chan: ctypes.c_uint8
    wflags: ctypes.c_uint8
    rflags: ctypes.c_uint8


class canmsg_t(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint32),
        ("data", ctypes.c_uint8 * 8),
        ("len", ctypes.c_uint8),
        ("flags", ctypes.c_uint16),
        ("ts", ctypes.c_uint32)
    ]

    id: ctypes.c_uint32
    data: ctypes.c_uint8 * 8
    len: ctypes.c_uint8
    flags: ctypes.c_uint16
    ts: ctypes.c_uint32


class canerrs_t(ctypes.Structure):
    _fields_ = [
        ("ewl", ctypes.c_uint16),
        ("boff", ctypes.c_uint16),
        ("hwovr", ctypes.c_uint16),
        ("swovr", ctypes.c_uint16),
        ("wtout", ctypes.c_uint16)
    ]

    ewl: ctypes.c_uint16
    boff: ctypes.c_uint16
    hwovr: ctypes.c_uint16
    swovr: ctypes.c_uint16
    wtout: ctypes.c_uint16

