import enum

import lief


FLASH_ADDR  = 0x08000000
FLASH_SIZE  = 1024*1024


class MemoryType(enum.IntEnum):
    FLASH           = enum.auto()
    RAM             = enum.auto()
    RAM_AT_FLASH    = enum.auto()


def get_endian_char(binary: lief.ELF.Binary) -> str:
    if binary.header.identity_data == lief.ELF.ELF_DATA.LSB:
        return "<"
    else:
        return ">"


def get_memory_type(phy_addr: int, virt_addr: int) -> MemoryType:
    if (virt_addr >= FLASH_ADDR) and (virt_addr < (FLASH_ADDR+FLASH_SIZE)):
        return MemoryType.FLASH
    
    elif (phy_addr >= FLASH_ADDR) and (phy_addr < (FLASH_ADDR+FLASH_SIZE)):
        return MemoryType.RAM_AT_FLASH
    
    else:
        return MemoryType.RAM


def get_phy_addr(seg: lief.ELF.Segment, virt_addr: int) -> int:
    if (virt_addr >= FLASH_ADDR) and (virt_addr < (FLASH_ADDR+FLASH_SIZE)):
        return virt_addr
    
    elif (seg.physical_address >= FLASH_ADDR) and (seg.physical_address < (FLASH_ADDR+FLASH_SIZE)):
        return virt_addr - seg.virtual_address + seg.physical_address
    
    else:
        return virt_addr
    

def get_symbol_phy_addr(binary: lief.ELF.Binary, symbol: lief.ELF.Symbol) -> int:
    return get_phy_addr(binary.segment_from_virtual_address(symbol.value), symbol.value)


def it_flash_content(binary: lief.ELF.Binary, print_=False):
    next_phy_addr: int = FLASH_ADDR

    for segment in binary.segments:
        mem_t: MemoryType = get_memory_type(segment.physical_address, segment.virtual_address)

        if mem_t not in [MemoryType.FLASH, MemoryType.RAM_AT_FLASH]:
            continue

        for section in segment.sections:
            phy_addr = get_phy_addr(segment, section.virtual_address)

            gap_len = phy_addr - next_phy_addr
            if gap_len > 0:
                if print_:
                    print(f"!gap                 size={gap_len:6d}; phy=0x{next_phy_addr:08x}")
                yield bytearray([0]*gap_len)

            next_phy_addr = phy_addr + section.size

            if print_:
                print(f"{section.name:20s} size={section.size:6d}; phy=0x{phy_addr:08x}")
            yield bytearray(binary.get_content_from_virtual_address(section.virtual_address, section.size))

    return None


def get_flash_content(binary: lief.ELF.Binary, print_=False) -> bytearray:
    content: bytearray = bytearray()

    for content_block in it_flash_content(binary, print_=print_):
        content.extend(content_block)

    return content