import enum
import struct
import argparse

import lief

from crc import GetCrc32
from abtci import MODULE_TYPES
from elf import *


GAP_FILL    = 0x00


BTL_CFG_SYMBOL      = "BTL_CFG"
BTL_CHECKSUM_SYMBOL = "BTL_CHECKSUM"

BTL_VERSION_1       = 0x01

BTL_VERSION_STRUCT  = "B"       # uint8_t

BTL_CFG_STRUCT_V1   = "BB"      # uint8_t, uint8_t

BTL_CHECKSUM_STRUCT = "L"       # uint32_t


def auto_int(x):
    return int(x, 0)


def get_btl_version(binary: lief.ELF.Binary) -> int:
    symbol = binary.get_static_symbol(BTL_CFG_SYMBOL)
    if symbol is None:
        raise ValueError(f"Not found symbol \"{BTL_CFG_SYMBOL}\"")

    endian = get_endian_char(binary)
    struct_format = endian + BTL_VERSION_STRUCT
    
    version_bytes = binary.get_content_from_virtual_address(symbol.value, struct.calcsize(struct_format))
    version_bytes = bytes(version_bytes)
    
    return struct.unpack(struct_format, version_bytes)[0]


def set_btl_cfg_v1(binary: lief.ELF.Binary, module_type: int):
    symbol = binary.get_static_symbol(BTL_CFG_SYMBOL)
    if symbol is None:
        raise ValueError(f"Not found symbol \"{BTL_CFG_SYMBOL}\"")

    endian = get_endian_char(binary)
    struct_format = endian + BTL_CFG_STRUCT_V1

    cfg_bytes = struct.pack(struct_format, *(BTL_VERSION_1, module_type))
    cfg_bytes = list(cfg_bytes)

    binary.patch_address(symbol.value, cfg_bytes)


def calc_btl_checksum(binary: lief.ELF.Binary) -> int:
    symbol = binary.get_static_symbol(BTL_CHECKSUM_SYMBOL)
    if symbol is None:
        raise ValueError(f"Not found symbol \"{BTL_CHECKSUM_SYMBOL}\"")

    content_phy_addr_start = FLASH_ADDR
    content_phy_addr_btl_checksum = get_symbol_phy_addr(binary, symbol)

    calc_size = content_phy_addr_btl_checksum - content_phy_addr_start

    content: bytearray = get_flash_content(binary)

    return GetCrc32(content[:calc_size])


def set_btl_checksum(binary: lief.ELF.Binary, checksum: int):
    symbol = binary.get_static_symbol(BTL_CHECKSUM_SYMBOL)
    if symbol is None:
        raise ValueError(f"Not found symbol \"{BTL_CHECKSUM_SYMBOL}\"")
    
    endian = get_endian_char(binary)
    struct_format = endian + BTL_CHECKSUM_STRUCT

    checksum_bytes = struct.pack(struct_format, *(checksum, ))
    checksum_bytes = list(checksum_bytes)

    binary.patch_address(symbol.value, checksum_bytes)


if __name__ == "__main__":
    #global GAP_FILL
    # print("Configure bootloader for STM32F407VGT6")

    parser = argparse.ArgumentParser(description='STM32F407VGT6 bootloader configure util')

    parser.add_argument('btl_fw',
                        type=str,
                        help='Bootlaoder firmware (.elf)')
    
    parser.add_argument('--module-type',
                        type=str,
                        default="ktrc",
                        help='Module type (cu, mpp, gks, ktrc, mec_v2, ... (see \"abtci_protocol.hpp\"))')
    
    parser.add_argument('--gap-fill',
                        type=auto_int,
                        default=0x00)
    
    args = parser.parse_args()

    btl_fw_path = args.btl_fw
    binary: lief.ELF.Binary = lief.parse(btl_fw_path)

    
    GAP_FILL = args.gap_fill

    if args.module_type not in MODULE_TYPES:
        raise ValueError(f"Unknown module type: \"{args.module_type}\"")
    
    module_type_num = MODULE_TYPES.get(args.module_type)
    module_type_num = module_type_num.value


    btl_version = get_btl_version(binary)
    print(f"-- Bootloader version = {btl_version}")

    if btl_version == BTL_VERSION_1:
        print(f"-- Setting module type = {args.module_type} (0x{module_type_num:02x})")
        set_btl_cfg_v1(binary, module_type_num)

    else:
        raise Exception(f"Unsupported bootlaoder version: {btl_version}")


    checksum = calc_btl_checksum(binary)
    set_btl_checksum(binary, checksum)

    print(f"-- Bootloader checksum = 0x{checksum:08x}")

    """
    content: bytearray = get_flash_content(binary)

    print(f"binary size: {len(content)}")

    #with open("bin.out", "wb") as f:
    #    f.write(content)

    with open("hex.out", "w") as f:

        sym_n = 1
        for byte in content:
            f.write(f"{byte:02x} ")

            if (sym_n % 4) == 0:
                f.write("  ")

            if (sym_n % 16) == 0:
                f.write("\n")

            sym_n += 1
    """

    binary.write(btl_fw_path)









