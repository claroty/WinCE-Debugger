import random
import pefile
from construct import *


def get_rand_guid():
    guid = Sequence(Int32ul, Int16ul, Int16ul, Int16ub, Bytes(6))
    return guid.parse(random.randbytes(0x10))


SANITY_SHELLCODE = b''
SANITY_SHELLCODE += b'\x01\x60\xA0\xE3' # MOV     R6, #0x1
SANITY_SHELLCODE += b'\x01\x60\x86\xE2' # ADD     R6, R6, #1
SANITY_SHELLCODE += b'\x00\x00\x56\xE3' # CMP     R6, #0 
SANITY_SHELLCODE += b'\xFC\xFF\xFF\x1A' # BEQ     #4
SANITY_SHELLCODE += b'\x00\x60\x9F\xE5' # LDR     R6, =0x42424242
SANITY_SHELLCODE += b'\x36\xFF\x2F\xE1' # BLX     R6
SANITY_SHELLCODE += b'\x42\x42\x42\x42' # 0x42424242


def patch_executable(exe, shellcode=SANITY_SHELLCODE, delay=0xfffffff0):
    pe = pefile.PE(exe)
    for section in pe.sections:
        characteristics = section.Characteristics
        if characteristics & 0x20000000:  
            cave_size = section.SizeOfRawData - section.Misc_VirtualSize

            if cave_size >= len(shellcode):
                oep = pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase
                cave_addr = section.VirtualAddress + section.Misc_VirtualSize
                offset = cave_addr - section.VirtualAddress + section.PointerToRawData
                shellcode = shellcode.replace(b'\x41\x41\x41\x41', Int32ul.build(delay))
                shellcode = shellcode.replace(b'\x42\x42\x42\x42', Int32ul.build(oep))
                pe.set_bytes_at_offset(offset, shellcode)                
                
                pe.OPTIONAL_HEADER.AddressOfEntryPoint = cave_addr
                break

    pe.write(exe+'_mod')
    return oep, cave_addr+pe.OPTIONAL_HEADER.ImageBase+len(SANITY_SHELLCODE)


def get_sections_info(exe):
    pe = pefile.PE(exe)
    info = []
    for sec in pe.sections:
        info.append((pe.OPTIONAL_HEADER.ImageBase+sec.VirtualAddress, sec.Misc_VirtualSize, sec.get_data()))
    return info