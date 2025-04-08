import binascii
from capstone import *


def disasm_arm_code(code, addr):
    cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    disasm = cs.disasm(code, addr)
    return [(insn.address, f'{binascii.hexlify(insn.bytes).decode()} {insn.mnemonic} {insn.op_str}') for insn in disasm]

