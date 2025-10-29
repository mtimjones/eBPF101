from dataclasses import dataclass
import struct
from insn import Insn

class EBPFDisassembler:
    # constants
    BPF_CLASS_MASK = 0x07
    BPF_SIZE_MASK  = 0x18
    BPF_MODE_MASK  = 0xE0
    BPF_SRC_MASK   = 0x08
    BPF_OP_MASK    = 0xF0

    BPF_LD    = 0x00
    BPF_LDX   = 0x01
    BPF_ST    = 0x02
    BPF_STX   = 0x03
    BPF_ALU   = 0x04
    BPF_JMP   = 0x05
    BPF_JMP32 = 0x06
    BPF_ALU64 = 0x07

    BPF_W  = 0x00
    BPF_H  = 0x08
    BPF_B  = 0x10
    BPF_DW = 0x18

    BPF_IMM  = 0x00
    BPF_ABS  = 0x20
    BPF_IND  = 0x40
    BPF_MEM  = 0x60
    BPF_XADD = 0xC0

    ALU_OPS = {
        0x00: "add", 0x10: "sub", 0x20: "mul", 0x30: "div",
        0x40: "or",  0x50: "and", 0x60: "lsh", 0x70: "rsh",
        0x80: "neg", 0x90: "mod", 0xA0: "xor", 0xB0: "mov",
        0xC0: "arsh",0xD0: "end"
    }

    JMP_OPS = {
        0x00: "ja",   0x10: "jeq",  0x20: "jgt",  0x30: "jge",
        0x40: "jset", 0x50: "jne",  0x60: "jsgt", 0x70: "jsge",
        0x80: "call", 0x90: "exit", 0xA0: "jlt",  0xB0: "jle",
        0xC0: "jslt", 0xD0: "jsle"
    }

    SIZE_SUFFIX = {BPF_B: "b", BPF_H: "h", BPF_W: "w", BPF_DW: "dw"}

    def __init__(self):
        pass

    def _reg(self, n: int) -> str:
        if n == 10:
            return "FP"
        else:
            return f"r{n}"

    def disasm(self, insn: Insn) -> str:

        opcode, dst, src, off, imm = insn.opcode, insn.dst, insn.src, insn.off, insn.imm

        cls  = opcode & self.BPF_CLASS_MASK
        op   = opcode & self.BPF_OP_MASK
        srcK = (opcode & self.BPF_SRC_MASK) != 0  # True => use register source

        # ---- ALU / ALU64
        if cls in (self.BPF_ALU, self.BPF_ALU64):
            width = "64" if cls == self.BPF_ALU64 else "32"
            mnem = self.ALU_OPS.get(op)
            if not mnem:
                return f".byte 0x{opcode:02x}  # unknown ALU op"

            if mnem == "neg":
                return f"neg{width} {self._reg(dst)}"
            if mnem == "end":
                endian = "be" if srcK else "le"
                return f"end{width} {self._reg(dst)}, {endian}{imm}"
            if mnem == "mov":
                rhs = self._reg(src) if srcK else f"{imm}"
                return f"mov{width} {self._reg(dst)}, {rhs}"
            rhs = self._reg(src) if srcK else f"{imm}"
            return f"{mnem}{width} {self._reg(dst)}, {rhs}"

        # ---- JMP / JMP32
        if cls in (self.BPF_JMP, self.BPF_JMP32):
            width = "32" if cls == self.BPF_JMP32 else ""
            mnem = self.JMP_OPS.get(op)
            if not mnem:
                return f".byte 0x{opcode:02x}  # unknown JMP op"

            if mnem == "exit":
                return "exit"
            if mnem == "call":
                return f"call {self._reg(src)}" if srcK else f"call {imm}"
            if mnem == "ja":
                return f"ja {off:+d}"
            rhs = self._reg(src) if srcK else f"{imm}"
            suf = "32" if width == "32" else ""
            return f"{mnem}{suf} {self._reg(dst)}, {rhs}, {off:+d}"

        # ---- LD/LDX/ST/STX
        if cls in (self.BPF_LDX, self.BPF_ST, self.BPF_STX, self.BPF_LD):
            size = opcode & self.BPF_SIZE_MASK
            mode = opcode & self.BPF_MODE_MASK
            sz = self.SIZE_SUFFIX.get(size, "?")

            if mode not in (self.BPF_MEM, self.BPF_XADD):
                return f".byte 0x{opcode:02x}  # unsupported LD/ST mode"

            if cls == self.BPF_LDX and mode == self.BPF_MEM:
                return f"ldx{sz} {self._reg(dst)}, [{self._reg(src)}{off:+d}]"
            if cls == self.BPF_ST and mode == self.BPF_MEM:
                return f"st{sz} [{self._reg(dst)}{off:+d}], {imm}"
            if cls == self.BPF_STX and mode == self.BPF_MEM:
                return f"stx{sz} [{self._reg(dst)}{off:+d}], {self._reg(src)}"
            if cls == self.BPF_STX and mode == self.BPF_XADD:
                return f"xadd{sz} [{self._reg(dst)}{off:+d}], {self._reg(src)}"

            return f".byte 0x{opcode:02x}  # unknown LD/ST form"

        return f".byte 0x{opcode:02x}  # unknown class"
