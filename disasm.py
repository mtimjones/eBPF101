from dataclasses import dataclass
import struct
import bpf
from insn import Insn

class EBPFDisassembler:
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

    SIZE_SUFFIX = {bpf.BPF_B: "b", bpf.BPF_H: "h", bpf.BPF_W: "w", bpf.BPF_DW: "dw"}

    def __init__(self):
        pass

    def _reg(self, n: int) -> str:
        if n == 10:
            return "FP"
        else:
            return f"r{n}"

    def disasm(self, insn: Insn) -> str:

        opcode, dst, src, off, imm = insn.opcode, insn.dst, insn.src, insn.off, insn.imm

        cls  = opcode & bpf.BPF_CLASS_MASK
        op   = opcode & bpf.BPF_OP_MASK
        srcK = (opcode & bpf.BPF_SRC_MASK) != 0  # True => use register source

        # ---- ALU / ALU64
        if cls in (bpf.BPF_ALU, bpf.BPF_ALU64):
            width = "64" if cls == bpf.BPF_ALU64 else "32"
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
        if cls in (bpf.BPF_JMP, bpf.BPF_JMP32):
            width = "32" if cls == bpf.BPF_JMP32 else ""
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
        if cls in (bpf.BPF_LDX, bpf.BPF_ST, bpf.BPF_STX, bpf.BPF_LD):
            size = opcode & bpf.BPF_SIZE_MASK
            mode = opcode & bpf.BPF_MODE_MASK
            sz = self.SIZE_SUFFIX.get(size, "?")

            if mode not in (bpf.BPF_MEM, bpf.BPF_XADD):
                return f".byte 0x{opcode:02x}  # unsupported LD/ST mode"

            if cls == bpf.BPF_LDX and mode == bpf.BPF_MEM:
                return f"ldx{sz} {self._reg(dst)}, [{self._reg(src)}{off:+d}]"
            if cls == bpf.BPF_ST and mode == bpf.BPF_MEM:
                return f"st{sz} [{self._reg(dst)}{off:+d}], {imm}"
            if cls == bpf.BPF_STX and mode == bpf.BPF_MEM:
                return f"stx{sz} [{self._reg(dst)}{off:+d}], {self._reg(src)}"
            if cls == bpf.BPF_STX and mode == bpf.BPF_XADD:
                return f"xadd{sz} [{self._reg(dst)}{off:+d}], {self._reg(src)}"

            return f".byte 0x{opcode:02x}  # unknown LD/ST form"

        return f".byte 0x{opcode:02x}  # unknown class"
