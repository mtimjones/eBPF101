from dataclasses import dataclass
import struct

# ---------------------------------------------------------
# eBPF decoding utilities
# ---------------------------------------------------------
@dataclass
class Insn:
    opcode: int
    dst: int
    src: int
    off: int
    imm: int

    @classmethod
    def from_bytes(cls, b: bytes) -> "Insn":
        if len(b) != 8:
            raise ValueError("eBPF instruction must be 8 bytes")
        opcode = b[0]
        regs = b[1]
        dst = regs & 0x0F
        src = (regs >> 4) & 0x0F
        off = struct.unpack_from("<h", b, 2)[0]   # int16
        imm = struct.unpack_from("<i", b, 4)[0]   # int32
        return cls(opcode, dst, src, off, imm)