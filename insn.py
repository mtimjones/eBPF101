import struct
from dataclasses import dataclass

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

    def to_str(self) -> str:
        from disasm import EBPFDisassembler  # local import to avoid circular ref
        dis = EBPFDisassembler()
        return dis.disasm(self)

    def to_bytes(self) -> bytes:
        regs = (self.src << 4) | self.dst
        return bytes([
            self.opcode,
            regs,
            self.off & 0xFF,
            (self.off >> 8) & 0xFF,
        ]) + self.imm.to_bytes(4, "little", signed=True)

    def get_insn_hex(self) -> str:
        b = self.to_bytes()
        return " ".join(f"{b:02X}" for b in self.to_bytes())

