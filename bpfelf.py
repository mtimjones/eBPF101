import struct
from typing import List, Optional

def _read(fmt: str, data: bytes, offset: int = 0):
    size = struct.calcsize(fmt)
    return struct.unpack_from(fmt, data, offset), size

class BpfELF:
    """Minimal ELF64(LE) parser to extract eBPF executable bytes.

    Looks for the first section with SHF_EXECINSTR (or a section named '.text')
    and returns its raw bytes.
    """

    ELF_MAGIC = b"\x7fELF"
    ELFCLASS64 = 2
    ELFDATA2LSB = 1
    EM_BPF = 247
    SHT_PROGBITS = 1
    SHF_EXECINSTR = 0x4

    ELF_HEADER_FMT = "<16sHHIQQQIHHHHHH"  # little-endian ELF64
    SEC_HEADER_FMT  = "<IIQQQQIIQQ"

    def __init__(self, blob: bytes):
        self.blob = blob
        self._parse_header()
        self._parse_sections()

    @classmethod
    def from_file(cls, path: str) -> "BpfELF":
        with open(path, "rb") as f:
            return cls(f.read())

    def _parse_header(self) -> None:
        (eh, _sz) = _read(self.ELF_HEADER_FMT, self.blob, 0)
        (e_ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
         e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = eh

        # Basic validation
        if len(e_ident) < 16 or e_ident[:4] != self.ELF_MAGIC:
            raise Exception("Not an ELF file")
        if e_ident[4] != self.ELFCLASS64:
            raise Exception("Only ELF64 supported")
        if e_ident[5] != self.ELFDATA2LSB:
            raise Exception("Only little-endian ELF supported")
        if e_machine != self.EM_BPF:
            raise Exception(f"ELF e_machine {e_machine} is not EM_BPF ({self.EM_BPF})")

        self.e_shoff = e_shoff
        self.e_shentsize = e_shentsize
        self.e_shnum = e_shnum
        self.e_shstrndx = e_shstrndx

    def _parse_sections(self) -> None:
        # Read all section headers
        sh: List[tuple] = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            (h, _sz) = _read(self.SEC_HEADER_FMT, self.blob, off)
            sh.append(h)
        self.sections = sh

        # Read section-header string table
        if not (0 <= self.e_shstrndx < len(sh)):
            raise Exception("Invalid e_shstrndx")
        shstr = sh[self.e_shstrndx]
        shstr_off = shstr[4]  # sh_offset
        shstr_size = shstr[5] # sh_size
        self.shstrtab = self.blob[shstr_off: shstr_off + shstr_size]

    def _sec_name(self, shdr: tuple) -> str:
        sh_name = shdr[0]
        end = self.shstrtab.find(b"\x00", sh_name)
        if end == -1:
            return ""
        return self.shstrtab[sh_name:end].decode("ascii", errors="replace")

    def find_exec_section(self) -> bytes:
        """Return bytes of the first executable section (or .text fallback)."""
        candidate_idx: Optional[int] = None
        text_idx: Optional[int] = None

        for i, h in enumerate(self.sections):
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = h
            name = self._sec_name(h)
            if name == ".text":
                text_idx = i
            if sh_type == self.SHT_PROGBITS and (sh_flags & self.SHF_EXECINSTR):
                candidate_idx = i
                break

        idx = candidate_idx if candidate_idx is not None else text_idx
        if idx is None:
            raise Exception("No executable (.text) section found")

        h = self.sections[idx]
        sh_offset, sh_size = h[4], h[5]
        return self.blob[sh_offset: sh_offset + sh_size]
