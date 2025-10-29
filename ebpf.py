#!/usr/bin/env python3
"""
Minimal, readable eBPF VM that loads the executable section from a BPF ELF64
object and interprets a practical subset of eBPF instructions.

Focus:
  - Simplicity and readability over completeness or speed
  - No verifier, no helpers, no maps (stack-only memory is supported)
  - ELF parsing kept minimal (ELF64 little-endian only, EM_BPF only)

Usage:
  python ebpf_vm.py path/to/program.o [-t]

Notes:
  * This VM supports many instructions you'll see in simple programs:
      - 64-bit imm load (BPF_LD | BPF_DW | BPF_IMM)
      - MOV/ADD/SUB/AND/OR/XOR/LSH/RSH/ARSH/MUL/DIV/MOD/NEG (ALU32 & ALU64)
      - Jumps: JA/JEQ/JNE/JGT/JGE/JLT/JLE/JSGT/JSGE/JSLT/JSLE/JSET (K/X forms)
      - EXIT
      - LDX/STX {B,H,W,DW} to stack via frame pointer (R10)
    If an instruction is unimplemented, a clear exception is raised.

  * The VM has these resources:
      - 11 64-bit regs (R0..R10), with R10 as read-only frame pointer
      - 512-byte stack (R10 points at stack_top = len(stack))
      - No helper calls, no maps, no program arrays, etc.

  * This is NOT a verifier and does no security checks beyond basic bounds
    checks on stack memory.

Author: (you)
"""
from __future__ import annotations

import io
import os
import sys
import struct
from insn import Insn
from bpfelf import BpfELF
from dataclasses import dataclass
from typing import List, Optional



# Masks & constants (see linux/bpf_common.h)
BPF_CLASS = 0x07
BPF_LD    = 0x00
BPF_LDX   = 0x01
BPF_ST    = 0x02
BPF_STX   = 0x03
BPF_ALU   = 0x04
BPF_JMP   = 0x05
BPF_JMP32 = 0x06
BPF_ALU64 = 0x07

BPF_SRC   = 0x08  # 0: K (imm), 1: X (src reg)
BPF_OP    = 0xF0

# Sizes (for LD/ST)
BPF_W  = 0x00  # 32-bit
BPF_H  = 0x08  # 16-bit
BPF_B  = 0x10  # 8-bit
BPF_DW = 0x18  # 64-bit

# Modes (we only use MEM here)
BPF_IMM = 0x00
BPF_ABS = 0x20
BPF_IND = 0x40
BPF_MEM = 0x60

# ALU/Jump operations
# (values are op bits masked by BPF_OP)
BPF_ADD  = 0x00
BPF_SUB  = 0x10
BPF_MUL  = 0x20
BPF_DIV  = 0x30
BPF_OR   = 0x40
BPF_AND  = 0x50
BPF_LSH  = 0x60
BPF_RSH  = 0x70
BPF_NEG  = 0x80
BPF_MOD  = 0x90
BPF_XOR  = 0xA0
BPF_MOV  = 0xB0
BPF_ARSH = 0xC0
BPF_END  = 0xD0  # ignored here

# Jumps
BPF_JA   = 0x00
BPF_JEQ  = 0x10
BPF_JGT  = 0x20
BPF_JGE  = 0x30
BPF_JSET = 0x40
BPF_JNE  = 0x50
BPF_JSGT = 0x60
BPF_JSGE = 0x70
BPF_CALL = 0x80  # not supported
BPF_EXIT = 0x90
BPF_JLT  = 0xA0
BPF_JLE  = 0xB0
BPF_JSLT = 0xC0
BPF_JSLE = 0xD0


# ---------------------------------------------------------
# The VM
# ---------------------------------------------------------
class EBPFVM:
    STACK_SIZE = 96

    def __init__(self, code: bytes, trace: bool = False):
        self.code = code
        self.trace = trace
        self.reg = [0] * 11    # R0..R10
        self.stack = bytearray(self.STACK_SIZE)
        self.reg[10] = len(self.stack)  # R10 (frame pointer) points to top of stack
        self.pc = 0
        self._insn = self._decode_all(code)

    # ------------------------ decoding ------------------------
    def _decode_all(self, code: bytes) -> List[Insn]:
        if len(code) % 8 != 0:
            raise Exception("Executable section size is not a multiple of 8 bytes")
        ins: List[Insn] = []
        for i in range(0, len(code), 8):
            ins.append(Insn.from_bytes(code[i:i+8]))
        return ins

    # ------------------------ helpers -------------------------
    @staticmethod
    def _u32(x: int) -> int:
        return x & 0xFFFFFFFF

    @staticmethod
    def _s32(x: int) -> int:
        x &= 0xFFFFFFFF
        return x if x < 0x80000000 else x - 0x100000000

    @staticmethod
    def _u64(x: int) -> int:
        return x & 0xFFFFFFFFFFFFFFFF

    @staticmethod
    def _s64(x: int) -> int:
        x &= 0xFFFFFFFFFFFFFFFF
        return x if x < 0x8000000000000000 else x - 0x10000000000000000

    def _read_stack(self, addr: int, size: int) -> int:
        if not (0 <= addr and addr + size <= len(self.stack)):
            raise RuntimeError("Stack access out of bounds")
        b = self.stack[addr:addr+size]
        if size == 1:
            return b[0]
        if size == 2:
            return struct.unpack_from("<H", b)[0]
        if size == 4:
            return struct.unpack_from("<I", b)[0]
        if size == 8:
            return struct.unpack_from("<Q", b)[0]
        raise RuntimeError("Invalid size for stack read")

    def _write_stack(self, addr: int, size: int, value: int) -> None:
        if not (0 <= addr and addr + size <= len(self.stack)):
            raise RuntimeError("Stack access out of bounds")
        if size == 1:
            self.stack[addr] = value & 0xFF
        elif size == 2:
            struct.pack_into("<H", self.stack, addr, value & 0xFFFF)
        elif size == 4:
            struct.pack_into("<I", self.stack, addr, value & 0xFFFFFFFF)
        elif size == 8:
            struct.pack_into("<Q", self.stack, addr, value & 0xFFFFFFFFFFFFFFFF)
        else:
            raise RuntimeError("Invalid size for stack write")

    def _mem_size_from_opcode(self, opcode: int) -> int:
        sz = opcode & 0x18
        return {BPF_B:1, BPF_H:2, BPF_W:4, BPF_DW:8}[sz]

    def _trace(self, msg: str) -> None:
        if self.trace:
            print(f"[pc={self.pc}] {msg}")

    # ------------------------- run loop -----------------------
    def run(self, max_steps: int = 100000) -> int:
        steps = 0
        while self.pc < len(self._insn):
            steps += 1
            if steps > max_steps:
                raise RuntimeError("Instruction step limit exceeded")

            ins = self._insn[self.pc]
            cls = ins.opcode & BPF_CLASS

            # 64-bit imm load: two slots (opcode 0x18 with BPF_LD|BPF_DW|BPF_IMM)
            if cls == BPF_LD and (ins.opcode & (BPF_OP | 0x07 | 0x18 | 0xE0)) == (BPF_DW | BPF_IMM | BPF_LD):
                # Combine next instruction's imm as high bits
                if self.pc + 1 >= len(self._insn):
                    raise RuntimeError("Truncated 64-bit immediate load")
                ins2 = self._insn[self.pc + 1]
                imm64 = (ins2.imm << 32) & 0xFFFFFFFF00000000
                imm64 |= (ins.imm & 0xFFFFFFFF)
                # sign-extend to 64 bits (following kernel semantics)
                imm64 = self._s64(imm64)
                self.reg[ins.dst] = self._u64(imm64)
                self._trace(f"LD_IMM64 r{ins.dst} = {self.reg[ins.dst]:#x}")
                self.pc += 2
                continue

            if cls in (BPF_ALU, BPF_ALU64):
                self._exec_alu(ins, is64 = (cls == BPF_ALU64))
                self.pc += 1
                continue

            if cls in (BPF_JMP, BPF_JMP32):
                taken = self._exec_jump(ins, is32 = (cls == BPF_JMP32))
                if taken is None:
                    # EXIT
                    return self._exit_value()
                if taken:
                    self.pc += ins.off + 1  # relative jump (next + off)
                else:
                    self.pc += 1
                continue

            if cls in (BPF_LDX, BPF_STX, BPF_ST):
                self._exec_mem(ins)
                self.pc += 1
                continue

            raise RuntimeError(f"Unsupported instruction class: {cls:#x} at pc={self.pc}")

        # If we drop off the end, return R0
        return self._exit_value()

    def _exit_value(self) -> int:
        return self._u64(self.reg[0])

    # ---------------------- operations -----------------------
    def _alu_binop(self, op: int, a: int, b: int, width64: bool) -> int:
        if not width64:
            a = self._u32(a)
            b = self._u32(b)
        if   op == BPF_ADD:  r = a + b
        elif op == BPF_SUB:  r = a - b
        elif op == BPF_MUL:  r = a * b
        elif op == BPF_DIV:  r = 0 if b == 0 else a // b
        elif op == BPF_OR:   r = a | b
        elif op == BPF_AND:  r = a & b
        elif op == BPF_LSH:  r = a << (b & 63)
        elif op == BPF_RSH:  r = (a & ((1<<(64 if width64 else 32))-1)) >> (b & 63)
        elif op == BPF_MOD:  r = 0 if b == 0 else a % b
        elif op == BPF_XOR:  r = a ^ b
        elif op == BPF_ARSH: r = (self._s64(a) >> (b & 63)) if width64 else (self._s32(a) >> (b & 31))
        else:
            raise RuntimeError(f"Unsupported ALU binop {op:#x}")
        return self._u64(r) if width64 else self._u32(r)

    def _exec_alu(self, ins: Insn, is64: bool) -> None:
        op = ins.opcode & BPF_OP
        src_is_reg = (ins.opcode & BPF_SRC) != 0

        if op == BPF_NEG:
            v = self.reg[ins.dst]
            r = - (self._s64(v) if is64 else self._s32(v))
            self.reg[ins.dst] = self._u64(r) if is64 else self._u32(r)
            self._trace(f"NEG{64 if is64 else 32} r{ins.dst}")
            return

        if op == BPF_MOV:
            val = self.reg[ins.src] if src_is_reg else ins.imm
            if is64:
                self.reg[ins.dst] = self._u64(val)
            else:
                self.reg[ins.dst] = self._u32(val)
            self._trace(f"MOV{64 if is64 else 32} r{ins.dst} = {val:#x} (from {'r'+str(ins.src) if src_is_reg else 'imm'})")
            return

        # Binary operations
        b = self.reg[ins.src] if src_is_reg else ins.imm
        a = self.reg[ins.dst]
        res = self._alu_binop(op, a, b, width64=is64)
        self.reg[ins.dst] = res
        self._trace(f"ALU{64 if is64 else 32} op={op:#x} r{ins.dst} <- {res:#x}")

    def _cmp(self, op: int, a: int, b: int, is32: bool) -> bool:
        if is32:
            a_u = self._u32(a); b_u = self._u32(b)
            a_s = self._s32(a); b_s = self._s32(b)
        else:
            a_u = self._u64(a); b_u = self._u64(b)
            a_s = self._s64(a); b_s = self._s64(b)

        if   op == BPF_JEQ:  return a_u == b_u
        elif op == BPF_JNE:  return a_u != b_u
        elif op == BPF_JGT:  return a_u >  b_u
        elif op == BPF_JGE:  return a_u >= b_u
        elif op == BPF_JLT:  return a_u <  b_u
        elif op == BPF_JLE:  return a_u <= b_u
        elif op == BPF_JSGT: return a_s >  b_s
        elif op == BPF_JSGE: return a_s >= b_s
        elif op == BPF_JSLT: return a_s <  b_s
        elif op == BPF_JSLE: return a_s <= b_s
        elif op == BPF_JSET: return (a_u & b_u) != 0
        else:
            raise RuntimeError(f"Unsupported jump op {op:#x}")

    def _exec_jump(self, ins: Insn, is32: bool) -> Optional[bool]:
        op = ins.opcode & BPF_OP
        src_is_reg = (ins.opcode & BPF_SRC) != 0

        # Unconditional jump (JA)
        if op == BPF_JA:
            self._trace(f"JA +{ins.off}")
            return True

        # EXIT
        if op == BPF_EXIT:
            self._trace("EXIT")
            return None

        # CALL not yet supported in this VM
        if op == BPF_CALL:
            raise RuntimeError("Helper calls are not yet supported in this VM")

        a = self.reg[ins.dst]
        b = self.reg[ins.src] if src_is_reg else ins.imm
        cond = self._cmp(op, a, b, is32=is32)
        self._trace(f"JMP op={op:#x} if {a:#x} ? {b:#x} => {'taken' if cond else 'not taken'}")
        return cond

    def _addr_from_fp(self, base_reg: int, off: int) -> int:
        if base_reg != 10:
            # For simplicity we only allow stack addressing via FP (R10)
            raise RuntimeError("Only R10 (frame pointer) based memory is supported")
        fp = self.reg[10]
        addr = fp + off
        return addr

    def _exec_mem(self, ins: Insn) -> None:
        size = self._mem_size_from_opcode(ins.opcode)
        cls = ins.opcode & BPF_CLASS

        if cls == BPF_LDX:
            addr = self._addr_from_fp(ins.src, ins.off)
            val = self._read_stack(addr, size)
            if size != 8:
                val = {1: val & 0xFF, 2: val & 0xFFFF, 4: val & 0xFFFFFFFF}[size]
            self.reg[ins.dst] = self._u64(val)
            self._trace(f"LDX size={size} r{ins.dst} <- [fp{ins.off:+d}] => {val:#x}")
            return

        if cls == BPF_STX:
            addr = self._addr_from_fp(ins.dst, ins.off)
            val = self.reg[ins.src]
            self._write_stack(addr, size, val)
            self._trace(f"STX size={size} [fp{ins.off:+d}] <- r{ins.src} ({val:#x})")
            return

        if cls == BPF_ST:
            addr = self._addr_from_fp(ins.dst, ins.off)
            self._write_stack(addr, size, ins.imm)
            self._trace(f"ST  size={size} [fp{ins.off:+d}] <- imm {ins.imm:#x}")
            return

        raise RuntimeError("Unsupported memory instruction")


# ---------------------------------------------------------
# CLI
# ---------------------------------------------------------
def main(argv: List[str]) -> int:
    import argparse

    p = argparse.ArgumentParser(description="Minimal eBPF VM for BPF ELF64 objects")
    p.add_argument("elf", help="Path to eBPF ELF object (EM_BPF)")
    p.add_argument("-t", "--trace", action="store_true", help="Trace execution")
    p.add_argument("-d", "--debug", action="store_true", help="Visually debug the eBPF object." )
    args = p.parse_args(argv)

    if args.trace and args.debug:
        print("One of debug or trace may be specified.\n")
        exit(-1)

    elf = BpfELF.from_file(args.elf)
    code = elf.find_exec_section()

    vm = EBPFVM(code, trace=args.trace)
    ret = vm.run()
    print(f"Program exited with R0={ret} (0x{ret:x})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
