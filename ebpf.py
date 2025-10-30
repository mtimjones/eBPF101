from __future__ import annotations

import io
import os
import sys
import struct
import bpf
import globals
from insn import Insn
from enum import IntEnum
from dataclasses import dataclass
from typing import List, Optional

class EBPFVM:
    STACK_SIZE = 96

    def __init__(self, code: bytes):
        self.vm_state = globals.VMStateClass.IDLE
        self.code = code
        self._insn = self._decode_all(code)
        self.reset()

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

    def get_vm_state(self) -> globals.VMStateClass:
        return self.vm_state 

    def set_vm_state(self, state) -> None:
        self.vm_state = state

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
        return {bpf.BPF_B:1, bpf.BPF_H:2, bpf.BPF_W:4, bpf.BPF_DW:8}[sz]

    def reset(self) -> None:
        self.steps = 0
        self.reg = [0] * 11    # R0..R10
        self.stack = bytearray(self.STACK_SIZE)
        self.reg[10] = len(self.stack)  # R10 (frame pointer) points to top of stack
        self.pc = 0

    def get_reg_value(self, register) -> str:
        val = self.reg[register]
        s = f"{val:016X}"
        s = f"{s[0:4]}_{s[4:8]}_{s[8:12]}_{s[12:16]}"
        return s;

    def get_pc(self) -> str:
        val = self.pc
        s = f"{val:03X}"
        return s;

    def get_stack(self, offset) -> str:
        ret = ""
        for i in range(8):
            val = self.stack[offset+i]
            ret += f"{val:02X} "
        return ret

    def get_disasm(self, offset) -> str:
        insn = self._insn[offset]
        return insn.to_str()

    def get_insn_hex(self, offset) -> str:
        insn = self._insn[offset]
        return insn.get_insn_hex()

    def step(self) -> None:
        if self.pc >= len(self._insn):
            return

        self.steps += 1
        ins = self._insn[self.pc]

        cls = ins.opcode & bpf.BPF_CLASS_MASK

        # 64-bit imm load: two slots (opcode 0x18 with BPF_LD|BPF_DW|BPF_IMM)
        if cls == bpf.BPF_LD and (ins.opcode & (bpf.BPF_OP_MASK | 0x07 | 0x18 | 0xE0)) == (bpf.BPF_DW | bpf.BPF_IMM | bpf.BPF_LD):
            # Combine next instruction's imm as high bits
            if self.pc + 1 >= len(self._insn):
                raise RuntimeError("Truncated 64-bit immediate load")
            ins2 = self._insn[self.pc + 1]
            imm64 = (ins2.imm << 32) & 0xFFFFFFFF00000000
            imm64 |= (ins.imm & 0xFFFFFFFF)
            # sign-extend to 64 bits (following kernel semantics)
            imm64 = self._s64(imm64)
            self.reg[ins.dst] = self._u64(imm64)
            self.pc += 2
            return

        if cls in (bpf.BPF_ALU, bpf.BPF_ALU64):
            self._exec_alu(ins, is64 = (cls == bpf.BPF_ALU64))
            self.pc += 1
            return

        if cls in (bpf.BPF_JMP, bpf.BPF_JMP32):
            taken = self._exec_jump(ins, is32 = (cls == bpf.BPF_JMP32))
            if taken is None:
                self.vm_state = globals.VMStateClass.EXITED
                # EXIT
                return
            if taken:
                self.pc += ins.off + 1  # relative jump (next + off)
            else:
                self.pc += 1
            return

        if cls in (bpf.BPF_LDX, bpf.BPF_STX, bpf.BPF_ST):
            self._exec_mem(ins)
            self.pc += 1
            return

        raise RuntimeError(f"Unsupported instruction class: {cls:#x} at pc={self.pc}")

    def _alu_binop(self, op: int, a: int, b: int, width64: bool) -> int:
        if not width64:
            a = self._u32(a)
            b = self._u32(b)
        if   op == bpf.BPF_ADD:  r = a + b
        elif op == bpf.BPF_SUB:  r = a - b
        elif op == bpf.BPF_MUL:  r = a * b
        elif op == bpf.BPF_DIV:  r = 0 if b == 0 else a // b
        elif op == bpf.BPF_OR:   r = a | b
        elif op == bpf.BPF_AND:  r = a & b
        elif op == bpf.BPF_LSH:  r = a << (b & 63)
        elif op == bpf.BPF_RSH:  r = (a & ((1<<(64 if width64 else 32))-1)) >> (b & 63)
        elif op == bpf.BPF_MOD:  r = 0 if b == 0 else a % b
        elif op == bpf.BPF_XOR:  r = a ^ b
        elif op == bpf.BPF_ARSH: r = (self._s64(a) >> (b & 63)) if width64 else (self._s32(a) >> (b & 31))
        else:
            raise RuntimeError(f"Unsupported ALU binop {op:#x}")
        return self._u64(r) if width64 else self._u32(r)

    def _exec_alu(self, ins: Insn, is64: bool) -> None:
        op = ins.opcode & bpf.BPF_OP_MASK
        src_is_reg = (ins.opcode & bpf.BPF_SRC_MASK) != 0

        if op == bpf.BPF_NEG:
            v = self.reg[ins.dst]
            r = - (self._s64(v) if is64 else self._s32(v))
            self.reg[ins.dst] = self._u64(r) if is64 else self._u32(r)
            return

        if op == bpf.BPF_MOV:
            val = self.reg[ins.src] if src_is_reg else ins.imm
            if is64:
                self.reg[ins.dst] = self._u64(val)
            else:
                self.reg[ins.dst] = self._u32(val)
            return

        # Binary operations
        b = self.reg[ins.src] if src_is_reg else ins.imm
        a = self.reg[ins.dst]
        res = self._alu_binop(op, a, b, width64=is64)
        self.reg[ins.dst] = res

    def _cmp(self, op: int, a: int, b: int, is32: bool) -> bool:
        if is32:
            a_u = self._u32(a); b_u = self._u32(b)
            a_s = self._s32(a); b_s = self._s32(b)
        else:
            a_u = self._u64(a); b_u = self._u64(b)
            a_s = self._s64(a); b_s = self._s64(b)

        if   op == bpf.BPF_JEQ:  return a_u == b_u
        elif op == bpf.BPF_JNE:  return a_u != b_u
        elif op == bpf.BPF_JGT:  return a_u >  b_u
        elif op == bpf.BPF_JGE:  return a_u >= b_u
        elif op == bpf.BPF_JLT:  return a_u <  b_u
        elif op == bpf.BPF_JLE:  return a_u <= b_u
        elif op == bpf.BPF_JSGT: return a_s >  b_s
        elif op == bpf.BPF_JSGE: return a_s >= b_s
        elif op == bpf.BPF_JSLT: return a_s <  b_s
        elif op == bpf.BPF_JSLE: return a_s <= b_s
        elif op == bpf.BPF_JSET: return (a_u & b_u) != 0
        else:
            raise RuntimeError(f"Unsupported jump op {op:#x}")

    def _exec_jump(self, ins: Insn, is32: bool) -> Optional[bool]:
        op = ins.opcode & bpf.BPF_OP_MASK
        src_is_reg = (ins.opcode & bpf.BPF_SRC_MASK) != 0

        # Unconditional jump (JA)
        if op == bpf.BPF_JA:
            return True

        # EXIT
        if op == bpf.BPF_EXIT:
            return None

        # CALL not yet supported in this VM
        if op == bpf.BPF_CALL:
            raise RuntimeError("Helper calls are not yet supported in this VM")

        a = self.reg[ins.dst]
        b = self.reg[ins.src] if src_is_reg else ins.imm
        cond = self._cmp(op, a, b, is32=is32)
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
        cls = ins.opcode & bpf.BPF_CLASS_MASK

        if cls == bpf.BPF_LDX:
            addr = self._addr_from_fp(ins.src, ins.off)
            val = self._read_stack(addr, size)
            if size != 8:
                val = {1: val & 0xFF, 2: val & 0xFFFF, 4: val & 0xFFFFFFFF}[size]
            self.reg[ins.dst] = self._u64(val)
            return

        if cls == bpf.BPF_STX:
            addr = self._addr_from_fp(ins.dst, ins.off)
            val = self.reg[ins.src]
            self._write_stack(addr, size, val)
            return

        if cls == bpf.BPF_ST:
            addr = self._addr_from_fp(ins.dst, ins.off)
            self._write_stack(addr, size, ins.imm)
            return

        raise RuntimeError("Unsupported memory instruction")
