import time
import sys
import curses
import argparse
import globals
from bpfelf import BpfELF
from ebpf import EBPFVM
from typing import Optional, List

MAX_W = 90
MAX_H = 37

def display_memory(mainwin, VM):

    memwin = mainwin.derwin(7, 88, 15, 1)
    memwin.box()
    memwin.addstr(0, 2, " Memory ")
    memwin.addstr(1, 2, f"Addr  Bytes {' '*42} ASCII")
    memwin.addstr(2, 2, VM.get_mem(0));
    memwin.addstr(3, 2, VM.get_mem(16));
    memwin.addstr(4, 2, VM.get_mem(32));
    memwin.addstr(5, 2, VM.get_mem(48));

    memwin.noutrefresh()

def display_instructions(mainwin, VM):

    inswin = mainwin.derwin(14, 88, 22, 1)
    inswin.box()
    inswin.addstr(0, 2, " Disassembly ")
    inswin.addstr(1, 2, f"PC   Bytes {' '*18} Instruction")

    curses.init_pair(1, curses.COLOR_YELLOW, -1)  # pair 1 = yellow

    window_size = 11
    n = VM.get_code_size()
    pc = VM.pc
    if n == 0:
        return

    # Clamp PC to valid range
    pc = max(0, min(pc, n - 1))

    # Compute window bounds
    start = max(0, min(pc, n - window_size))
    end = min(n, start + window_size)

    # Render items; PC always visible
    j = 0
    for i in range(start, end):
        if i == pc:
            inswin.addstr(2+j, 2, f"{i:02X}:  {VM.get_insn_hex(i)}  ")
            inswin.addstr(VM.get_disasm(i), curses.color_pair(1) | curses.A_BOLD)
        else:
            inswin.addstr(2+j, 2, f"{i:02X}:  {VM.get_insn_hex(i)}  {VM.get_disasm(i)}")
        j=j+1

    inswin.noutrefresh()


def display_registers(mainwin, VM):

    regwin = mainwin.derwin(14, 28, 1, 1)
    regwin.box()
    regwin.addstr(0, 2, " Registers ")

    # One-time color/attr init (stored on the function as "static")
    if not hasattr(display_registers, "_inited"):
        display_registers._inited = True
        display_registers._prev_regs = None  # will store [R0..R9, FP, PC]
        curses.init_pair(1, curses.COLOR_YELLOW, -1)

    # Read current values
    cur = [0] * 12
    cur[0]  = VM.get_reg_value(0)
    cur[1]  = VM.get_reg_value(1)
    cur[2]  = VM.get_reg_value(2)
    cur[3]  = VM.get_reg_value(3)
    cur[4]  = VM.get_reg_value(4)
    cur[5]  = VM.get_reg_value(5)
    cur[6]  = VM.get_reg_value(6)
    cur[7]  = VM.get_reg_value(7)
    cur[8]  = VM.get_reg_value(8)
    cur[9]  = VM.get_reg_value(9)
    cur[10] = VM.get_reg_value(10)  # FP
    cur[11] = VM.get_pc()           # PC

    prev = display_registers._prev_regs

    # Helper to print a line, highlighted if changed
    def put(y, x, text, changed):
        if changed:
            regwin.addstr(y, x, text, curses.color_pair(1) | curses.A_BOLD)
        else:
            regwin.addstr(y, x, text)

    # Emit R0..R9
    i = 0
    while i < 10:
        label = f"R{i} : {cur[i]}"
        changed = (prev is None) or (cur[i] != prev[i])
        put(i+1, 2, label.ljust(24), changed)
        i += 1

    # FP (R10)
    label_fp = f"FP : {cur[10]}"
    changed_fp = (prev is None) or (cur[10] != prev[10])
    put(11, 2, label_fp.ljust(24), changed_fp)

    # PC
    label_pc = f"PC : {cur[11]}"
    put(12, 2, label_pc.ljust(24), False)

    # Persist snapshot for next call
    display_registers._prev_regs = cur


def display_stack(mainwin, VM):
    stackwin = mainwin.derwin(14, 34, 1, 29)
    stackwin.box()
    stackwin.addstr(0, 2, " Stack ")
    stackwin.addstr(1, 2, f"fp-00: {VM.get_stack(0)}")
    stackwin.addstr(2, 2, f"fp-08: {VM.get_stack(8)}")
    stackwin.addstr(3, 2, f"fp-10: {VM.get_stack(16)}")
    stackwin.addstr(4, 2, f"fp-18: {VM.get_stack(24)}")
    stackwin.addstr(5, 2, f"fp-20: {VM.get_stack(32)}")
    stackwin.addstr(6, 2, f"fp-28: {VM.get_stack(40)}")
    stackwin.addstr(7, 2, f"fp-30: {VM.get_stack(48)}")
    stackwin.addstr(8, 2, f"fp-38: {VM.get_stack(56)}")
    stackwin.addstr(9, 2, f"fp-40: {VM.get_stack(64)}")
    stackwin.addstr(10, 2, f"fp-48: {VM.get_stack(72)}")
    stackwin.addstr(11, 2, f"fp-50: {VM.get_stack(80)}")
    stackwin.addstr(12, 2, f"fp-58: {VM.get_stack(88)}")

    stackwin.noutrefresh()


def display_help(mainwin, VM):
    helpwin = mainwin.derwin(14, 26, 1, 63)
    helpwin.box()
    helpwin.addstr(0, 2, " Help ")
    helpwin.addstr(1, 2, "r - Reset VM")
    helpwin.addstr(2, 2, "n - Next Instruction")
    helpwin.addstr(3, 2, "g - Go (run)")
    helpwin.addstr(4, 2, "b - Interrupt VM")
    helpwin.addstr(5, 2, "q - Quit Debugger")
    helpwin.addstr(11, 2, f"VM Steps: {VM.get_steps()}")
    helpwin.addstr(12, 2, f"VM State: {VM.get_vm_state().name}")

    helpwin.noutrefresh()


# Horribly inefficient, but works for now...
def draw(stdscr, vm):

    VM = vm['name']
    object = vm['object']

    # Ensure the window is large enough to support the application.
    maxh, maxw = stdscr.getmaxyx()
    if maxh < MAX_H or maxw < MAX_W:
        stdscr.addstr(0,0, f"Resize to at least {MAX_W}x{MAX_H} (current: {maxw}x{maxh}).")
        stdscr.refresh()
        stdscr.getch()
        return

    start_h = max(0, (maxh - MAX_H) // 2)
    start_w = max(0, (maxw - MAX_W) // 2)

    mainwin = curses.newwin(MAX_H, MAX_W, start_h, start_w)
    mainwin.box()
    mainwin.addstr(0, 2, f" eBPF Debugger [{object}] ")

    display_registers(mainwin, VM)
    display_stack(mainwin, VM)
    display_help(mainwin, VM)
    display_memory(mainwin, VM)

    display_instructions(mainwin, VM)

    # Refresh all windows at the same time.
    mainwin.noutrefresh()
    stdscr.noutrefresh()
    curses.doupdate()

    stdscr.refresh()

def UI(stdscr, vm):
    stdscr.clear()
    curses.curs_set(0)
    curses.noecho()
    curses.cbreak()
    stdscr.nodelay(True)
    stdscr.keypad(True)
    curses.start_color()
    curses.use_default_colors()

    # Debugger loop -- nodelay is set above, so getch does not block.
    while True:
        draw(stdscr, vm)
        VM = vm['name']
        ch = stdscr.getch()

        if ch in (ord('q'), 27):
            break

        if VM.get_vm_state() == globals.VMStateClass.IDLE:
            if ch == ord('n'):
                VM.step()
            elif ch == ord('r'):
                VM.reset()
            elif ch == ord('g'):
                VM.set_vm_state(globals.VMStateClass.RUNNING)

        if VM.get_vm_state() == globals.VMStateClass.RUNNING:
            if ch == ord('b'):
                VM.set_vm_state(globals.VMStateClass.IDLE)
            elif ch == ord('r'):
                VM.reset()
            else:
                VM.step()

        if VM.get_vm_state() == globals.VMStateClass.EXITED:
            if ch == ord('r'):
                VM.reset()
                VM.set_vm_state(globals.VMStateClass.IDLE)

        # Sleep for 100ms (allows user to watch the running program).
        time.sleep(0.1)


def main(argv: List[str]) -> None:

    p = argparse.ArgumentParser(description="Minimal eBPF VM for BPF ELF64 objects")
    p.add_argument("elf", help="Path to eBPF ELF object file")
    p.add_argument("--mem-hex", help="White-space hex bytes for memory.")
    args = p.parse_args(argv)

    elf = BpfELF.from_file(args.elf)
    code = elf.find_exec_section()

    vm = EBPFVM(code)
    my_vm = {"name": vm, "object": args.elf}

    if args.mem_hex:
        try:
            n = vm.load_mem_from_hexfile(args.mem_hex)
        except Exception as e:
            print(f"Error loading memory file: {e}", file=sys.stderr)
            return -1

    curses.wrapper(UI, my_vm)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
