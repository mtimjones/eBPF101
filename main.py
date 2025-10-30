import time
import sys
import curses
import argparse
import globals
from bpfelf import BpfELF
from ebpf import EBPFVM
from typing import Optional, List

MAX_W = 90
MAX_H = 30

def display_instructions(inswin, VM):

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
            inswin.addstr(2+j, 2, f"{i:2}:  {VM.get_insn_hex(i)}  ")
            inswin.addstr(VM.get_disasm(i), curses.color_pair(1) | curses.A_BOLD)
        else:
            inswin.addstr(2+j, 2, f"{i:2}:  {VM.get_insn_hex(i)}  {VM.get_disasm(i)}")
        j=j+1


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

    regwin = mainwin.derwin(14, 28, 1, 1)
    regwin.box()
    regwin.addstr(0, 2, " Registers ")
    regwin.addstr(1, 2,  f"R0 : {VM.get_reg_value(0)}")
    regwin.addstr(2, 2,  f"R1 : {VM.get_reg_value(1)}")
    regwin.addstr(3, 2,  f"R2 : {VM.get_reg_value(2)}")
    regwin.addstr(4, 2,  f"R3 : {VM.get_reg_value(3)}")
    regwin.addstr(5, 2,  f"R4 : {VM.get_reg_value(4)}")
    regwin.addstr(6, 2,  f"R5 : {VM.get_reg_value(5)}")
    regwin.addstr(7, 2,  f"R6 : {VM.get_reg_value(6)}")
    regwin.addstr(8, 2,  f"R7 : {VM.get_reg_value(7)}")
    regwin.addstr(9, 2,  f"R8 : {VM.get_reg_value(8)}")
    regwin.addstr(10, 2, f"R9 : {VM.get_reg_value(9)}")
    regwin.addstr(11, 2, f"FP : {VM.get_reg_value(10)}")
    regwin.addstr(12, 2, f"PC : {VM.get_pc()}")

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

    helpwin = mainwin.derwin(14, 26, 1, 63)
    helpwin.box()
    helpwin.addstr(0, 2, " Help ")
    helpwin.addstr(1, 2, "r - Reset VM")
    helpwin.addstr(2, 2, "n - Next Instruction")
    helpwin.addstr(3, 2, "g - Go (run)")
    helpwin.addstr(4, 2, "b - Interrupt VM")
    helpwin.addstr(5, 2, "q - Quit Debugger")
    helpwin.addstr(12, 2, f"VM State: {VM.get_vm_state().name}")

    inswin = mainwin.derwin(14, 88, 15, 1)
    inswin.box()
    inswin.addstr(0, 2, " Disassembly ")
    inswin.addstr(1, 2, "PC   Bytes                    Instruction")

    curses.init_pair(1, curses.COLOR_YELLOW, -1)  # pair 1 = yellow

    display_instructions(inswin, VM)

    # Refresh all windows at the same time.
    mainwin.noutrefresh()
    regwin.noutrefresh()
    stackwin.noutrefresh()
    helpwin.noutrefresh()
    inswin.noutrefresh()
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
            if ch in (ord('n'), 25):
                VM.step()
            elif ch in (ord('r'), 30):
                VM.reset()
            elif ch in (ord('g'), 37):
                VM.set_vm_state(globals.VMStateClass.RUNNING)

        if VM.get_vm_state() == globals.VMStateClass.RUNNING:
            if ch in (ord('b'), 98):
                VM.set_vm_state(globals.VMStateClass.IDLE)
            elif ch in (ord('r'), 30):
                VM.reset()
            else:
                VM.step()

        if VM.get_vm_state() == globals.VMStateClass.EXITED:
            if ch in (ord('r'), 30):
                VM.reset()
                VM.set_vm_state(globals.VMStateClass.IDLE)

        # Sleep for 50ms (allows user to watch the running program).
        time.sleep(0.05)


def main(argv: List[str]) -> None:

    p = argparse.ArgumentParser(description="Minimal eBPF VM for BPF ELF64 objects")
    p.add_argument("elf", help="Path to eBPF ELF object file")
    args = p.parse_args(argv)

    elf = BpfELF.from_file(args.elf)
    code = elf.find_exec_section()

    vm = EBPFVM(code)
    my_vm = {"name": vm, "object": args.elf}

    curses.wrapper(UI, my_vm)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
