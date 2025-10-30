import time
import sys
import curses
import argparse
from bpfelf import BpfELF
from ebpf import EBPFVM
from typing import Optional, List

MAX_W = 90
MAX_H = 30

# Horribly inefficient, but works for now...
def draw(stdscr, vm):

    vm = vm['name']

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
    mainwin.addstr(0, 2, " eBPF Debugger ")

    regwin = mainwin.derwin(14, 28, 1, 1)
    regwin.box()
    regwin.addstr(0, 2, " Registers ")
    regwin.addstr(1, 2,  "R0 : XXXX_XXXX_XXXX_XXXX")
    regwin.addstr(2, 2,  "R1 : XXXX_XXXX_XXXX_XXXX")
    regwin.addstr(3, 2,  "R2 : XXXX_XXXX_XXXX_XXXX")
    regwin.addstr(4, 2,  "R3 : XXXX_XXXX_XXXX_XXXX")
    regwin.addstr(5, 2,  "R4 : XXXX_XXXX_XXXX_XXXX")
    regwin.addstr(6, 2,  "R5 : XXXX_XXXX_XXXX_XXXX")
    regwin.addstr(7, 2,  "R6 : XXXX_XXXX_XXXX_XXXX")
    regwin.addstr(8, 2,  "R7 : XXXX_XXXX_XXXX_XXXX")
    regwin.addstr(9, 2,  "R8 : XXXX_XXXX_XXXX_XXXX")
    regwin.addstr(10, 2, "R9 : XXXX_XXXX_XXXX_XXXX")
    regwin.addstr(11, 2, "FP : XXXX_XXXX_XXXX_XXXX")
    regwin.addstr(12, 2, "PC : XXX")

    stackwin = mainwin.derwin(14, 34, 1, 29)
    stackwin.box()
    stackwin.addstr(0, 2, " Stack ")
    stackwin.addstr(1, 2, "fp-00: xx xx xx xx xx xx xx xx")
    stackwin.addstr(2, 2, "fp-08: xx xx xx xx xx xx xx xx")
    stackwin.addstr(3, 2, "fp-10: xx xx xx xx xx xx xx xx")
    stackwin.addstr(4, 2, "fp-18: xx xx xx xx xx xx xx xx")
    stackwin.addstr(5, 2, "fp-20: xx xx xx xx xx xx xx xx")
    stackwin.addstr(6, 2, "fp-28: xx xx xx xx xx xx xx xx")
    stackwin.addstr(7, 2, "fp-30: xx xx xx xx xx xx xx xx")
    stackwin.addstr(8, 2, "fp-38: xx xx xx xx xx xx xx xx")
    stackwin.addstr(9, 2, "fp-40: xx xx xx xx xx xx xx xx")
    stackwin.addstr(10, 2, "fp-48: xx xx xx xx xx xx xx xx")
    stackwin.addstr(11, 2, "fp-50: xx xx xx xx xx xx xx xx")
    stackwin.addstr(12, 2, "fp-58: xx xx xx xx xx xx xx xx")

    helpwin = mainwin.derwin(14, 26, 1, 63)
    helpwin.box()
    helpwin.addstr(0, 2, " Help ")
    helpwin.addstr(1, 2, "r - Reset VM")
    helpwin.addstr(2, 2, "n - Next Instruction")
    helpwin.addstr(3, 2, "q - Quit Debugger")
    helpwin.addstr(8, 2, f"State: {vm.get_vm_state()}")

    inswin = mainwin.derwin(14, 88, 15, 1)
    inswin.box()
    inswin.addstr(0, 2, " Disassembly ")
    inswin.addstr(1, 2, "PC    Bytes                    Instruction")

    inswin.addstr(2, 2, "0x00  b4 01 00 00 05 00 00 00  w1 = 0x5")
    inswin.addstr(3, 2, "0x01  63 1a fc ff 00 00 00 00  *(u32 *)(r10 - 0x4) = w1")

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

    while True:
        draw(stdscr, vm)
        ch = stdscr.getch()
        if ch in (ord('q'), 27):
            break

def main(argv: List[str]) -> None:
    p = argparse.ArgumentParser(description="Minimal eBPF VM for BPF ELF64 objects")
    p.add_argument("elf", help="Path to eBPF ELF object file")
    args = p.parse_args(argv)

    elf = BpfELF.from_file(args.elf)
    code = elf.find_exec_section()

    vm = EBPFVM(code)
    my_vm = {"name": vm}

    curses.wrapper(UI,my_vm)

    vm = EBPFVM(code)
    ret = vm.run()
    vm.reset()
    ret = vm.run()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))