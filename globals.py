# globals
from enum import IntEnum

class VMStateClass(IntEnum):
    IDLE = 0x00
    RUNNING = 0x01
    EXITED = 0x02

