# constants
BPF_CLASS_MASK = 0x07
BPF_SIZE_MASK  = 0x18
BPF_MODE_MASK  = 0xE0
BPF_SRC_MASK   = 0x08
BPF_OP_MASK    = 0xF0

BPF_LD    = 0x00
BPF_LDX   = 0x01
BPF_ST    = 0x02
BPF_STX   = 0x03
BPF_ALU   = 0x04
BPF_JMP   = 0x05
BPF_JMP32 = 0x06
BPF_ALU64 = 0x07

BPF_W  = 0x00
BPF_H  = 0x08
BPF_B  = 0x10
BPF_DW = 0x18

BPF_IMM  = 0x00
BPF_ABS  = 0x20
BPF_IND  = 0x40
BPF_MEM  = 0x60
BPF_XADD = 0xC0

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

