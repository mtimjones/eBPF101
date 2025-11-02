class ByteRing:
    SIZE = 32

    def __init__(self):
        self.reset()

    def get_byte(self, offset):
        return self.buf[offset]

    def reset(self):
        self.buf = bytearray(self.SIZE)
        self.head = 0   # next write
        self.tail = 0   # next read

    def push(self, b: int) -> bool:
        """Push one byte. Returns False if full."""
        nxt = (self.head + 1) % self.SIZE
        if nxt == self.tail:
            return False  # full
        self.buf[self.head] = b & 0xFF
        self.head = nxt
        return True

    def pop(self) -> int | None:
        """Pop one byte. Returns None if empty."""
        if self.head == self.tail:
            return None  # empty
        b = self.buf[self.tail]
        self.tail = (self.tail + 1) % self.SIZE
        return b

    def __len__(self):
        if self.head >= self.tail:
            return self.head - self.tail
        else:
            return self.SIZE - (self.tail - self.head)

    def empty(self) -> bool:
        return self.head == self.tail

    def full(self) -> bool:
        return (self.head + 1) % self.SIZE == self.tail

    def get_head(self) -> int:
        return self.head

    def get_tail(self) -> int:
        return self.tail

