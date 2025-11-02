#include <stdint.h>

// Helper function to translate a put to a call-1.
static inline long vm_ringbuf_put(unsigned char msg)
{
    long ret;
    register long r1 __asm__("r1") = 0;    // Map, ignored.
    register long r2 __asm__("r2") = msg;  // Message (value)

    // Emit BPF_CALL imm=1
    asm volatile("call 1"
		    : "=r"(ret)
		    : "=r"(r1), "r"(r2));

    return 0;
}

uint64_t test_func(void)
{
    for (unsigned char i = 0x30 ; i < 0x3A ; i++)
    {
        vm_ringbuf_put(i);
    }

    return 0;
}

