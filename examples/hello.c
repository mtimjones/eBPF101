#include <stdint.h>

#define SHM_MEM_BASE ((volatile unsigned char *)0x0000)

// Helper function to translate a put to a call-1 for ring-buffer output.
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


int main(void) {
    int N = SHM_MEM_BASE[0];    // First index is count.
    int seed = SHM_MEM_BASE[1]; // Second index is seed.
    int in_index = 2;
    int out_index = 16;

    SHM_MEM_BASE[out_index] = seed;  // Seed character.
    
    for (int i = 1 ; i < N+1 ; i++) {
        SHM_MEM_BASE[out_index] = (char)(SHM_MEM_BASE[out_index-1]+SHM_MEM_BASE[in_index-1]);
	vm_ringbuf_put(SHM_MEM_BASE[out_index]);
	out_index++;
	in_index++;
    }

    return 0;
}

