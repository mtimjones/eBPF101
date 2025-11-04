
#define SHM_MEM_BASE ((volatile unsigned char *)0x0000)

// Search for and count 0xff in the memory space.
int test_prog(void)
{
    int limit = 64;
    int count = 0;

    for (int i = 0 ; i < limit ; i++) {
        if (SHM_MEM_BASE[i] == 0xff) {
	    SHM_MEM_BASE[i] = 0;
	    count++;
	} else {
	    SHM_MEM_BASE[i]++;
	}
    }

    return count;
}
