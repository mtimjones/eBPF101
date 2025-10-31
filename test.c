
#define SHM_MEM_BASE ((volatile unsigned char *)0x1000)


int test_prog(void)
{
    int limit = 16;
    int sum = 0;

    for (int i = 0 ; i < limit ; i++)
    {
        sum += *SHM_MEM_BASE+i;
    }

    return sum;
}
