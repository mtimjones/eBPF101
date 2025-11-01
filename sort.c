
#define SHM_MEM_BASE ((volatile unsigned char *)0x0000)

void sort_bytes() {
    char n = SHM_MEM_BASE[0];  // First byte is number of bytes to sort.
    volatile unsigned char* a = &SHM_MEM_BASE[1];

    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - i - 1; j++) {
            if (a[j] > a[j + 1]) {
                unsigned char tmp = a[j];
                a[j] = a[j + 1];
                a[j + 1] = tmp;
            }
        }
    }
}
