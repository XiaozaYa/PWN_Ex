#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
const uint16_t size_classes[] = {
    1, 2, 3, 4, 5, 6, 7, 8,
    9, 10, 12, 15,
    18, 20, 25, 31,
    36, 42, 50, 63,
    72, 84, 102, 127,
    146, 170, 204, 255,
    292, 340, 409, 511,
    584, 682, 818, 1023,
    1169, 1364, 1637, 2047,
    2340, 2730, 3276, 4095,
    4680, 5460, 6552, 8191,
};
#define IB 4
static inline int a_ctz_32(uint32_t x)
{
#ifdef a_clz_32
    return 31-a_clz_32(x&-x);
#else
    static const char debruijn32[32] = {
        0, 1, 23, 2, 29, 24, 19, 3, 30, 27, 25, 11, 20, 8, 4, 13,
        31, 22, 28, 18, 26, 10, 7, 12, 21, 17, 9, 6, 16, 5, 15, 14
    };
    return debruijn32[(x&-x)*0x076be629 >> 27];
#endif
}
static inline int a_clz_32(uint32_t x)
{
    x >>= 1;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    x++;
    return 31-a_ctz_32(x);
}
static inline int size_to_class(size_t n)
{
    n = (n+IB-1)>>4;
    if (n<10) return n;
    n++;
    int i = (28-a_clz_32(n))*4 + 8;
    if (n>size_classes[i+1]) i+=2;
    if (n>size_classes[i]) i++;
    return i;
}


int main(int argc, char** argv, char** env)
{

	int i = 0;
	int buf[0x100000] = {0};
	for (i = 0; i < 0x100000; i++)
	{
		int m = size_to_class(i);
		if (m > 48) break;
		if (!buf[m])
		{
			printf("%6d -> %2d\n", i, size_to_class(i));
			buf[m] = 1;
		}
	}
	return 0;
}
