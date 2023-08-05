#include <stdio.h>
#include <stdlib.h>
int main()
{
	
	long long *p0, *p1, *p2, *p3, *p4, *p5;
	p0 = malloc(0x660);
	malloc(0x10);
	free(p0);
	p1 = malloc(0x80);
	malloc(0x5d0);
	return 0;
}
