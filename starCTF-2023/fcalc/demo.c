#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char** argv, char** env)
{

	malloc(0x10);
	char* p0 = alloca(0x180);
	char* p1 = alloca(0x40);
	printf("p0 => %p\np1 => %p\n", p0, p1);
	memset(p1, 'A', 0x40);
	memset(p0, 'B', 0x180);
	return 0;
}
