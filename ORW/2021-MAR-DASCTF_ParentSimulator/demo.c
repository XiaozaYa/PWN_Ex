#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv, char** env)
{
	void *p[7];
	void *p1, *p2;
	int i = 0;
	for (;i < 7; i++)
		p[i] = malloc(0x80);
	p1 = malloc(0x80);
	p2 = malloc(0x80);
	malloc(0x10);
	for (i = 0; i < 7; i++)
		free(p[i]);
	free(p2);
	free(p1);
	return 0;
}
