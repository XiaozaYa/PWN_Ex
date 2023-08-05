#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv){
	
		
	long long *p0, *p1, *p2, *p3, *p4, *p5, *p6, *p7, *p8; 
	
	p0 = (long long *)malloc(0x500);
	malloc(0x10);
	p1 = (long long *)malloc(0x510);
	malloc(0x10);
	p2 = (long long *)malloc(0x520);
	malloc(0x10);
	p3 = (long long *)malloc(0x500);
        malloc(0x10);
	p4 = (long long *)malloc(0x510);
	malloc(0x10);
	p5 = (long long *)malloc(0x520);
	malloc(0x10);
	p6 = (long long *)malloc(0x500);
        malloc(0x10);
	p7 = (long long *)malloc(0x510);
        malloc(0x10);
        p5 = (long long *)malloc(0x520);
	malloc(0x10);
	free(p0);
	free(p1);
	free(p2);
	free(p3);
	free(p4);	
	free(p5);
	free(p6);
	free(p7);
	free(p8);
	malloc(0x540);
	return 0;
}
