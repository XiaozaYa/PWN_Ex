#include<stdio.h>
#include<stdlib.h>
int main(){

	void *ptr = malloc(0x1000);
	malloc(0x10);
	free(ptr);
	malloc(0x10);
	ptr = malloc(0x400);
	malloc(0x10);
	return 0;
}
