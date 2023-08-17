#include <stdio.h>
#include <stdlib.h>
int main(){

	char *ptr = malloc(0x200000);
	gets(ptr);
	return 0;
}
