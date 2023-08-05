#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(){

	char s[0x500];
	gets(s);
	((void(*)(void))s)();
	return 0;
}
