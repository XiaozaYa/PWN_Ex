#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char** argv, char** env)
{

	char *p[10];
	int i = 0;
	int n = 10;
	for (i = 0; i < n; i++)
	{
		p[i] = malloc(0x30);
		strncpy(p[i], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 0x30);
		printf("%s\n", p[i]);
	}
	for (i = 0; i < n; i++)
		printf("%p\n", p[i]);	
	for (i = 2; i < n; i++)
	{
		free(p[i]);
		printf("%s\n", p[i]);
	}
	printf("------------------------------\n");
	for (i = 0; i < n; i++)
		p[i] = 0;
	for (i = 0; i < n; i++)
	{	
		p[i] = malloc(0x30);
		printf("%s\n", p[i]);
	}
	
	for (i = 0; i < n; i++)
		printf("%p\n", p[i]);	
	
	return 0;
}
