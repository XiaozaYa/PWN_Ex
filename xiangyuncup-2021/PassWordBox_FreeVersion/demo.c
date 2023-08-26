#include <stdio.h>

int main(int argc, char** argv, char** env)
{
	char *ptr;
	printf("%p\n", &ptr);
	printf("%p\n", &ptr+1);
	return 0;
}
