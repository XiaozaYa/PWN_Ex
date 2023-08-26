#include <stdio.h>
#include <stdlib.h>
int main(int argc, char** argv, char** env)
{
	char buf[100] = {0};
	char b[100] = {0};
	int x;
	printf("%p\n", buf);
	printf("%p\n", b);
	
	//scanf('
	scanf("%s %s", buf, b);
	//scanf(buf);
	//scanf(buf);
	printf("buf: %s\n", buf);
	printf("b  : %s\n", b);
	//printf("b: %s\n", b);
	return 0;
}
