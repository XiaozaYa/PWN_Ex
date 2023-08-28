#include <stdio.h>
#include <unistd.h>
int main()
{
	char buf[200];
	int a = 10;
	read(0, buf, 100);
	printf("hello %s\n", buf);
	write(1, "bye bye\n", 8);
	return 0;
}
