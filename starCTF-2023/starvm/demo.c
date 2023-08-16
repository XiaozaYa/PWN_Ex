#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char** argv, char** env)
{

	char* str = "   16a132";
	long long n = strtol(str, 0, 10);
	printf("%lld\n", n);
	return 0;
}
