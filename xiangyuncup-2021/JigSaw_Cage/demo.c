#include <stdio.h>
#include <unistd.h>
int main(int argc, char** argv, char** env)
{

	int a = 0;
	int b = 0;
	printf("%p\n%p\n", &a, &b);
	printf("a = %d, b = %d\n", a, b);	
	scanf("%d", &a);
	printf("a = %d, b = %d\n", a, b);	
	long long page = 0x1000;
	long long bss_ptr = 0x7f0123456789;
	printf("%llx\n", -page & bss_ptr);
	printf("%llx\n", (-page & (bss_ptr + 1024 + page - 1)) - (-page & bss_ptr));
	
	return 0;
}
