// x86: gcc -m32 printable.c -o printable32
// x64: gcc printable.c -o printable64
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

int is_printable(char *s, int length)
{
    int i;

    for (i = 0; i < length; i ++)
    {
        if (s[i] <= 31 || s[i] >= 127)
        {
            return 0;
        }
    }
    return 1;
}

int main()
{
    char *buf = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    int tail = read(0, buf, 0x1000);

    alarm(60);

    if (buf[tail - 1] == '\n')
    {
        buf[tail - 1] = '\0';
        tail--;
    }

    if (!is_printable(buf, tail))
    {
        puts("It must be a printable string!");
        exit(-1);
    }
    asm("call *%0" ::"r"(buf));
    return 0;
}
