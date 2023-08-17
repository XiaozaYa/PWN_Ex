#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>  
#include <sys/wait.h>

void getshell(void)
{
    system("/bin/sh");
}

void init(void)
{
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
}

void vuln(void)
{
    char buf[100];
    memset(buf, 0, sizeof(buf));
    read(0, buf, 0x200);
    //printf("%s\n", buf);
}
int main(void)
{
    init();
    while (1)
    {
        printf("Hello Hacker!\n");
        if (fork())
        {
            wait(NULL);
        }
        else
        {
            vuln();
            exit(0);
        }
    }

    return 0;
}
