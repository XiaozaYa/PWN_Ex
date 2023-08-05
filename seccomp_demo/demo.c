#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
int main(int argc, char **argv){

	prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
	char *buf = "hello world!\n";
	write(0, buf, strlen(buf));
	printf("%s", "Hello World\n");
	return 0;
}
