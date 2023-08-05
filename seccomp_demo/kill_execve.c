#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

int main(int argc, char **argv){

	struct sock_filter filter[] = {

		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 4),
		BPF_JUMP(BPF_JMP+BPF_JEQ, 0XC000003E, 0, 2),
		BPF_STMT(BPF_LD+BPF_ABS, 0),
		BPF_JUMP(BPF_JMP+BPF_JEQ, 1, 1, 0),
		BPF_JUMP(BPF_JMP+BPF_JEQ, 59, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	};

	struct sock_fprog prog = {
	
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};
	
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
	
	char *buf = "Hello World!\n";
	//printf("%d\n", sizeof(filter[0]));
	//write(1, buf, strlen(buf));
	execve("/bin/sh", NULL, NULL);
	return 0;
}
