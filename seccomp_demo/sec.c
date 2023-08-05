#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include "seccomp-bpf.h"

int main(){


	struct sock_filter filter[] = {

		VALID_ARCH,
		EXAMINE,
		ALLOW(rt_sigreturn),
	#ifdef __NR_sigreturn
		ALLOW(sigreturn),
	#endif
		ALLOW(exit),
		ALLOW(exit_group),
		ALLOW(read),
		ALLOW(write),
		ALLOW(execve),
		KILL,	
	};

	struct sock_fprog prog = {
		
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	if(!prctl(22, 1, 0, 0, 0)){
		perror("prctl(NO_NEW_PRIVS)");
	}
	if(prctl(38, 2, &prog)){
		perror("prctl(SECCOMP)");
	}
	
	printf("hello world\n");
	return 0;
}
