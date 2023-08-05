#include <stdio.h>
#include <stdlib.h>
#include <seccomp.h>
#include <linux/seccomp.h>

int main(int argc, char **argv){

	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_ALLOW);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
	seccomp_load(ctx);
	write(1, "Hello World\n", 12); 	
	execve("/bin/sh", NULL, NULL);
	return 0;
}
