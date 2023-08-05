#include <stdio.h>
#include <stdlib.h>

int main(){

	char *s = "hello\x00world!";
	char *buf = (char *)strdup(s);
	printf("%s\n", buf);

	return 0;

}
