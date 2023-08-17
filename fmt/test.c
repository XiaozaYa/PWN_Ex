#include <stdio.h>

int main(){
	int x = 200;
	int a = 10;
	float b = 3.14;
	char *s = "hello world!";
	printf("a = %d, b = %lf, c = %s, x = %d, %n x = %d\n", a, b, s, x, &x, x);
	printf("x = %d\n", x);
	//printf("a = %d, b = %lf, c = %s\n");
	return 0;
}