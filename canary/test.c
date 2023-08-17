#include <stdio.h>
#include <string.h>

void func1(){
	int a = 10;
	printf("Func1 int a = %d\n", a);
}


void func2(){
	char s[10] = "func2";
	gets(s);
	printf("Func2 char s[10] = %s\n", s);
}


void func3(){
	int a[10] = {0};
	char *s = "hello  world";
	printf("Func3 char *s = %s\n", s);
}

int main(){
	func1();
	func2();
	func3();
	return 0;
}