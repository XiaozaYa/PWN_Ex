#include <stdio.h>

int main()
{
	char arr[] = "ACEG";
	char* p = arr;
	*p++ = 'X';
 	printf("%s\n%s\n", arr,p);
	return 0;
}
