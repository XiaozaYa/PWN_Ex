#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(){
    char data0[20];
    char data1[20];
    FILE *fp = fopen("test.txt", "rb");
    fread(data0, 1, 20, fp);
    fread(data1, 1, 8, fp);
    gets(data0);
    scanf("%s", data0);
    fscanf(fp, "%s", data0);
    return 0;
}
