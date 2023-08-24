//gcc test.c -o test -w -g
//ubuntu 20.04     GLIBC 2.31
#include<stdio.h> 
#include <unistd.h> 
#define num 10
void *chunk_list[num];
int chunk_size[num];

void init()
{
	setbuf(stdin, 0);
	setbuf(stdout, 0);
	setbuf(stderr, 0);
}

void menu()
{
	puts("1.add");
	puts("2.edit");
	puts("3.show");
	puts("4.delete");
	puts("5.exit");
	puts("Your choice:");
}


int add()
{
	int index,size;
	puts("index:");
	scanf("%d",&index);
	if(index<0 || index>=num)
		exit(1);
	puts("Size:");
	scanf("%d",&size);
	if(size<0x80||size>0x500)
		exit(1);
	chunk_list[index] = calloc(size,1);
	chunk_size[index] = size;
}

int edit()
{
	int index;
	puts("index:");
	scanf("%d",&index);
	if(index<0 || index>=num)
		exit(1);
	puts("context: ");
	read(0,chunk_list[index],chunk_size[index]);
}

int delete()
{
	int index;
	puts("index:");
	scanf("%d",&index);
	if(index<0 || index>=num)
		exit(1);
		
	free(chunk_list[index]);
}

int show()
{
	int index;
	puts("index:");
	scanf("%d",&index);
	if(index<0 || index>=num)
		exit(1);
		
	puts("context: ");
	puts(chunk_list[index]);
}


int main()
{
	int choice;
	init();
	while(1){
		menu();
		scanf("%d",&choice);
		if(choice==5){
			exit(0);
		}
		else if(choice==1){
			add();
		}
		else if(choice==2){
			show();
		}
		else if(choice==3){
			edit();
		}
		else if(choice==4){
			delete();
		}
	}
}


