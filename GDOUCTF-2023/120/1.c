#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(){
  unsigned int v3 = time(0LL);
  srand(v3);
  unsigned int i;
  int v4 = rand();
  srand(v4 % 3 - 1522127470);
  for ( i = 1; (int)i <= 120; ++i )
  {
  	int tmp = rand();
  	//printf("%d ", tmp);
    printf("%d,",  tmp% 4 + 1);
  
  }

	return 0;
}