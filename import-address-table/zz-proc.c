#include <stdio.h>
//#include "zz-lib.dll"

int main() {

	unsigned int a = 0;
	while(1) {
		printf("Sleeping for %d [seconds]\n", a);
		call_function(a);
		a++;
		if((a % 3) == 0) call_function_two();
	}
}