#include <stdio.h>

int call_function(unsigned int n) {
	sleep(n);
}

void call_function_two(void) {
	printf("multiple of 3\n");
}