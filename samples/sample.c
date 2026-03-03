#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* MANUALLY DECLARE FORBIDDEN FUNCTIONS FOR TESTING */
char *gets(char *str); 

void stack_demo() {
	char buffer[16];
	char *input = "This_string_is_way_too_long_for_sixteen_bytes";
	printf("[*] Testing Stack Overflow with strcpy...\n");
	// STACK OVERFLOW POINT
	strcpy(buffer, input); 
}

void heap_demo() {
	char *ptr = (char *)malloc(10);
	printf("[*] Testing Heap Overflow via manual loop...\n");
	// HEAP OVERFLOW POINT
	for(int i = 0; i < 50; i++) {
		ptr[i] = 'A'; 
	}
	free(ptr);
}

void forbidden_demo() {
	char buf[10];
	printf("[*] Testing Banned Function gets()...\n");
	printf("Type something long: ");
	// BANNED FUNCTION POINT
	gets(buf); 
}

int main(int argc, char *argv[]) {
	printf("--- VULNERABILITY TEST SUITE ---\n");
	
	// Choose which one to trigger for Dynamic Analysis
	// ASan stops at the FIRST error it finds.
	stack_demo();
	// heap_demo(); 
	// forbidden_demo();
	
	return 0;
}
