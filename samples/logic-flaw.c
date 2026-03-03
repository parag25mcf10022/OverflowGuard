#include <stdio.h>
#include <limits.h>

void test_logic() {
	// 1. Integer Overflow
	int a = INT_MAX;
	printf("[*] Attempting Integer Overflow...\n");
	int b = a + 1; 
	printf("Value: %d\n", b);
	
	// 2. Division by Zero
	int x = 10;
	int y = 0;
	printf("[*] Attempting Division by Zero...\n");
	// Note: Some compilers optimize this out, so we use variables
	int z = x / y; 
	printf("Value: %d\n", z);
}

int main() {
	test_logic();
	return 0;
}
