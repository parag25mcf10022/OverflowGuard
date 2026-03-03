#include <stdlib.h>
#include <string.h>

int main() {
	char *ptr = malloc(10);
	// Writing past the 10 bytes allocated on the heap
	ptr[12] = 'A'; 
	free(ptr);
	return 0;
}
