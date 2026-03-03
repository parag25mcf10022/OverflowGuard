#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
	char *data = (char *)malloc(64);
	strcpy(data, "Secret Security Token");
	
	printf("[*] Freeing memory...\n");
	free(data);
	
	// VULNERABILITY: Use-After-Free (UAF)
	// The pointer 'data' still exists, but the memory it points to is gone.
	printf("[!] Attempting to access freed memory: %s\n", data);
	
	return 0;
}
