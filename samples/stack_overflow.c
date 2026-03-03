#include <stdio.h>
#include <string.h>

int main() {
	char buffer[10];
	// This is the classic vulnerability: strcpy doesn't check bounds
	char *dangerous_input = "This string is way too long for a ten byte buffer!";
	
	printf("Attempting to copy string into buffer...\n");
	strcpy(buffer, dangerous_input); 
	
	printf("Buffer content: %s\n", buffer);
	return 0;
}
