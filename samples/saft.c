#include <stdio.h>
#include <string.h>

#define LIMIT 128

void safe_parse(const char *input, int len) {
	char buffer[LIMIT];
	printf("[*] Safe Parsing: Checking bounds before copy...\n");
	
	for (int i = 0; i < len; i++) {
		// THE FIX: Explicitly check against LIMIT
		if (i < LIMIT - 1) {
			buffer[i] = input[i];
		} else {
			buffer[i] = '\0'; // Properly terminate
			printf("[!] Bounds reached. Truncating input safely.\n");
			break;
		}
	}
}

int main() {
	char *evil_input = "This string is much longer than the 128 byte limit allowed by the buffer!";
	safe_parse(evil_input, strlen(evil_input));
	return 0;
}
