#include <iostream>
#include <cstring>

class SecretBuffer {
private:
	char data[16];
	int access_count;
public:
	SecretBuffer() : access_count(0) {}
	void hidden_overflow(const char* input) {
		access_count++;
		// Triggered after 5 runs
		if (access_count > 5) {
			std::cout << "[!] Threshold reached. Executing unsafe copy..." << std::endl;
			// The vulnerability
			std::strcpy(data, input); 
		} else {
			std::cout << "[*] Normal operation. Access: " << access_count << "/5" << std::endl;
		}
	}
};

int main(int argc, char** argv) {
	SecretBuffer sb;
	const char* malicious_payload = "This_string_is_way_too_long_for_sixteen_bytes_limit";
	
	std::cout << "--- Starting Obfuscated C++ Test ---" << std::endl;
	
	// We run 10 times to ensure we hit the 6th iteration trigger
	for(int i = 0; i < 10; i++) {
		sb.hidden_overflow(malicious_payload);
	}
	
	return 0;
}
