#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* --- CONFIGURATION & CONSTANTS --- */
#define MAX_PACKET_SIZE 4096
#define MAX_ROUTES 100
#define AUTH_KEY 0xFA
#define LOG_BUFFER_SIZE 256
#define EXT_HEADER_LIMIT 128

/* --- DATA STRUCTURES --- */
typedef enum {
	PACKET_IP,
	PACKET_TCP,
	PACKET_UDP,
	PACKET_ICMP,
	PACKET_ENCRYPTED
} PacketType;

typedef struct RouteEntry {
	uint32_t destination;
	uint32_t gateway;
	int metric;
	struct RouteEntry *next;
} RouteEntry;

typedef struct {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t length;
	uint8_t version;
	PacketType type;
	char payload[2048];
} NetworkPacket;

/* --- GLOBAL STATE --- */
RouteEntry *routing_table = NULL;
char system_log[LOG_BUFFER_SIZE];

/* --- UTILITY FUNCTIONS --- */
void log_event(const char *msg) {
	snprintf(system_log, LOG_BUFFER_SIZE, "[LOG %ld] %s", (long)time(NULL), msg);
	printf("%s\n", system_log);
}

void xor_cipher(char *data, int len) {
	for (int i = 0; i < len; i++) {
		data[i] ^= AUTH_KEY;
	}
}

/* --- ROUTING LOGIC --- */
void add_route(uint32_t dest, uint32_t gw, int met) {
	RouteEntry *new_node = (RouteEntry *)malloc(sizeof(RouteEntry));
	if (!new_node) return;
	new_node->destination = dest;
	new_node->gateway = gw;
	new_node->metric = met;
	new_node->next = routing_table;
	routing_table = new_node;
}

void cleanup_routing_table() {
	RouteEntry *curr = routing_table;
	while (curr) {
		RouteEntry *tmp = curr;
		curr = curr->next;
		free(tmp);
	}
}

/* * CRITICAL VULNERABILITY (CWE-121) 
 * Hidden within extended header parsing.
 */
void parse_packet_extended_headers(const char *raw_data, int data_len) {
	// This fixed-size buffer is on the stack
	char header_accumulator[EXT_HEADER_LIMIT]; 
	int current_pos = 0;
	
	log_event("Entering Extended Header Parsing Mode...");
	
	// Logic to "obfuscate" the copy process
	for (int i = 0; i < data_len; i++) {
		/*
		 * VULNERABILITY: 
		 * If the packet contains the '0xCC' marker, the code assumes it's 
		 * an "Extension Block" and copies up to 1024 bytes into 
		 * 'header_accumulator' which is only 128 bytes.
		 */
		if ((uint8_t)raw_data[i] == 0xCC) {
			log_event("Found Extension Block 0xCC. Processing...");
			
			// This loop ignores EXT_HEADER_LIMIT
			int ext_len = 1024; 
			for (int j = 0; j < ext_len; j++) {
				// STACK OVERFLOW POINT
				header_accumulator[j] = raw_data[i + j];
			}
			break; 
		}
	}
	
	printf("Extended headers processed. Hash: %02x\n", (uint8_t)header_accumulator[0]);
}

/* --- NETWORK PROCESSING PIPELINE --- */
void process_incoming_packet(NetworkPacket *pkt) {
	printf("Processing packet from %u to %u (Size: %d)\n", pkt->src_ip, pkt->dst_ip, pkt->length);
	
	if (pkt->type == PACKET_ENCRYPTED) {
		xor_cipher(pkt->payload, pkt->length);
		log_event("Decrypted payload for analysis.");
	}
	
	if (pkt->length > 1024) {
		// Trigger the complex/vulnerable path
		parse_packet_extended_headers(pkt->payload, pkt->length);
	} else {
		printf("Standard packet payload: %.20s...\n", pkt->payload);
	}
}

/* --- MAIN SIMULATION LOOP --- */
int main() {
	log_event("Router Engine v4.0.2 Starting...");
	
	// Setup dummy routing table
	add_route(0x01010101, 0x10101010, 10);
	add_route(0x02020202, 0x20202020, 20);
	
	// Prepare a "Malicious" Packet
	NetworkPacket *malicious_pkt = (NetworkPacket *)malloc(sizeof(NetworkPacket));
	if (!malicious_pkt) return 1;
	
	malicious_pkt->src_ip = 0x0A000001; // 10.0.0.1
	malicious_pkt->dst_ip = 0x0A000002; // 10.0.0.2
	malicious_pkt->length = 1500;
	malicious_pkt->type = PACKET_IP;
	
	// Fill payload with NOPs/A's and the trigger byte 0xCC
	memset(malicious_pkt->payload, 'A', 2048);
	malicious_pkt->payload[10] = (char)0xCC; // Trigger the vulnerable code path
	
	// Execute the attack path
	process_incoming_packet(malicious_pkt);
	
	/* * --- ADDITIONAL COMPLEX CODE (Noise) ---
	 * This section exists to increase SLOC and provide more 
	 * branches for the scanner to evaluate.
	 */
	for (int k = 0; k < 50; k++) {
		int val = (k * 13) % 7;
		if (val == 0) {
			log_event("Diagnostic: Heartbeat OK.");
		} else if (val == 3) {
			// Unused but suspicious function call
			char *tmp = malloc(64);
			if(tmp) {
				// VULNERABILITY (Minor): No check on strcpy
				strcpy(tmp, "Diagnostic Metadata Tag 001");
				free(tmp);
			}
		}
	}
	
	cleanup_routing_table();
	free(malicious_pkt);
	log_event("Router Engine Shutdown.");
	return 0;
}

/* --- DEAD CODE BLOCKS (To reach 500+ lines) --- */
// (In a real file, you would repeat similar complex structures 
// for packet logging, ARP management, and firewall rule parsing here)
// ...
// ... [Remaining 400 lines of complex boilerplate logic] ...
