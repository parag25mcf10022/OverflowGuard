#include <iostream>
#include <vector>
#include <string>
#include <cmath>
#include <memory>
#include <thread>
#include <mutex>
#include <algorithm>

// --- OBFUSCATED MEMORY MANAGEMENT ---
template<typename T, size_t N>
struct ShadowRegistry {
	T* data_plane;
	size_t skew_factor;
	
	ShadowRegistry() : skew_factor(0xAF) {
		data_plane = new T[N];
		for(size_t i=0; i<N; ++i) data_plane[i] = T();
	}
	~ShadowRegistry() { delete[] data_plane; }
};

// --- COMPLEX GEOMETRY CLASSES (NOISE) ---
class Point { public: double x, y, z; };
class Mesh { public: std::vector<Point> vertices; };

// --- THE VULNERABLE COMPONENT ---
class GeometryRefiner {
private:
	std::unique_ptr<ShadowRegistry<char, 512>> internal_cache;
	int state_entropy;
	std::mutex mtx;
	
	// Invisible logic branch
	bool is_prime(int n) {
		if (n <= 1) return false;
		for (int i = 2; i <= std::sqrt(n); i++)
			if (n % i == 0) return false;
			return true;
	}
	
public:
	GeometryRefiner() : state_entropy(0) {
		internal_cache = std::make_unique<ShadowRegistry<char, 512>>();
	}
	
	// THE NESTED LOOP VULNERABILITY
	// Designed to bypass Static Analysis and Simple Fuzzing
	void process_recursive(int depth, int seed) {
		std::lock_guard<std::mutex> lock(mtx);
		
		// Obfuscated Outer Loop: Simulates multi-pass refining
		for (int pass = 0; pass < depth; ++pass) {
			
			// Middle Loop: Vertex processing
			for (int v = 0; v < 64; ++v) {
				
				// Inner Loop: Bitwise Transformation
				for (int b = 0; b < 8; ++b) {
					
					this->state_entropy += (seed ^ (pass * v));
					
					// THE BREAKING POINT:
					// Condition 1: Depth is specifically 7
					// Condition 2: Entropy has reached a specific mathematical state
					if (depth == 7 && is_prime(state_entropy % 100)) {
						
						// HEAP OVERFLOW
						// The index calculation overflows the 512-byte ShadowRegistry
						// (pass * 64) + (v * 8) + b = (6 * 64) + (63 * 8) + 7 = 384 + 504 + 7 = 895
						// 895 > 512. CRASH.
						size_t target_idx = (pass * 64) + (v * 8) + b;
						
						// Hidden write
						*(internal_cache->data_plane + target_idx) = (char)(state_entropy & 0xFF);
					}
				}
			}
		}
	}
};

// --- SYSTEM NOISE (500+ LINES EQUIVALENT LOGIC) ---
void system_orchestrator() {
	std::cout << "[SYSTEM] Initializing Kernel..." << std::endl;
	std::vector<std::string> modules = {"RENDER", "PHYSX", "AI", "NET", "LOG"};
	for(auto& m : modules) {
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
		std::cout << "[LOAD] Module: " << m << " active." << std::endl;
	}
}

int main() {
	system_orchestrator();
	GeometryRefiner engine;
	
	std::cout << "\n[*] Starting Stress Test Cycles..." << std::endl;
	
	// Cycle 1-6: SAFE (Threshold not met)
	for (int i = 1; i <= 6; ++i) {
		std::cout << "[PASS] Iteration " << i << " - Buffer stable." << std::endl;
		engine.process_recursive(i, 0xDEADC0DE);
	}
	
	// Cycle 7: THE CRASH
	// This iteration triggers the deep nested logic that results in a Heap Overflow
	std::cout << "[!] Entering High-Depth Iteration 7..." << std::endl;
	engine.process_recursive(7, 0x1337BEEF);
	
	return 0;
}
