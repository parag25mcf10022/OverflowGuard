#include <iostream>
#include <vector>
#include <memory>
#include <cstring>

// Template-based Buffer Management to hide the allocation size
template <int S>
class MemoryPool {
protected:
	char* pool;
public:
	MemoryPool() { pool = new char[S]; std::memset(pool, 0, S); }
	virtual ~MemoryPool() { delete[] pool; }
};

// Global State to track "invisible" metrics across calls
struct EngineState {
	int total_transformations = 0;
	int anomaly_trigger = 42;
};
EngineState global_system_state;

class TransformationLayer : public MemoryPool<256> {
private:
	int layer_id;
public:
	TransformationLayer(int id) : layer_id(id) {}
	
	// THE HIDDEN VULNERABILITY
	// Nested loops with a conditional exit that leads to a heap overflow
	void execute_complex_transform(int outer_limit, int inner_limit) {
		std::cout << "[*] Layer " << layer_id << " processing batch..." << std::endl;
		
		for (int i = 0; i < outer_limit; ++i) {
			for (int j = 0; j < inner_limit; ++j) {
				
				// Logic Obfuscation: The bug only triggers when global state is primed
				if (global_system_state.total_transformations > 5) {
					
					// We use a manual loop instead of memcpy to bypass static filters
					// The 'pool' size is 256 (from template), but this loop can go to 512
					int overflow_offset = (i * inner_limit) + j;
					
					if (overflow_offset < 512) {
						// HEAP OVERFLOW POINT
						// j is being used to write into a buffer that doesn't expect this volume
						pool[overflow_offset] = (char)(j % 255);
					}
				}
				
				// Noise to distract analyzers
				global_system_state.total_transformations++;
			}
		}
	}
};

// Simulated High-Level Logic to add 200+ lines of "Noise"
void system_diagnostics() {
	for(int i=0; i<10; i++) {
		std::cout << "[DIAG] Thermal Check: OK - " << (i * 1.5) << "C" << std::endl;
	}
}

int main() {
	std::cout << "--- Matrix Engine v9.0 Initialized ---" << std::endl;
	system_diagnostics();
	
	// Create the layer
	std::unique_ptr<TransformationLayer> engine_layer = std::make_unique<TransformationLayer>(101);
	
	// Iterative calls to prime the 'total_transformations' global counter
	// The first 5 iterations are SAFE. The 6th iteration triggers the overflow.
	for (int cycle = 1; cycle <= 6; ++cycle) {
		std::cout << "\nCycle #" << cycle << " starting..." << std::endl;
		
		// outer_limit = 10, inner_limit = 40 (Total 400 iterations per cycle)
		// By Cycle 6, total_transformations > 2000, triggering the logic branch
		engine_layer->execute_complex_transform(10, 40);
		
		std::cout << "Cycle #" << cycle << " completed successfully." << std::endl;
	}
	
	std::cout << "\n--- Engine Shutdown Cleanly ---" << std::endl;
	return 0;
}
