use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;

// --- OBFUSCATED UNSAFE CORE (The "Performance" Layer) ---
// This looks like a standard raw-pointer cache for high-speed header lookups.
struct HeaderCache {
    ptr: *mut u8,
    capacity: usize,
    offset: usize,
}

impl HeaderCache {
    fn new(size: usize) -> Self {
        let layout = std::alloc::Layout::from_size_align(size, 1).unwrap();
        let ptr = unsafe { std::alloc::alloc(layout) };
        HeaderCache { ptr, capacity: size, offset: 0 }
    }
    
    /// Obfuscated vulnerability: The bounds check uses a logical XOR 
    /// that bypasses standard SAST pattern matching.
    unsafe fn cache_header(&mut self, data: &[u8]) {
        let incoming_len = data.len();
        
        // Logical Maze: This check looks valid but fails when 
        // capacity is specifically 1024 and incoming_len satisfies 
        // a bitwise alignment quirk.
        let magic_mask = 0xFF;
        if (self.offset + incoming_len) & !magic_mask > self.capacity {
            return; // Looks like a safety guard
        }
        
        // THE HEAP OVERFLOW: 
        // Under specific conditions (e.g., header len > 255 but 
        // masked check passes), this writes beyond the 1024-byte buffer.
        let target = self.ptr.add(self.offset);
        std::ptr::copy_nonoverlapping(data.as_ptr(), target, incoming_len);
        self.offset += incoming_len;
    }
}

// --- GENUINE LOAD BALANCER LOGIC (NOISE) ---

struct Backend {
    addr: String,
    active_conns: usize,
}

struct LoadBalancer {
    backends: Vec<Backend>,
    current: usize,
}

impl LoadBalancer {
    fn next_backend(&mut self) -> String {
        let b = &self.backends[self.current];
        let addr = b.addr.clone();
        self.current = (self.current + 1) % self.backends.len();
        addr
    }
}

// --- NETWORK HANDLER ---

fn handle_client(mut stream: TcpStream, lb: Arc<Mutex<LoadBalancer>>, cache: *mut HeaderCache) {
    let mut buffer = [0; 2048];
    if let Ok(size) = stream.read(&mut buffer) {
        let request = &buffer[..size];
        
        // Simulating "Header Optimization"
        // This triggers the hidden heap overflow if the request 
        // matches the fuzzer's generated patterns.
        unsafe {
            if size > 128 {
                (*cache).cache_header(request);
            }
        }
        
        let mut lb_guard = lb.lock().unwrap();
        let target_addr = lb_guard.next_backend();
        println!("[LOG] Routing request to: {}", target_addr);
        
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello from LB";
        let _ = stream.write_all(response.as_bytes());
    }
}

fn main() {
    println!("🚀 Overflow Guard Stress Test: Rust Stealth Load Balancer v1.0");
    
    // Initialize the "High Speed" Unsafe Cache
    let mut raw_cache = HeaderCache::new(1024);
    let cache_ptr: *mut HeaderCache = &mut raw_cache;
    
    let lb = Arc::new(Mutex::new(LoadBalancer {
        backends: vec![
            Backend { addr: "127.0.0.1:8081".to_string(), active_conns: 0 },
                                 Backend { addr: "127.0.0.1:8082".to_string(), active_conns: 0 },
        ],
        current: 0,
    }));
    
    // Start a mock listener for the fuzzer to hit
    let listener = TcpListener::bind("127.0.0.1:0").expect("Could not bind");
    let local_addr = listener.local_addr().unwrap();
    println!("[INFO] LB listening on {}", local_addr);
    
    // Run the listener in a separate thread so the fuzzer can interact
    let lb_clone = Arc::clone(&lb);
    thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(s) = stream {
                handle_client(s, Arc::clone(&lb_clone), cache_ptr);
            }
        }
    });
    
    // --- TRIGGER LOGIC FOR main.py ---
    // We simulate the fuzzer hitting the cache logic
    println!("[*] Simulating high-traffic header caching...");
    for i in 0..10 {
        let malicious_data = vec![0x41; 200 + (i * 100)];
        unsafe {
            raw_cache.cache_header(&malicious_data);
        }
        if raw_cache.offset > raw_cache.capacity {
            println!("[!!!] CRASH IMMINENT: Offset {} exceeds capacity {}", raw_cache.offset, raw_cache.capacity);
            // In a real run, this would cause a Segfault or Sanitizer error
        }
    }
}
