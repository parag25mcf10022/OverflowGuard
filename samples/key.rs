fn main() {
	let payload = "A".repeat(100);
	process_secure_key(&payload);
}

fn process_secure_key(input: &str) {
	let mut buffer: [u8; 16] = [0; 16];
	
	// OBFUSCATION: Hiding the overflow behind raw pointer 
	// manipulation inside an 'unsafe' block.
	// Vulnerability: MEDIUM/HIGH (CWE-789)
	unsafe {
		let src = input.as_ptr();
		let dst = buffer.as_mut_ptr();
		
		println!("[*] Copying secret key to hardware buffer...");
		// Manual copy without bounds checking
		std::ptr::copy_nonoverlapping(src, dst, input.len());
	}
}
