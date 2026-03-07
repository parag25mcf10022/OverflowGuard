import subprocess
import random
import string
import sys
import os
from colorama import init, Fore

init(autoreset=True)

class UniversalFuzzer:
    def __init__(self, target_cmd):
        self.target_cmd = target_cmd  # e.g., ["python3", "vault.py"] or ["./temp_bin"]
        self.iteration = 0

    def generate_mutated_input(self):
        """Generates various types of malicious strings."""
        choice = random.randint(1, 5)
        
        if choice == 1: # Massive Buffer
            return "A" * random.randint(100, 5000)
        
        if choice == 2: # Format String Attack
            return "%x %s %p %n" * 10
        
        if choice == 3: # Command Injection attempt
            return "; whoami; cat /etc/passwd; " + "B" * 50
        
        if choice == 4: # Integer Extremes
            return str(random.choice([2147483647, -2147483648, 0, 4294967295]))
            
        if choice == 5: # Null bytes and binary junk
            return "\x00\xff\x41\x00" * 20

    def run(self, iterations=50, mode="arg"):
        """
        mode='arg': Pass as command line argument
        mode='stdin': Pass via standard input
        """
        print(f"{Fore.CYAN}🚀 Starting Fuzzing Campaign on: {' '.join(self.target_cmd)}")
        print(f"{Fore.CYAN}Mode: {mode.upper()} | Iterations: {iterations}")
        
        crashes = 0
        for i in range(iterations):
            payload = self.generate_mutated_input()
            
            try:
                if mode == "arg":
                    # Pass payload as an argument: program.exe <payload>
                    process = subprocess.run(self.target_cmd + [payload], capture_output=True, text=False, timeout=2)
                else:
                    # Pass payload via stdin: echo <payload> | program.exe
                    process = subprocess.run(self.target_cmd, input=payload.encode(), capture_output=True, timeout=2)

                # Check for crashes (Non-zero exit codes or Sanitizer signals)
                if process.returncode != 0:
                    print(f"{Fore.RED}[!] CRASH DETECTED at iteration {i+1}")
                    print(f"{Fore.YELLOW}Payload used: {payload[:50]}...")
                    crashes += 1
                    
            except subprocess.TimeoutExpired:
                print(f"{Fore.BLUE}[i] Iteration {i+1}: Program Hang (Potential DoS)")
            except Exception as e:
                print(f"{Fore.RED}Error: {e}")

        print(f"\n{Fore.GREEN}🏁 Fuzzing Complete. Total Crashes Found: {crashes}")

if __name__ == "__main__":
    print(f"{Fore.MAGENTA}🛡️  UNIVERSAL INPUT FUZZER v1.0")
    
    target = input("Enter execution command (e.g., 'python3 vault.py' or './temp_bin'): ").split()
    if not target:
        sys.exit()
        
    fuzz_mode = input("Pass input via (1) Arguments or (2) Stdin? [1/2]: ")
    mode = "arg" if fuzz_mode == "1" else "stdin"
    
    fuzzer = UniversalFuzzer(target)
    fuzzer.run(iterations=30, mode=mode)
