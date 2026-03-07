"""
fuzzer.py — Universal Mutation Fuzzer (OverflowGuard v6.0)

Provides both a standalone CLI and an importable UniversalFuzzer class
used by main.py's dynamic analysis stage.

Improvements over v1.0:
  • 10 payload categories covering buffer overflow, format string, integer
    extremes, command injection, path traversal, SQL injection, XSS,
    JSON/XML fuzzing, null-byte sequences, and large numeric inputs.
  • ASAN/crash classification from stderr.
  • Per-iteration output with crash type labeling.
  • Optional stdin + argument dual-mode per iteration.
"""

import subprocess
import random
import string
import sys
import os
from colorama import init, Fore, Style

init(autoreset=True)


# ---------------------------------------------------------------------------
# Payload generators
# ---------------------------------------------------------------------------

def _buffer_overflow():
    size = random.choice([128, 256, 512, 1024, 2048, 4096, 65536])
    return "A" * size

def _format_string():
    tokens = ["%x", "%s", "%p", "%n", "%08x", "%.1000d", "%hn", "%%"]
    return " ".join(random.choices(tokens, k=random.randint(8, 20)))

def _command_injection():
    payloads = [
        "'; whoami; cat /etc/passwd; '",
        '"; id; "',
        "`id`",
        "$(cat /etc/passwd)",
        "| cat /etc/shadow",
        "&& cat /etc/passwd &&",
        "\n/bin/sh\n",
        "; ls -la /",
        "' OR '1'='1",
    ]
    return random.choice(payloads)

def _integer_extremes():
    values = [
        str(2**31 - 1),        # INT32_MAX
        str(2**31),            # INT32 overflow
        str(-2**31),           # INT32_MIN
        str(2**32 - 1),        # UINT32_MAX
        str(2**32),            # UINT32 overflow
        str(2**63 - 1),        # INT64_MAX
        str(-1),               # All-ones as unsigned
        str(0),                # Zero — div-by-zero probe
        str(2**16 - 1),        # UINT16_MAX
        str(2**16),            # UINT16 overflow
        str(-2**63),           # INT64_MIN
    ]
    return random.choice(values)

def _path_traversal():
    payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "%2e%2e%2f" * 4 + "etc/passwd",
        "....//....//....//etc/passwd",
        "/etc/passwd\x00",
        "file:///etc/passwd",
        "../../proc/self/cmdline",
    ]
    return random.choice(payloads)

def _sql_injection():
    payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users;--",
        "1; SELECT * FROM information_schema.tables",
        "' UNION SELECT 1,2,3--",
        "admin'--",
        "\" OR \"\"=\"",
        "1' ORDER BY 100--",
        "'/**/OR/**/1=1--",
    ]
    return random.choice(payloads)

def _xss():
    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "'><svg/onload=alert(1)>",
        "\"onmouseover=\"alert(1)\"",
        "<iframe src='javascript:alert(1)'>",
        "{{7*7}}",               # Template injection probe
        "${7*7}",                # EL injection probe
    ]
    return random.choice(payloads)

def _null_binary():
    return "".join(random.choices(
        ["\x00", "\xff", "\x41", "\xfe", "\x7f", "\x80", "\x01"],
        k=random.randint(20, 200)))

def _json_xml_fuzz():
    payloads = [
        '{"__proto__": {"admin": true}}',
        '{"key": "' + "A" * 10000 + '"}',
        '[]' * 1000,
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<x>' + '<y>' * 500 + '</y>' * 500 + '</x>',
        'null',
        'undefined',
        'NaN',
        'Infinity',
        '-Infinity',
    ]
    return random.choice(payloads)

def _newline_flood():
    return ("\n" + "A" * 64) * random.randint(100, 1000)

PAYLOAD_GENERATORS = [
    _buffer_overflow,
    _format_string,
    _command_injection,
    _integer_extremes,
    _path_traversal,
    _sql_injection,
    _xss,
    _null_binary,
    _json_xml_fuzz,
    _newline_flood,
]


# ---------------------------------------------------------------------------
# Crash classifier
# ---------------------------------------------------------------------------

def classify_crash(returncode: int, stderr_text: str) -> str:
    """Return a VULN_DATA key based on crash signals in stderr."""
    s = stderr_text.lower()
    if "stack-buffer-overflow" in s or "stack buffer overflow" in s:
        return "stack-buffer-overflow"
    if "heap-buffer-overflow" in s or "heap buffer overflow" in s:
        return "heap-buffer-overflow"
    if "use-after-free" in s or "heap-use-after-free" in s:
        return "use-after-free"
    if "double-free" in s:
        return "double-free"
    if "integer overflow" in s or "ubsan" in s:
        return "integer-overflow"
    if "null dereference" in s or "null pointer" in s:
        return "null-pointer"
    if "format string" in s:
        return "format-string"
    if "addresssanitizer" in s or "asan" in s:
        return "buffer-overflow"
    if returncode in (-11, 139):   # SIGSEGV
        return "buffer-overflow"
    if returncode in (-6, 134):    # SIGABRT
        return "double-free"
    if returncode in (-8, 136):    # SIGFPE
        return "division-by-zero"
    return "buffer-overflow"


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class UniversalFuzzer:
    """Mutational fuzzer for OverflowGuard's dynamic analysis stage."""

    def __init__(self, target_cmd):
        self.target_cmd = target_cmd

    def generate_mutated_input(self) -> str:
        return random.choice(PAYLOAD_GENERATORS)()

    def run(self, iterations: int = 50, mode: str = "both") -> tuple:
        """
        Run the fuzzer.
        mode = 'arg'   — pass payload as CLI argument
        mode = 'stdin' — pass payload on stdin
        mode = 'both'  — try both per iteration (default)

        Returns (crashed: bool, payload: str)
        """
        print(f"{Fore.CYAN}🚀 Starting Fuzzing Campaign on: {' '.join(self.target_cmd)}")
        print(f"{Fore.CYAN}Mode: {mode.upper()} | Iterations: {iterations}")

        for i in range(iterations):
            payload = self.generate_mutated_input()
            try:
                if mode in ("arg", "both"):
                    proc = subprocess.run(
                        self.target_cmd + [payload],
                        capture_output=True, timeout=1.5)
                    stderr = proc.stderr.decode(errors="ignore")
                    if proc.returncode != 0 or "sanitizer" in stderr.lower():
                        crash_type = classify_crash(proc.returncode, stderr)
                        print(f"{Fore.RED}[!!!] CRASH ({crash_type}) at iteration {i+1} "
                              f"(arg mode) payload={payload[:40]!r}")
                        return True, payload

                if mode in ("stdin", "both"):
                    proc2 = subprocess.run(
                        self.target_cmd,
                        input=payload.encode(errors="replace"),
                        capture_output=True, timeout=1.5)
                    stderr2 = proc2.stderr.decode(errors="ignore")
                    if proc2.returncode != 0 or "sanitizer" in stderr2.lower():
                        crash_type = classify_crash(proc2.returncode, stderr2)
                        print(f"{Fore.RED}[!!!] CRASH ({crash_type}) at iteration {i+1} "
                              f"(stdin mode) payload={payload[:40]!r}")
                        return True, payload

            except subprocess.TimeoutExpired:
                print(f"{Fore.BLUE}[i] Iteration {i+1}: Hang detected (possible DoS/infinite loop)")
                return True, payload
            except Exception:
                continue

        print(f"{Fore.GREEN}[+] Fuzzer: No crashes in {iterations} iterations.")
        return False, ""


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"{Fore.MAGENTA}{Style.BRIGHT}🛡️  OVERFLOW GUARD — UNIVERSAL FUZZER v6.0")

    target = input("Enter execution command (e.g. 'python3 vault.py' or './temp_bin'): ").split()
    if not target:
        sys.exit(1)

    mode_choice = input("Pass input via: (1) Arguments  (2) Stdin  (3) Both [default=3]: ").strip()
    mode_map = {"1": "arg", "2": "stdin", "3": "both", "": "both"}
    mode = mode_map.get(mode_choice, "both")

    iters = input("Iterations [default=50]: ").strip()
    iterations = int(iters) if iters.isdigit() else 50

    fuzzer = UniversalFuzzer(target)
    crashed, payload = fuzzer.run(iterations=iterations, mode=mode)

    if crashed:
        print(f"\n{Fore.RED}{Style.BRIGHT}💥 Target CRASHED on: {payload[:80]!r}")
    else:
        print(f"\n{Fore.GREEN}{Style.BRIGHT}✅ Target survived all {iterations} iterations.")

