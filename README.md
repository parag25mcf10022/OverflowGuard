# 🛡️ OverflowGuard v6.0

**Lead Researcher:** Parag Bagade  
**GitHub:** [parag25mcf10022/OverflowGuard](https://github.com/parag25mcf10022/OverflowGuard)  
**Status:** Production Ready — v6.0 (AST + cppcheck + clang-tidy Edition)

---

## 🚀 Overview

**OverflowGuard** is a polyglot security orchestration framework that detects, classifies, and reports memory-corruption and logic vulnerabilities across C, C++, Python, Go, Rust, and Java source code.

Unlike surface-level scanners, it combines **four independent analysis layers** to minimize false positives and maximize detection confidence:

| Layer | Technology | Languages |
|---|---|---|
| 1 — AST Sink/Source Tracking | libclang (Python) + regex fallback | C, C++ |
| 2 — External Static Analysis | cppcheck + clang-tidy | C, C++ |
| 3 — SAST | Bandit | Python |
| 4 — Dynamic Fuzzing | AddressSanitizer + mutational fuzzer | C, C++, Python, Go |

All findings are deduplicated, mapped to real CVEs/CWEs/CVSS v3.1 scores, and rendered in a professional HTML dashboard.

---

## ✨ Features

- **AST-based sink/source tracking** — libclang walks the parse tree to find dangerous calls (`strcpy`, `gets`, `sprintf`, `printf` with variable format), heap vs. stack classification by tracing `malloc`/`calloc` assignments, and pointer use-after-free detection
- **cppcheck integration** — catches out-of-bounds access, use-after-free, integer overflow, null-pointer dereference, division-by-zero, memory leaks, and more via XML parsing
- **clang-tidy integration** — runs `clang-analyzer-security.*`, `clang-analyzer-core.*`, `bugprone-*`, and `cert-*` checks
- **Bandit SAST** — per-test-ID mapping for Python (OS injection, eval, hardcoded secrets, unsafe temp files, insecure deserialization)
- **Mutational fuzzer** — 5 payload classes (buffer overflow, format string, command injection, integer wrap, null-byte injection) via both argument and stdin channels; ASAN crash messages parsed for precise classification
- **Global deduplication** — `(file, issue_type, line)` keyed set prevents the same bug appearing twice regardless of which layer found it
- **27-entry vulnerability DB** — every entry has a real CVE, accurate CVSS v3.1 base score, correct CWE, detailed description, and remediation
- **Rich terminal scorecard** — per-file table with CRITICAL/HIGH/MED/LOW columns + colour-coded status badges, ending with a total summary banner
- **HTML report** — dark-themed dashboard with severity bar charts, detection-stage breakdown, file summary table, and detailed finding cards
- **Unit test suite** — 24 pytest tests covering AST accuracy, pipeline correctness, deduplication, cppcheck, clang-tidy, edge cases, and robustness

---

## 🗂️ Project Structure

```
OverflowGuard/
├── main.py               # Entry point, audit pipeline, HTML report, scorecard
├── ast_analyzer.py       # libclang AST walker + regex fallback
├── static_tools.py       # cppcheck & clang-tidy integration
├── fuzzer.py             # Standalone universal input fuzzer
├── vulnerability_db.py   # 27-entry CVE/CWE/CVSS intelligence database
├── setup.sh              # One-shot environment bootstrap
├── requirements.txt      # Python dependencies
├── .env.example          # Environment variable template
├── tests/
│   └── test_audit.py     # 24-test pytest suite
├── samples/              # Intentionally vulnerable sample files
│   ├── stack_overflow.c
│   ├── heap_overflow.c
│   ├── use_after.c
│   ├── logic-flaw.c
│   ├── engine.rs
│   ├── loader.java
│   ├── race.go
│   ├── vault.py
│   └── ...
└── results/              # Generated HTML reports (git-ignored)
```

---

## 🛠️ Installation

> Tested on **Parrot OS**, **Kali Linux**, and **Ubuntu 22.04+**.

### 1. Clone

```bash
git clone https://github.com/parag25mcf10022/OverflowGuard.git
cd OverflowGuard
```

### 2. System dependencies

```bash
sudo apt update
sudo apt install -y \
    gcc g++ \
    cppcheck clang-tidy \
    golang-go \
    rustc cargo \
    openjdk-17-jdk \
    python3-pip python3-venv
```

### 3. Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Or run the all-in-one bootstrap:

```bash
chmod +x setup.sh && ./setup.sh
```

---

## ▶️ Usage

### Scan a single file

```bash
source .venv/bin/activate
python3 main.py
# When prompted: Enter Path/File: samples/stack_overflow.c
```

### Scan an entire directory

```bash
python3 main.py
# When prompted: Enter Path/File: samples
```

### Run the standalone fuzzer

```bash
python3 fuzzer.py
# Enter command, e.g.: ./my_binary
# Choose argument or stdin mode
```

### Run the test suite

```bash
python3 -m pytest tests/ -v
```

---

## 📊 Example Terminal Output

```
══════════════════════════════════════════════════════════════════════════════
         📊  OVERFLOW GUARD — FINAL AUDIT SCORECARD  (v5.3)
══════════════════════════════════════════════════════════════════════════════
FILE                              FINDS        CRIT      HIGH       MED       LOW  STATUS
──────────────────────────────────────────────────────────────────────────────
stack_overflow.c                      3           2         —         —         —  ⚠  VULNERABLE
use_after.c                           6           1         2         —         —  ⚠  VULNERABLE
heap_overflow.c                       4           2         1         —         —  ⚠  VULNERABLE
vault.py                              4           4         —         —         —  ⚠  VULNERABLE
loader.java                           1           1         —         —         —  ⚠  VULNERABLE
engine.rs                             1           —         —         1         —  ⚠  VULNERABLE
──────────────────────────────────────────────────────────────────────────────
TOTAL                                71          19        14         2         —
══════════════════════════════════════════════════════════════════════════════

  Files scanned   : 15
  Vulnerable      : 15
  Safe            : 0
  Total findings  : 71  (CRIT:19  HIGH:14  MED:2  LOW:0)
══════════════════════════════════════════════════════════════════════════════
```

---

## 🔬 Detection Capabilities

| Vulnerability Class | CWE | Languages | Detection Method |
|---|---|---|---|
| Stack Buffer Overflow | CWE-121 | C/C++ | AST + cppcheck + fuzzer |
| Heap Buffer Overflow | CWE-122 | C/C++ | AST + cppcheck + ASAN |
| Use-After-Free | CWE-416 | C/C++ | AST + cppcheck |
| Format String | CWE-134 | C/C++ | AST + clang-tidy |
| Integer Overflow | CWE-190 | C/C++ | cppcheck + UBSan |
| Null Pointer Deref | CWE-476 | C/C++ | cppcheck + Clang SA |
| Division by Zero | CWE-369 | C/C++ | cppcheck |
| Memory Leak | CWE-401 | C/C++ | cppcheck |
| OS Command Injection | CWE-78 | Python | Bandit + fuzzer |
| Insecure Eval | CWE-95 | Python | Bandit |
| Hardcoded Password | CWE-259 | Python | Bandit |
| Race Condition | CWE-362 | Go | Go race detector |
| Unsafe Block | CWE-119 | Rust | Static keyword scan |
| Insecure Deserialization | CWE-502 | Java | Static pattern |

---

## 📋 Requirements

### Python packages
```
colorama>=0.4.6
libclang>=18.1.1
bandit>=1.7.0
pytest>=7.0
```

### System tools
| Tool | Purpose | Install |
|---|---|---|
| `gcc` / `g++` | Compile with ASAN/UBSan | `apt install gcc g++` |
| `cppcheck` | Static analysis (XML) | `apt install cppcheck` |
| `clang-tidy` | Clang static analyzer | `apt install clang-tidy` |
| `go` | Go race detector | `apt install golang-go` |
| `rustc` | Rust keyword scan | `apt install rustc` |
| `java` | Java deserialization check | `apt install openjdk-17-jdk` |
| `bandit` | Python SAST | `pip install bandit` |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Add tests in `tests/test_audit.py` for any new detection logic
4. Run `python -m pytest tests/ -v` — all tests must pass
5. Open a Pull Request

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## ⚠️ Disclaimer

This tool is intended for **authorized security research and educational purposes only**.  
The sample files in `samples/` are intentionally vulnerable — do not deploy them.  
The authors are not responsible for any misuse of this software.
