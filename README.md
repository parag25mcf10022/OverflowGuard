# 🛡️ OverflowGuard v7.1

**Lead Researcher:** Parag Bagade  
**GitHub:** [parag25mcf10022/OverflowGuard](https://github.com/parag25mcf10022/OverflowGuard)  
**Status:** Production Ready — v7.1 (Dataflow + Interprocedural Taint + Symbolic + ML Filter + Concolic + LLVM + Build-Integration Edition)

![CI](https://github.com/parag25mcf10022/OverflowGuard/actions/workflows/ci.yml/badge.svg)

---

## 🚀 Overview

**OverflowGuard** is a polyglot security orchestration framework that detects, classifies, and reports memory-corruption and logic vulnerabilities across **C, C++, Python, Go, Rust, and Java** source code.

Unlike surface-level scanners, it combines **ten independent analysis layers** to minimise false positives and maximise detection confidence:

| Layer | Technology | Languages |
|---|---|---|
| 1a — Taint / Dataflow Analysis | `taint_analyzer.py` (zero-dependency) | C/C++, Python, Java, Go, Rust |
| 1b — AST Sink/Source Tracking | libclang (Python) + regex fallback | C, C++ |
| 1c — Deep Pattern Analysis | `deep_analyzer.py` | C/C++ |
| 1d — SSA-style Dataflow | `dataflow.py` (def-use chains) | C/C++, Python |
| 1e — Call Graph Summaries | `call_summary.py` | C/C++, Python |
| 1f — Symbolic Range Checks | `symbolic_check.py` (Z3 / fallback) | C/C++, Python |
| 1g — Interprocedural Taint | `interprocedural_taint.py` | C/C++, Python |
| 1h — Concurrency Races | `concurrency_analyzer.py` | C/C++, Go |
| 2a — External SAST | cppcheck + clang-tidy + semgrep + Infer + LLVM (`llvm_analyzer.py`) | C/C++, Python, Java |
| 2b — Concolic Fuzzing | `concolic_fuzzer.py` (angr + AFL++ + ASAN) | C/C++ |

All findings are deduplicated, tagged with **HIGH / MEDIUM / LOW confidence**, mapped to real CVEs / CWEs / CVSS v3.1 scores, and rendered in a professional HTML dashboard.

---

## ✨ Features

- **Multi-language taint analysis** (`taint_analyzer.py`) — zero external dependency dataflow engine with 60+ rules across C/C++ (double-free, off-by-one, integer overflow in alloc sizes, NULL-unchecked malloc, path traversal, weak-RNG), Python (SQL injection, SSRF, template injection, JWT none-alg, XSS, insecure deserialisation), Java (LDAP injection, SpEL injection, open redirect, XXE), Go (insecure TLS, race condition, resource leak), and Rust (unsafe block, `mem::transmute`, panic-unwrap)
- **AST-based sink/source tracking** — libclang walks the parse tree to find dangerous calls (`strcpy`, `gets`, `sprintf`, `strncat`, `tmpnam`, `system`, `popen`), heap vs. stack classification, double-free detection, and off-by-one loop analysis
- **SSA-style def-use dataflow** (`dataflow.py`) — builds definition-use chains, propagates taint through assignments and function returns, catches second-order flows missed by single-pass taint
- **Interprocedural taint** (`interprocedural_taint.py`) — follows taint across function boundaries using call-graph summaries built by `call_summary.py`; catches multi-hop injection paths
- **Symbolic range checking** (`symbolic_check.py`) — uses Z3 SMT solver (optional; falls back to interval arithmetic) to prove or refute off-by-one and integer-overflow conditions
- **Concurrency analysis** (`concurrency_analyzer.py`) — detects data races, lock-order inversions, and missing mutex guards in C/C++ and Go
- **LLVM IR analysis** (`llvm_analyzer.py`) — compiles to LLVM IR (`clang -emit-llvm`) and inspects IR for unsafe intrinsics, unreachable code patterns, and integer wrap in arithmetic
- **Concolic fuzzer** (`concolic_fuzzer.py`) — three-tier approach: angr symbolic execution → AFL++ mutation → ASAN-instrumented brute-force; `classify_crash()` maps signals and ASAN reports to specific CWEs
- **ML false-positive filter** (`ml_filter.py`) — optional RandomForest classifier (scikit-learn) trained on historical findings; silently falls back to heuristic scoring when sklearn is absent; model files are only auto-loaded from `~/.overflowguard` (safe path)
- **Persistent scan cache** (`cache_manager.py`) — SHA-256 content-addressed SQLite cache skips unchanged files, cutting re-scan time by up to 90% on large codebases
- **Build-system integration** (`build_integration.py`) — auto-detects Makefile / CMake / Cargo / Gradle and runs the project's own build with ASAN/UBSan flags injected; uses `bear` to capture compilation database for clang-tidy
- **cppcheck + clang-tidy integration** — 40+ mapped rule IDs covering buffer overflows, UAF, integer issues, insecure APIs, and cert checks
- **Semgrep wrapper** — `run_semgrep()` runs `semgrep --config auto`, maps 26 rule IDs to vulnerability types
- **Facebook Infer wrapper** — `run_infer()` runs Infer on C/Java files, maps 17 bug types including null-dereference and memory leaks
- **Bandit SAST** — 30+ per-test-ID mappings for Python (OS injection, eval, hardcoded secrets, insecure TLS, weak crypto, YAML load, SQL injection)
- **10-category smart fuzzer** (`fuzzer.py`) — buffer overflow, format string, command injection, integer extremes, path traversal, SQL injection, XSS, null/binary, JSON/XML (XXE, prototype pollution), newline flood
- **Smart directory scanning** — `os.walk` prunes `.venv/`, `__pycache__/`, `site-packages/`, `node_modules/`, `.git/`, and build artefact directories so third-party code is never falsely reported
- **Global deduplication** — `(file, issue_type, line)` keyed set prevents the same bug appearing twice regardless of which layer found it
- **42+ entry vulnerability DB** — every entry has a real CVE, accurate CVSS v3.1 base score, correct CWE, detailed description, and remediation guidance
- **Confidence badges** — each finding is tagged HIGH (green) / MEDIUM (amber) / LOW (grey) based on detection certainty
- **Rich terminal scorecard** — per-file table with CRITICAL/HIGH/MED/LOW columns + colour-coded status badges, ending with a total summary banner
- **HTML report** — dark-themed dashboard with severity breakdown, detection-stage bar chart, file summary, and per-finding cards showing severity + confidence badge + CWE/CVE/CVSS + remediation
- **GitHub Actions CI** — 4-job pipeline: pytest, cppcheck, Bandit SAST, full scan with HTML artifact upload
- **Unit test suite** — 24 pytest tests covering AST accuracy, pipeline correctness, deduplication, cppcheck, clang-tidy, edge cases, and robustness

---

## 🗂️ Project Structure

```
OverflowGuard/
├── main.py                      # Entry point, audit pipeline, HTML report, scorecard (v7.1)
├── taint_analyzer.py            # Multi-language taint/dataflow engine
├── ast_analyzer.py              # libclang AST walker + regex fallback
├── static_tools.py              # cppcheck, clang-tidy, semgrep & Infer integration
├── deep_analyzer.py             # Deep pattern + heuristic analysis
├── fuzzer.py                    # Standalone universal input fuzzer (10 payload categories)
├── vulnerability_db.py          # 42+ entry CVE/CWE/CVSS intelligence database
│
├── # ── v7.0 advanced analysis modules ────────────────────────────────
├── dataflow.py                  # SSA-style def-use chain dataflow analysis
├── call_summary.py              # Call graph builder + per-function taint summaries
├── symbolic_check.py            # Symbolic range / bounds checking (Z3 + fallback)
├── interprocedural_taint.py     # Cross-function taint propagation
├── build_integration.py         # Build-system detection + ASAN/UBSan injection
├── cache_manager.py             # SHA-256 content-addressed SQLite scan cache
├── concurrency_analyzer.py      # Data-race and lock-order inversion detection
├── ml_filter.py                 # Optional RandomForest ML false-positive filter
├── llvm_analyzer.py             # LLVM IR emission and analysis
├── concolic_fuzzer.py           # Concolic fuzzer (angr → AFL++ → ASAN)
│
├── setup.sh                     # One-shot environment bootstrap
├── requirements.txt             # Python dependencies
├── .env.example                 # Environment variable template
├── .github/
│   └── workflows/
│       └── ci.yml               # GitHub Actions CI (4 jobs)
├── tests/
│   └── test_audit.py            # 24-test pytest suite
├── samples/                     # Intentionally vulnerable sample files
│   ├── stack_overflow.c
│   ├── heap_overflow.c
│   ├── use_after.c
│   ├── sample.c / sample2.c / saft.c / logic-flaw.c
│   ├── test.cpp / test2.cpp / logic.cpp
│   ├── engine.rs / key.rs
│   ├── loader.java
│   ├── race.go
│   └── vault.py
└── results/                     # Generated HTML reports (git-ignored)
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

Or run the all-in-one bootstrap (installs system deps + venv + semgrep):

```bash
chmod +x setup.sh && ./setup.sh
```

### 4. Optional: Facebook Infer

```bash
# Infer provides deep C/Java null-dereference and memory-leak analysis.
# Install from: https://fbinfer.com/docs/getting-started
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
# Enter binary/script path, choose payload mode (1=args, 2=stdin, 3=both)
```

### Run the test suite

```bash
python3 -m pytest tests/ -v
```

---

## 📊 Example Terminal Output

```
══════════════════════════════════════════════════════════════════════════════
         📊  OVERFLOW GUARD — FINAL AUDIT SCORECARD  (v7.1)
══════════════════════════════════════════════════════════════════════════════
FILE                              FINDS        CRIT      HIGH       MED       LOW  STATUS
──────────────────────────────────────────────────────────────────────────────
stack_overflow.c                      3           2         —         —         —  ⚠  VULNERABLE
use_after.c                           6           1         2         —         —  ⚠  VULNERABLE
heap_overflow.c                       4           2         1         —         —  ⚠  VULNERABLE
sample2.c                            15           2         6         —         —  ⚠  VULNERABLE
vault.py                              4           4         —         —         —  ⚠  VULNERABLE
loader.java                           1           1         —         —         —  ⚠  VULNERABLE
race.go                               1           —         1         —         —  ⚠  VULNERABLE
engine.rs                             1           —         —         1         —  ⚠  VULNERABLE
──────────────────────────────────────────────────────────────────────────────
TOTAL                                92          19        19        13         4
══════════════════════════════════════════════════════════════════════════════

  Files scanned   : 15
  Vulnerable      : 15
  Safe            : 0
  Total findings  : 92  (CRIT:19  HIGH:19  MED:13  LOW:4)
══════════════════════════════════════════════════════════════════════════════
```

---

## 🎯 Confidence Levels

Each finding in the HTML report displays a colour-coded confidence badge:

| Badge | Colour | Meaning |
|---|---|---|
| **HIGH** | 🟢 Green | High-certainty detection (direct sink match, taint path confirmed) |
| **MEDIUM** | 🟡 Amber | Probable vulnerability (pattern match, partial taint path) |
| **LOW** | ⚫ Grey | Low-certainty signal (heuristic, needs manual review) |

---

## 🔬 Detection Capabilities

| Vulnerability Class | CWE | Languages | Detection Method |
|---|---|---|---|
| Stack Buffer Overflow | CWE-121 | C/C++ | AST + Taint + cppcheck + fuzzer |
| Heap Buffer Overflow | CWE-122 | C/C++ | AST + Taint + cppcheck + ASAN |
| Use-After-Free | CWE-416 | C/C++ | AST + Taint + cppcheck |
| Double-Free | CWE-415 | C/C++ | Taint + AST |
| Off-By-One | CWE-193 | C/C++ | Taint + AST |
| Integer Overflow / Truncation | CWE-190/197 | C/C++ | Taint + cppcheck + UBSan |
| Format String | CWE-134 | C/C++ | AST + clang-tidy |
| Null Pointer Deref | CWE-476 | C/C++ | cppcheck + Clang SA + Infer |
| Memory Leak | CWE-401 | C/C++ | cppcheck + Infer |
| Insecure Temp File | CWE-377 | C/C++ | AST (`tmpnam`/`mktemp`) |
| Weak RNG | CWE-338 | C/C++, Python, Java, Go | Taint + Bandit |
| Weak Crypto | CWE-327 | C/C++, Python, Java, Go | Taint + Bandit + semgrep |
| SQL Injection | CWE-89 | Python, Java, Go | Taint + Bandit |
| OS Command Injection | CWE-78 | Python, Java, Go, Rust | Taint + Bandit + fuzzer |
| Path Traversal | CWE-22 | C/C++, Python, Java | Taint |
| SSRF | CWE-918 | Python, Go | Taint |
| Template Injection | CWE-94 | Python, Java | Taint |
| XSS | CWE-79 | Python | Taint |
| Open Redirect | CWE-601 | Python, Java, Go | Taint |
| LDAP Injection | CWE-90 | Java | Taint |
| XXE Injection | CWE-611 | Python, Java | Taint |
| JWT None-Alg | CWE-347 | Python | Taint |
| Insecure Deserialization | CWE-502 | Python, Java | Taint + Bandit |
| Hardcoded Password | CWE-259 | Python, Java, Go, Rust | Taint + Bandit |
| Insecure TLS | CWE-295 | Python, Go | Taint + Bandit |
| Insecure Config | CWE-16 | Python | Taint |
| Resource Leak | CWE-772 | Go | Taint |
| Unsafe Block / Transmute | CWE-119 | Rust | Taint + static |
| Panic / Unwrap | CWE-248 | Rust | Taint |
| Race Condition | CWE-362 | Go | Go race detector + Taint |
| Insecure Eval | CWE-95 | Python | Bandit |

---

## 📋 Requirements

### Python packages

```
# Core
colorama>=0.4.6
libclang>=18.1.1
bandit>=1.7.0
pytest>=7.0
semgrep>=1.60.0
requests==2.31.0
click==8.1.7
flawfinder==2.0.19

# Optional — advanced analysis (gracefully skipped when absent)
z3-solver>=4.12.0        # symbolic_check.py: SMT-based range / overflow proofs
scikit-learn>=1.3.0      # ml_filter.py: ML false-positive filter
angr>=9.2                # concolic_fuzzer.py: symbolic execution (heavy ~1 GB)
```

### System tools

| Tool | Purpose | Install |
|---|---|---|
| `gcc` / `g++` | Compile with ASAN/UBSan | `apt install gcc g++` |
| `cppcheck` | Static analysis (XML) | `apt install cppcheck` |
| `clang-tidy` | Clang static analyser | `apt install clang-tidy` |
| `clang` / `llvm` | LLVM IR emission (`llvm_analyzer.py`) | `apt install clang llvm` |
| `afl++` | Mutation fuzzing tier (`concolic_fuzzer.py`) | `apt install afl++` |
| `bear` | Compilation DB for clang-tidy (`build_integration.py`) | `apt install bear` |
| `semgrep` | Multi-language SAST patterns | `pip install semgrep` |
| `infer` | Facebook deep C/Java analysis | [fbinfer.com](https://fbinfer.com) |
| `go` | Go race detector | `apt install golang-go` |
| `rustc` | Rust keyword/taint scan | `apt install rustc` |
| `java` | Java static pattern checks | `apt install openjdk-17-jdk` |
| `bandit` | Python SAST | `pip install bandit` |

---

## 🔄 CI/CD

The repository ships with a **GitHub Actions** workflow (`.github/workflows/ci.yml`) that runs on every push to `main` or `feature/**`:

| Job | Steps |
|---|---|
| `test` | Install deps, run `pytest tests/test_audit.py -v` |
| `static-analysis` | Run cppcheck on `samples/`, upload result artifact |
| `bandit` | Run `bandit -r .`, upload result artifact |
| `full-scan` | Run `python main.py` on `samples/`, upload HTML report artifact |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Add tests in `tests/test_audit.py` for any new detection logic
4. Run `python -m pytest tests/ -v` — all 24 tests must pass
5. Open a Pull Request

> **Note:** When scanning a directory, OverflowGuard automatically skips `.venv/`, `__pycache__/`, `site-packages/`, `node_modules/`, `.git/`, and build artefact folders, so you will never see false positives from third-party packages.
















## �📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## ⚠️ Disclaimer

This tool is intended for **authorized security research and educational purposes only**.  
The sample files in `samples/` are intentionally vulnerable — do not deploy them.  
The authors are not responsible for any misuse of this software.
