# 🛡️ OverflowGuard v8.0

**Lead Researcher:** Parag Bagade  
**GitHub:** [parag25mcf10022/OverflowGuard](https://github.com/parag25mcf10022/OverflowGuard)  
**Status:** Production Ready — v8.0 (SAST + SCA + Secrets + SBOM + SARIF — Full Supply-Chain Security Edition)

![CI](https://github.com/parag25mcf10022/OverflowGuard/actions/workflows/ci.yml/badge.svg)

---

## 🚀 Overview

**OverflowGuard** is a polyglot security orchestration framework that detects, classifies, and reports memory-corruption and logic vulnerabilities across **C, C++, Python, Go, Rust, and Java** source code.

Unlike surface-level scanners, it combines **twelve independent analysis stages** to minimise false positives and maximise detection confidence across both first-party code *and* the software supply chain:

| Stage | Technology | What it covers |
|---|---|---|
| 1a — Taint / Dataflow | `taint_analyzer.py` (zero-dependency) | C/C++, Python, Java, Go, Rust |
| 1b — AST Sink/Source | libclang + regex fallback | C, C++ |
| 1c — Deep Patterns | `deep_analyzer.py` | C/C++ |
| 1d — SSA Dataflow | `dataflow.py` def-use chains | C/C++, Python |
| 1e — Call Summaries | `call_summary.py` | C/C++, Python |
| 1f — Symbolic Ranges | `symbolic_check.py` (Z3 / fallback) | C/C++, Python |
| 1g — Interprocedural | `interprocedural_taint.py` | C/C++, Python |
| 1h — Concurrency | `concurrency_analyzer.py` | C/C++, Go |
| 2a — External SAST | cppcheck + clang-tidy + semgrep + Infer + LLVM | C/C++, Python, Java |
| 2b — Concolic Fuzzing | `concolic_fuzzer.py` (angr → AFL++ → ASAN) | C/C++ |
| **3 — SCA** | **`sca_scanner.py` (OSV API)** | **All manifest formats** |
| **4 — Secrets Scan** | **`secrets_scanner.py` (30+ patterns + entropy)** | **All source + config files** |

Output formats: **HTML dashboard**, **SARIF 2.1.0** (GitHub Code Scanning / Azure DevOps), **CycloneDX 1.4 SBOM**.

---

## ✨ Features

- **SCA — dependency vulnerability scanning** (`sca_scanner.py`) — parses `requirements.txt`, `pyproject.toml`, `Pipfile`, `package.json`, `Cargo.toml`, `go.mod`, `pom.xml`, `build.gradle`; queries the [OSV API](https://osv.dev) (free, no key) for known CVEs; includes fix-version in every finding; auto-remediation messages show the exact safe upgrade path (e.g. *“Upgrade requests 2.27.0 → 2.31.0 to fix CVE-2023-32681”*)
- **License compliance** — detects GPL / LGPL / AGPL / SSPL / EUPL / MPL / CDDL licences in dependencies that could “infect” proprietary code; rated HIGH (GPL/AGPL/SSPL), MEDIUM (LGPL/MPL); remediation guidance included
- **OSS snippet matching** — SHA-256 fingerprints every source file and looks up known open-source code signatures so copyleft code can be detected even without a package manifest
- **Secrets / credentials scanner** (`secrets_scanner.py`) — 30+ regex patterns covering AWS access keys, GitHub tokens (ghp\_/gho\_/ghu\_/ghs\_), Google API keys, Slack tokens + webhooks, Stripe live/test keys, Twilio SIDs, SendGrid/NPM/PyPI API tokens, PEM private keys (RSA/EC/OpenSSH/PGP), JWT tokens, database connection strings, hardcoded password assignments, Azure storage keys, and Basic-Auth-in-URL; backs each pattern hit with Shannon entropy analysis; suppresses test fixtures and placeholder values
- **SBOM generation** (`sbom_generator.py`) — produces a **CycloneDX 1.4 JSON** Software Bill of Materials listing every detected dependency with PURL, version, licence, known CVEs, and recommended fix versions; satisfies the NTIA minimum SBOM requirements and US EO 14028 federal supply-chain mandates
- **SARIF 2.1.0 export** (`sarif_output.py`) — converts all findings (SAST + SCA + secrets) to the industry-standard SARIF format accepted natively by GitHub Code Scanning (free annotation on PR diffs), Azure DevOps, VS Code Problems panel, and every major SIEM/ASPM platform; no competitor integration needed
- **Multi-language taint analysis** (`taint_analyzer.py`) — zero external dependency dataflow engine with 60+ rules across C/C++ (double-free, off-by-one, integer overflow in alloc sizes, NULL-unchecked malloc, path traversal, weak-RNG), Python (SQL injection, SSRF, template injection, JWT none-alg, XSS, insecure deserialisation), Java (LDAP injection, SpEL injection, open redirect, XXE), Go (insecure TLS, race condition, resource leak), and Rust (unsafe block, `mem::transmute`, panic-unwrap)
- **AST-based sink/source tracking** — libclang walks the parse tree to find dangerous calls (`strcpy`, `gets`, `sprintf`, `strncat`, `tmpnam`, `system`, `popen`), heap vs. stack classification, double-free detection, and off-by-one loop analysis
- **SSA-style def-use dataflow** (`dataflow.py`) — builds definition-use chains, propagates taint through assignments and function returns, catches second-order flows missed by single-pass taint
- **Interprocedural taint** (`interprocedural_taint.py`) — follows taint across function boundaries using call-graph summaries; catches multi-hop injection paths
- **Symbolic range checking** (`symbolic_check.py`) — uses Z3 SMT solver (optional; falls back to interval arithmetic) to prove or refute off-by-one and integer-overflow conditions
- **Concurrency analysis** (`concurrency_analyzer.py`) — detects data races, lock-order inversions, and missing mutex guards in C/C++ and Go
- **LLVM IR analysis** (`llvm_analyzer.py`) — compiles to LLVM IR and inspects for unsafe intrinsics and integer wrap
- **Concolic fuzzer** (`concolic_fuzzer.py`) — angr symbolic execution → AFL++ mutation → ASAN-instrumented brute-force
- **ML false-positive filter** (`ml_filter.py`) — optional RandomForest classifier; model files only auto-loaded from `~/.overflowguard`
- **Persistent scan cache** (`cache_manager.py`) — SHA-256 content-addressed SQLite cache; skips unchanged files
- **Build-system integration** (`build_integration.py`) — auto-detects Makefile / CMake / Cargo / Gradle; injects ASAN/UBSan flags
- **Smart directory scanning** — prunes `.venv/`, `__pycache__/`, `site-packages/`, `node_modules/`, `.git/`, build artefact directories
- **42+ entry vulnerability DB** — every entry has a real CVE, CVSS v3.1 score, CWE, description, and remediation
- **Confidence badges** — HIGH (green) / MEDIUM (amber) / LOW (grey) per finding
- **HTML report** — dark-themed dashboard with severity breakdown, detection-stage chart, file summary, and per-finding cards
- **GitHub Actions CI** — 4-job pipeline: pytest, cppcheck, Bandit SAST, full scan + HTML artifact upload
- **Unit test suite** — 24 pytest tests

---



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
z3-solver>=4.12.0        # symbolic_check.py
scikit-learn>=1.3.0      # ml_filter.py
angr>=9.2                # concolic_fuzzer.py  (~1 GB)
```

The SCA, secrets, SBOM, and SARIF modules use only the Python standard library (`urllib`, `hashlib`, `json`, `re`) — **no extra pip packages required** for the new v8.0 features.

### System tools

| Tool | Purpose | Install |
|---|---|---|
| `gcc` / `g++` | Compile with ASAN/UBSan | `apt install gcc g++` |
| `cppcheck` | Static analysis (XML) | `apt install cppcheck` |
| `clang-tidy` | Clang static analyser | `apt install clang-tidy` |
| `clang` / `llvm` | LLVM IR emission | `apt install clang llvm` |
| `afl++` | Mutation fuzzing tier | `apt install afl++` |
| `bear` | Compilation DB for clang-tidy | `apt install bear` |
| `semgrep` | Multi-language SAST patterns | `pip install semgrep` |
| `infer` | Facebook deep C/Java analysis | [fbinfer.com](https://fbinfer.com) |
| `go` | Go race detector | `apt install golang-go` |
| `rustc` | Rust keyword/taint scan | `apt install rustc` |
| `java` | Java static pattern checks | `apt install openjdk-17-jdk` |

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

## 🗓️ Changelog

| Version | Date | Highlights |
|---|---|---|
| **v8.0** | 2026-03-07 | `sca_scanner.py` (OSV API, 7 manifest formats, license compliance, snippet matching); `secrets_scanner.py` (30+ patterns + Shannon entropy); `sbom_generator.py` (CycloneDX 1.4 JSON); `sarif_output.py` (SARIF 2.1.0 — GitHub Code Scanning native); 6-stage pipeline; zero new pip dependencies |
| **v7.1** | 2026-03-07 | Smart directory scanning (skip `.venv/`, `site-packages/`); SQL f-string fix; safer pickle loading |
| **v7.0** | 2026-03 | 10 new advanced-analysis modules; 8-stage pipeline; persistent scan cache; ML false-positive filter |
| **v6.0** | 2026-02 | Multi-language taint (Go, Rust, Java), semgrep, Infer, GitHub Actions CI, HTML dashboard |
| **v5.0** | 2026-01 | Python SAST (Bandit), deep pattern analyser, CVE/CWE/CVSS v3.1 vulnerability DB |

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## ⚠️ Disclaimer

This tool is intended for **authorized security research and educational purposes only**.  
The sample files in `samples/` are intentionally vulnerable — do not deploy them.  
The authors are not responsible for any misuse of this software.

