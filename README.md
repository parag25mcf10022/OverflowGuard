# 🛡️ OverflowGuard v9.0

**Lead Researcher:** Parag Bagade  
**GitHub:** [parag25mcf10022/OverflowGuard](https://github.com/parag25mcf10022/OverflowGuard)  
**Status:** Production Ready — v9.0 (Real AST Parsing + CFG Dataflow + Symbolic Execution + 14 Languages)

![CI](https://github.com/parag25mcf10022/OverflowGuard/actions/workflows/ci.yml/badge.svg)

---

## 🚀 Overview

**OverflowGuard** is a polyglot security orchestration framework that detects, classifies, and reports memory-corruption and logic vulnerabilities across **14 programming languages**: C, C++, Python, Go, Rust, Java, JavaScript, TypeScript, PHP, Ruby, C#, Kotlin, Swift, and Scala.

Unlike surface-level scanners that rely on regex pattern matching, v9.0 introduces **real AST parsing** (tree-sitter), **real dataflow analysis** on Control-Flow Graphs (reaching definitions, taint propagation with gen/kill semantics), **real symbolic execution** (Z3 SMT solver with bitvector arithmetic, path constraints, and counterexample generation), and **context-aware false-positive filtering** (dominator-based sanitizer verification, dead-code elimination, test-code detection).

| Stage | Technology | What it covers |
|---|---|---|
| 0 — Real AST + CFG | `tree_sitter_engine.py` + `cfg_builder.py` | **14 languages** — real syntax-tree analysis |
| 0a — Real Dataflow | `real_dataflow.py` (CFG-based taint) | **14 languages** — source→sink with gen/kill on CFG |
| 0b — Real Symbolic | `real_symbolic.py` (Z3 / interval) | **14 languages** — path-sensitive, counterexamples |
| 0c — FP Filter | `false_positive_filter.py` | **14 languages** — dominator-based guard verification |
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
| 3 — SCA | `sca_scanner.py` (OSV API) | All manifest formats |
| 4 — Secrets Scan | `secrets_scanner.py` (30+ patterns + entropy) | All source + config files |
| **★ GitHub** | **`github_scanner.py` (clone or Contents API)** | **Any public or private GitHub repo** |

Output formats: **HTML dashboard**, **SARIF 2.1.0** (GitHub Code Scanning / Azure DevOps), **CycloneDX 1.4 SBOM**.

---

## ✨ Features

### v9.0 — Real Analysis Engine (Industry-Grade)

- **Real AST parsing** (`tree_sitter_engine.py`) — uses [tree-sitter](https://tree-sitter.github.io/) to build proper syntax trees for **14 languages**: C, C++, Python, Java, Go, Rust, JavaScript, TypeScript, PHP, Ruby, C#, Kotlin, Swift, Scala; replaces regex pattern matching with proper node-type-aware AST traversal; language-specific sink/source/sanitizer databases with 200+ entries; graceful fallback to regex when tree-sitter is not installed
- **Control-Flow Graph builder** (`cfg_builder.py`) — constructs proper basic-block CFGs from tree-sitter ASTs; handles if/else branching, loops (for/while/do), switch/match, try/catch/finally, break/continue, return; computes **dominator trees** (Cooper-Harvey-Kennedy algorithm) for guard verification; supports all 14 languages
- **Real dataflow analysis** (`real_dataflow.py`) — CFG-based taint propagation with proper gen/kill semantics and fixpoint iteration; reaching definitions analysis; source→sink path tracking with complete taint-flow paths; dominator-based sanitizer verification (not ±10-line heuristic); inter-procedural taint via call-graph summaries; double-free and use-after-free detection via AST-based variable tracking; unchecked array access detection
- **Real symbolic execution** (`real_symbolic.py`) — path-sensitive analysis using Z3 SMT solver with 64-bit bitvector arithmetic; path constraint accumulation at branches; infeasible path pruning; buffer overflow proof (memcpy size > alloc size); strcpy unbounded-source proof; integer overflow/wraparound detection; array out-of-bounds proof; **counterexample generation** (Z3 produces concrete inputs that trigger the bug); falls back to interval abstract interpretation when Z3 is absent
- **Context-aware false-positive filter** (`false_positive_filter.py`) — test file/function detection (auto-downgrade findings in test code); dead-code elimination (suppress findings inside `if(0)` / `if False`); **dominator-based sanitizer guard verification** on the CFG; auto-generated code detection; duplicate/subsumption merging; confidence score adjustment

### v8.1 — GitHub Repository Scanning

- **GitHub repository scanning** (`github_scanner.py`) — scan **any GitHub repo directly** by entering a URL (`https://github.com/owner/repo`), SSH URL (`git@github.com:owner/repo.git`), or shorthand (`owner/repo` or `owner/repo@branch`) at the prompt; automatically shallow-clones with `git` (preferred) or falls back to the GitHub Contents API (no git required); fetches repo metadata (stars, forks, language, licence, topics); supports private repos via `GITHUB_TOKEN` env var; cleans up the temp clone automatically after the scan; the entire pipeline runs on the downloaded code unchanged

### v8.0 — Supply-Chain Security
- **SCA — dependency vulnerability scanning** (`sca_scanner.py`) — parses `requirements.txt`, `pyproject.toml`, `Pipfile`, `package.json`, `Cargo.toml`, `go.mod`, `pom.xml`, `build.gradle`; queries the [OSV API](https://osv.dev) for known CVEs; auto-remediation messages show the exact safe upgrade path
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

### Scan a GitHub repository (any public repo or private with token)

```bash
source .venv/bin/activate
python3 main.py
# When prompted: Enter Path/File/GitHub Repo: torvalds/linux
# ...or a full URL:
# Enter Path/File/GitHub Repo: https://github.com/pallets/flask
# ...or a specific branch:
# Enter Path/File/GitHub Repo: pallets/flask@main
```

For **private repos** or to avoid the 60 req/hr unauthenticated rate limit:

```bash
export GITHUB_TOKEN=ghp_your_token_here
python3 main.py
# Enter Path/File/GitHub Repo: your-org/private-repo
```

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
⛔  OVERFLOW GUARD v9.0 | Researcher: Parag Bagade

┌─────────────────────────────────────────────────────────────────┐
│ ANALYZING: sample.c                                               │
└─────────────────────────────────────────────────────────────────┘
[*] v9.0 AST(tree‑sitter) real dataflow / symbolic pass (c)...
[!!!] RealDataflow [High] use-after-free @ line 23
[!!!] RealDataflow [Medium] buffer-overflow @ line 21
[~] Symbolic(Z3) [High] buffer-overflow @ line 13 — Z3 proved: strcpy overflow
[~] Symbolic(interval) [High] buffer-overflow @ line 9 — index > buffer size
[!!!] AST: [HIGH] stack-buffer-overflow @ line 13 — Dangerous call to strcpy()
[!!!] AST: [HIGH] use-after-free @ line 23 — Pointer 'ptr' used after free()
[!] cppcheck: [error] Array 'ptr[10]' accessed at index 49 @ line 21
[!!!] Concolic [HIGH] stack-buffer-overflow @ line 13 — Heuristic fuzzing crash

───  v9.0 Summary  ───
  AST engine           : AST(tree‑sitter)
  Languages supported  : C, C++, Python, Java, Go, Rust, JS, TS, PHP, Ruby, C#
  SCA findings         : 0 CVEs in dependencies
  Secrets detected     : 0
  SBOM components      : 0 dependencies documented
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
| Stack Buffer Overflow | CWE-121 | C/C++ | **AST + CFG dataflow + Z3 symbolic** + cppcheck + fuzzer |
| Heap Buffer Overflow | CWE-122 | C/C++ | **AST + CFG dataflow + Z3 symbolic** + cppcheck + ASAN |
| Use-After-Free | CWE-416 | C/C++ | **AST-based variable tracking** + cppcheck |
| Double-Free | CWE-415 | C/C++ | **AST-based variable tracking** + Taint |
| Off-By-One | CWE-193 | C/C++ | **Z3 symbolic** + Taint + AST |
| Integer Overflow / Truncation | CWE-190/197 | C/C++, **JS, TS, PHP, C#** | **Z3 bitvector wrap-around proof** + UBSan |
| Format String | CWE-134 | C/C++ | AST + clang-tidy |
| Null Pointer Deref | CWE-476 | C/C++ | cppcheck + Clang SA + Infer |
| Memory Leak | CWE-401 | C/C++ | cppcheck + Infer |
| Insecure Eval | CWE-95 | Python, **JS, TS, PHP, Ruby** | **AST + CFG taint** + Bandit |
| OS Command Injection | CWE-78 | Python, Java, Go, Rust, **JS, TS, PHP, Ruby, C#, Kotlin, Swift, Scala** | **AST + CFG taint** + Bandit + fuzzer |
| SQL Injection | CWE-89 | Python, Java, Go, **PHP, Ruby, C#** | **AST + CFG taint** + Bandit |
| XSS | CWE-79 | Python, **JS, TS, PHP** | **AST + CFG taint** |
| Path Traversal | CWE-22 | C/C++, Python, Java, **PHP** | **AST + CFG taint** |
| SSRF | CWE-918 | Python, Go, **PHP** | **AST + CFG taint** |
| Insecure Deserialization | CWE-502 | Python, Java, **PHP, Ruby, C#, Kotlin, Swift, Scala** | **AST + CFG taint** + Bandit |
| Weak RNG | CWE-338 | C/C++, Python, Java, Go | Taint + Bandit |
| Weak Crypto | CWE-327 | C/C++, Python, Java, Go | Taint + Bandit + semgrep |
| Template Injection | CWE-94 | Python, Java | Taint |
| Open Redirect | CWE-601 | Python, Java, Go | Taint |
| LDAP Injection | CWE-90 | Java | Taint |
| XXE Injection | CWE-611 | Python, Java | Taint |
| JWT None-Alg | CWE-347 | Python | Taint |
| Hardcoded Password | CWE-259 | Python, Java, Go, Rust | Taint + Bandit |
| Insecure TLS | CWE-295 | Python, Go | Taint + Bandit |
| Insecure Config | CWE-16 | Python, Go | Taint |
| Resource Leak | CWE-772 | Go | Taint |
| Unsafe Block / Transmute | CWE-119 | Rust | **AST + CFG taint** |
| Panic / Unwrap | CWE-248 | Rust | Taint |
| Race Condition | CWE-362 | Go, C/C++, Java, Python | Concurrency + Go race detector |

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

# v9.0 — Real AST + CFG dataflow + symbolic execution
tree-sitter>=0.25.0
tree-sitter-c  tree-sitter-cpp  tree-sitter-python
tree-sitter-java  tree-sitter-go  tree-sitter-rust
tree-sitter-javascript  tree-sitter-typescript
tree-sitter-php  tree-sitter-ruby  tree-sitter-c-sharp
z3-solver>=4.12.0        # real_symbolic.py (Z3 SMT solver)

# Optional — advanced analysis (gracefully skipped when absent)
scikit-learn>=1.3.0      # ml_filter.py
angr>=9.2                # concolic_fuzzer.py  (~1 GB)
```

The SCA, secrets, SBOM, and SARIF modules use only the Python standard library (`urllib`, `hashlib`, `json`, `re`) — **no extra pip packages required** for the v8.0 features.

The v9.0 real-analysis engine uses individual `tree-sitter-*` grammar wheels (11 languages). Without them, the tool gracefully falls back to regex-based analysis. Z3 (`z3-solver`) enables proven symbolic execution findings with counterexamples; without it the engine falls back to interval abstract interpretation.

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
| `tree-sitter` | v9.0 real AST parsing (14 languages) | `pip install tree-sitter tree-sitter-c ...` |
| `z3-solver` | v9.0 symbolic execution + proofs | `pip install z3-solver` |
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
| **v9.0** | 2026-03-07 | **Real AST parsing** (tree-sitter, 14 languages); **real CFG-based dataflow** (reaching definitions, taint with gen/kill, fixpoint iteration); **real symbolic execution** (Z3 bitvector, path constraints, counterexamples); **dominator-based FP filter** (sanitizer guard verification, dead-code elimination); 5 new modules (`tree_sitter_engine.py`, `cfg_builder.py`, `real_dataflow.py`, `real_symbolic.py`, `false_positive_filter.py`); 8 new languages (JS, TS, PHP, Ruby, C#, Kotlin, Swift, Scala) |
| **v8.1** | 2026-03-07 | `github_scanner.py` — scan any GitHub repo by URL/shorthand; git-clone + Contents API fallback; private repo support via GITHUB_TOKEN; full 6-stage pipeline runs on downloaded code |
| **v8.0** | 2026-03-07 | `sca_scanner.py` (OSV API, 7 manifest formats); `secrets_scanner.py` (30+ patterns + entropy); `sbom_generator.py` (CycloneDX 1.4); `sarif_output.py` (SARIF 2.1.0); 6-stage pipeline |
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

