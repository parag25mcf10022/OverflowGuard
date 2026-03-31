# 🛡️ OverflowGuard v11.0

**Lead Researcher:** Parag Bagade  
**GitHub:** [parag25mcf10022/OverflowGuard](https://github.com/parag25mcf10022/OverflowGuard)  
**Medium:** Read about the tool here [https://medium.com/@bagade1122/i-built-a-security-scanner-that-goes-beyond-regex-heres-why-and-how-0713f64d03ae]
**Status:**  v11.0 (IaC Scanning + Cross-file Taint + Container Security + OWASP Top 10 + Custom Rules + Auto-fix + JSON Output + Trend Tracking + CI Templates)

![CI](https://github.com/parag25mcf10022/OverflowGuard/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue)
![Languages](https://img.shields.io/badge/languages-14-green)
![License](https://img.shields.io/badge/license-MIT-blue)
![Version](https://img.shields.io/badge/version-11.0-red)

---

## 🚀 Overview

**OverflowGuard** is a polyglot security orchestration framework that detects, classifies, and reports memory-corruption and logic vulnerabilities across **14 programming languages**: C, C++, Python, Go, Rust, Java, JavaScript, TypeScript, PHP, Ruby, C#, Kotlin, Swift, and Scala.

Unlike surface-level scanners that rely on regex pattern matching, OverflowGuard features **real AST parsing** (tree-sitter), **real dataflow analysis** on Control-Flow Graphs (reaching definitions, taint propagation with gen/kill semantics), **real symbolic execution** (Z3 SMT solver with bitvector arithmetic, path constraints, and counterexample generation), **context-aware false-positive filtering** (dominator-based sanitizer verification, dead-code elimination, test-code detection), **advanced source-to-sink taint analysis** (Checkmarx/CodeQL-style risk scoring), **differential scanning** (git-aware, only scan changed files), **remediation guidance** (secure alternative code snippets for 28 vulnerability types), **Infrastructure-as-Code scanning** (Terraform, Kubernetes, Docker, CloudFormation, Ansible), **cross-file taint analysis**, **container image scanning**, **OWASP Top 10 coverage reporting**, **custom rule engine**, **auto-fix patch generation**, **JSON machine-readable output**, **severity trend tracking**, and **CI/CD templates** for GitLab, Jenkins, Bitbucket, and Azure Pipelines.

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
| 1i — Advanced Taint | `advanced_taint.py` (source→sink, CVSS risk scoring) | C/C++, Python, Java, Go, Rust |
| 2a — External SAST | cppcheck + clang-tidy + semgrep + Infer + LLVM | C/C++, Python, Java |
| 2b — Concolic Fuzzing | `concolic_fuzzer.py` (angr → AFL++ → ASAN) | C/C++ |
| 3 — SCA | `sca_scanner.py` (OSV API) | All manifest formats |
| 4 — Secrets Scan | `secrets_scanner.py` (30+ patterns + entropy) | All source + config files |
| **★ GitHub** | **`github_scanner.py` (clone or Contents API)** | **Any public or private GitHub repo** |

| Stage | Technology | What it covers |
|---|---|---|
| 7 — IaC Scanning | `iac_scanner.py` (44 rules, 5 frameworks) | Terraform, Kubernetes, Docker, CloudFormation, Ansible |
| 8 — Cross-file Taint | `cross_file_taint.py` (file-level call graph) | C/C++, Python, Java, Go, Rust, JS/TS — multi-hop injection paths |
| 9 — Container Scan | `container_scanner.py` (CIS Benchmark) | Dockerfiles, docker-compose.yml — 18 rules + EOL base image DB |
| 10 — Custom Rules | `custom_rules.py` (YAML engine) | Any language — user-defined regex-based security rules |
| 11 — OWASP Top 10 | `owasp_mapper.py` (200+ CWE mappings) | Maps all findings to OWASP Top 10 (2021) categories |
| 12 — Auto-fix | `autofix.py` (unified diff patches) | C/C++, Python, Go, Java — 18 auto-fix patterns |
| 13 — Trend Tracking | `trend_tracker.py` (SQLite) | Historical severity trends with quality gates |
| 14 — JSON Output | `json_output.py` | Machine-readable JSON reports for CI/CD pipelines |

Output formats: **HTML dashboard** (with secure-alternative remediation cards + OWASP coverage), **SARIF 2.1.0** (GitHub Code Scanning / Azure DevOps), **CycloneDX 1.4 SBOM**, **JSON** (machine-readable for CI/CD).

Scan modes: **Full directory scan**, **single file**, **GitHub repo**, **differential scan** (git-aware, `--diff` flag), **incremental scan** (dependency-cone, `--incremental` flag).

---

## ✨ Features

### v11.0 — IaC Scanning, Cross-file Taint, Container Security, OWASP Top 10, Custom Rules, Auto-fix, JSON Output, Trend Tracking, CI Templates

- **Project configuration** (`project_config.py`) — `.overflowguard.yml` config file with path exclusions, rule filtering, severity thresholds, language selection, and feature toggles; auto-discovers config by walking up the directory tree; generate a sample config with `--init-config`
- **Infrastructure-as-Code scanning** (`iac_scanner.py`) — 44 security rules across **5 IaC frameworks**: Terraform (14 rules: S3 public access, unencrypted storage, open security groups, no logging, public IPs, etc.), Kubernetes (11 rules: privileged containers, host PID/network, missing resource limits, `latest` tag, etc.), Dockerfile (9 rules: `ADD` from URL, `curl | bash`, secrets in ENV, etc.), CloudFormation (6 rules: public S3, unencrypted RDS/EBS, wildcard IAM, open SGs), Ansible (4 rules: plaintext passwords, no_log missing, shell injection, HTTP downloads)
- **Cross-file taint analysis** (`cross_file_taint.py`) — builds file-level call graphs from imports/includes across C/C++ (`#include`), Python (`import`/`from`), Java (`import`), Go (`import`), Rust (`use`/`mod`), and JavaScript/TypeScript (`import`/`require`); propagates taint findings across file boundaries to detect multi-hop injection paths; per-language source/sink databases
- **Auto-fix patch generation** (`autofix.py`) — generates unified diff patches for 18 vulnerability patterns: C/C++ (7: `gets`→`fgets`, `strcpy`→`strncpy`, `sprintf`→`snprintf`, printf format, `system()`, `rand()`→`arc4random()`), Python (7: SQL injection, `os.system`, `eval`, `pickle`, weak-crypto, hardcoded-password, path-traversal), Go (2: SQL, `InsecureSkipVerify`), Java (2: `Statement`→`PreparedStatement`, weak-crypto); pass `--autofix` to generate a `.patch` file
- **JSON machine-readable output** (`json_output.py`) — `--format json` produces a structured JSON report with summary, all findings, SCA, IaC, cross-file taint, auto-fixes, OWASP mapping, and trend data; ideal for CI/CD pipeline consumption and ASPM integration
- **Severity trend tracking** (`trend_tracker.py`) — SQLite-backed historical scan database (`~/.overflowguard/trends.db`); records every scan with severity counts, git commit, and branch; compares current scan to previous and shows delta (↑/↓/→); **quality gate**: fails if critical or high findings increased; trend data included in JSON output
- **Custom rule engine** (`custom_rules.py`) — YAML-based rule definitions in a `rules/` directory; each rule has an id, regex pattern, message, severity, language filter, CWE, and fix suggestion; generate sample rules with `--init-rules`; scan is automatically run when a `rules/` directory is detected
- **Container & Dockerfile scanning** (`container_scanner.py`) — 18 CIS Docker Benchmark rules covering privilege escalation (running as root, `--privileged`), supply-chain attacks (`curl | bash`, `ADD` from URL), network exposure (SSH port 22, database ports), secrets in images (`.env`, `.pem`, hardcoded ENV passwords), and best practices (unpinned base images, missing `HEALTHCHECK`, `apt-get` cache cleanup); 25-entry EOL/vulnerable base image database; docker-compose.yml scanning (privileged mode, host networking, dangerous mounts)
- **Incremental cross-file analysis** (`incremental_analysis.py`) — combines git diff with dependency-cone analysis: only re-analyzes changed files plus files that import/include them; BFS through reverse-dependency graph; reports scan savings percentage; pass `--incremental` to enable
- **OWASP Top 10 (2021) coverage report** (`owasp_mapper.py`) — maps all findings to OWASP Top 10 categories using a 200+ CWE-to-OWASP mapping table plus keyword-based fallback; generates CLI table and HTML fragment showing coverage percentage, per-category finding counts, and severity breakdown; included in JSON output
- **CI/CD pipeline templates** (`ci_templates/`) — ready-to-use pipeline configurations for **GitLab CI** (4 stages: test, scan, diff-scan, pages), **Jenkins** (declarative pipeline, 4 stages with JUnit + HTML publisher), **Bitbucket Pipelines** (default + PR + branch pipelines), and **Azure Pipelines** (2 stages with JUnit publish and build artifacts)

### v10.0 — Differential Scanning, Remediation Guidance, Advanced Taint

- **Differential scanning** (`diff_scanner.py`) — git-aware mode that only scans **changed files** to dramatically reduce scan times on large repositories; supports five diff modes: `staged` (files in the git index), `working` (unstaged changes), `head` (last commit), `commits:N` (last N commits), `last-tag` (changes since the most recent tag); automatically detects the repository root and falls back to a full scan if git is unavailable; pass `--diff [mode]` and optionally `--diff-only` on the CLI
- **Remediation guidance** (`remediation_db.py`) — every finding now includes a **"Secure Alternative"** code snippet card in the HTML report and a one-liner hint in the CLI output; covers **28 vulnerability types** with dangerous-call explanation, why it's dangerous, secure replacement, language-tagged code snippet, and reference links (CWE / OWASP); integrated directly into the per-finding cards in the HTML dashboard as collapsible `<details>` blocks
- **Advanced source-to-sink taint analysis** (`advanced_taint.py`) — elite Checkmarx / CodeQL-style taint engine that tracks attacker-controlled data from **sources** (network sockets, `recv`, `fgets`, `input()`, `http.Request`, `stdin`) to **sinks** (`system()`, `exec()`, `memcpy`, `strcpy`, SQL execute, `eval`) with **CVSS-like risk scoring** (0–10 scale); dual engine: CFG-based fixpoint taint tracker (tree-sitter) + regex fallback; per-language source/sink/sanitizer databases for C/C++, Python, Java, Go, Rust; sanitizer families (bounds_check, shell_escape, parameterization, input_validation, etc.) reduce risk scores; risk provenance weighting (network=9.8, user_input=8.0, env=5.5, file=3.0)

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

### Differential scan (only changed files)

```bash
# Scan only files changed since last commit (default: working tree changes)
python3 main.py --diff
# When prompted: Enter Path/File: samples

# Scan only staged files
python3 main.py --diff staged

# Scan changes in last 3 commits
python3 main.py --diff commits:3

# Scan changes since the last git tag
python3 main.py --diff last-tag

# Only scan changed files (skip full scan entirely)
python3 main.py --diff --diff-only
```

### v11.0 new CLI options

```bash
# Generate JSON output (for CI/CD pipelines)
python3 main.py --format json samples/

# Generate auto-fix patch file
python3 main.py --autofix samples/

# Incremental scan (only changed files + dependency cone)
python3 main.py --incremental samples/

# Set minimum severity threshold
python3 main.py --severity high samples/

# Disable specific scan stages
python3 main.py --no-iac --no-container samples/

# Use custom rules from a specific directory
python3 main.py --rules-dir /path/to/rules samples/

# Generate sample configuration file
python3 main.py --init-config

# Generate sample custom rules
python3 main.py --init-rules
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
⛔  OVERFLOW GUARD v11.0 | Researcher: Parag Bagade

┌─────────────────────────────────────────────────────────────────┐
│ ANALYZING: sample.c                                               │
└─────────────────────────────────────────────────────────────────┘
[*] v9.0 AST(tree‑sitter) real dataflow / symbolic pass (c)...
[!!!] RealDataflow [High] use-after-free @ line 23
[!!!] RealDataflow [Medium] buffer-overflow @ line 21
[~] Symbolic(Z3) [High] buffer-overflow @ line 13 — Z3 proved: strcpy overflow
[!!!] AdvancedTaint [8.0/10] stack-buffer-overflow @ line 6 — gets → stack buffer
    💡 Remediation: Replace gets() with fgets(buf, sizeof(buf), stdin)

━━━  Stage 7: Infrastructure-as-Code (IaC) Scanning  ━━━
  [iac] scanning main.tf
  IaC Summary: 3 issues (1 high, 2 medium) across 1 file(s)

━━━  Stage 8: Cross-file Taint Analysis  ━━━
  [✔] Cross-file taint: 2 cross-boundary flows detected

━━━  Stage 11: OWASP Top 10 (2021) Coverage Report  ━━━
  A01:2021  Broken Access Control          0 findings  ✗ No findings
  A03:2021  Injection                      5 findings  ✓ COVERED (2 critical, 3 high)
  A05:2021  Security Misconfiguration      3 findings  ✓ COVERED (1 high, 2 medium)
  Coverage: 40% (8/12 findings mapped)

━━━  v11.0 Summary  ━━━
  AST engine           : AST(tree‑sitter)
  Languages supported  : C, C++, Python, Java, Go, Rust, JS, TS, PHP, Ruby, C#, Kotlin, Swift, Scala
  SCA findings         : 0 CVEs in dependencies
  IaC findings         : 3
  Cross-file taint     : 2 flows
  Container issues     : 0
  OWASP coverage       : 40%
  Auto-fix patches     : 2
  Output format        : html
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

# v10.0 — No additional pip dependencies required
# diff_scanner.py    — uses subprocess (git) — stdlib only
# remediation_db.py  — pure Python dataclass DB — stdlib only
# advanced_taint.py  — reuses tree-sitter (already installed above)

# v11.0 — No additional pip dependencies required
# All v11.0 modules use only the Python standard library (os, re, json,
# sqlite3, subprocess, dataclasses). PyYAML is optional for project_config.py
# and custom_rules.py — a built-in YAML parser handles simple configs.
PyYAML>=6.0              # optional: for .overflowguard.yml and custom rules

# Optional — advanced analysis (gracefully skipped when absent)
scikit-learn>=1.3.0      # ml_filter.py
angr>=9.2                # concolic_fuzzer.py  (~1 GB)
```

The SCA, secrets, SBOM, and SARIF modules use only the Python standard library (`urllib`, `hashlib`, `json`, `re`) — **no extra pip packages required** for the v8.0 features.

The v9.0 real-analysis engine uses individual `tree-sitter-*` grammar wheels (11 languages). Without them, the tool gracefully falls back to regex-based analysis. Z3 (`z3-solver`) enables proven symbolic execution findings with counterexamples; without it the engine falls back to interval abstract interpretation.

The v10.0 modules (`diff_scanner.py`, `remediation_db.py`, `advanced_taint.py`) require **no additional pip packages** — they use the Python standard library and reuse tree-sitter grammars already installed for v9.0. The diff scanner requires `git` to be available on `$PATH`.

The v11.0 modules (`project_config.py`, `iac_scanner.py`, `cross_file_taint.py`, `autofix.py`, `json_output.py`, `trend_tracker.py`, `custom_rules.py`, `container_scanner.py`, `incremental_analysis.py`, `owasp_mapper.py`) require **no additional pip packages** — they use only the Python standard library. `PyYAML` is optional (a built-in parser handles simple YAML configs). Trend tracking uses SQLite (stdlib `sqlite3`).

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
| `git` | v10.0 differential scanning | `apt install git` |
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
| **v11.0** | 2026-03-09 | **12 new features**: Project config (`.overflowguard.yml`); **IaC scanning** (Terraform, K8s, Docker, CloudFormation, Ansible — 44 rules); **cross-file taint** (file-level call graph, multi-hop injection); **auto-fix patch generation** (18 patterns, unified diff); **JSON output** (`--format json`); **severity trend tracking** (SQLite, quality gates); **custom rule engine** (YAML, `--init-rules`); **container scanning** (CIS Docker Benchmark, 18 rules, EOL base image DB); **incremental analysis** (dependency-cone, `--incremental`); **OWASP Top 10 mapping** (200+ CWE mappings, coverage report); **CI templates** (GitLab, Jenkins, Bitbucket, Azure); 10 new Python modules, 4 CI template files |
| **v10.0** | 2026-03-08 | **Differential scanning** (`diff_scanner.py` — git-aware, 5 diff modes, `--diff` CLI flag); **remediation guidance** (`remediation_db.py` — 28 vuln types with secure-alternative snippets in HTML + CLI); **advanced source-to-sink taint** (`advanced_taint.py` — Checkmarx/CodeQL-style, CVSS risk scoring 0–10, dual CFG + regex engine, per-language source/sink/sanitizer DBs) |
| **v9.0** | 2026-03-07 | **Real AST parsing** (tree-sitter, 14 languages); **real CFG-based dataflow** (reaching definitions, taint with gen/kill, fixpoint iteration); **real symbolic execution** (Z3 bitvector, path constraints, counterexamples); **dominator-based FP filter** (sanitizer guard verification, dead-code elimination); 5 new modules (`tree_sitter_engine.py`, `cfg_builder.py`, `real_dataflow.py`, `real_symbolic.py`, `false_positive_filter.py`); 8 new languages (JS, TS, PHP, Ruby, C#, Kotlin, Swift, Scala) |
| **v8.1** | 2026-03-07 | `github_scanner.py` — scan any GitHub repo by URL/shorthand; git-clone + Contents API fallback; private repo support via GITHUB_TOKEN; full 6-stage pipeline runs on downloaded code |
| **v8.0** | 2026-03-07 | `sca_scanner.py` (OSV API, 7 manifest formats); `secrets_scanner.py` (30+ patterns + entropy); `sbom_generator.py` (CycloneDX 1.4); `sarif_output.py` (SARIF 2.1.0); 6-stage pipeline |
| **v7.1** | 2026-03-03 | Smart directory scanning (skip `.venv/`, `site-packages/`); SQL f-string fix; safer pickle loading |
| **v7.0** | 2026-03-03 | 10 new advanced-analysis modules; 8-stage pipeline; persistent scan cache; ML false-positive filter |
| **v6.0** | 2026-03-03 | Multi-language taint (Go, Rust, Java), semgrep, Infer, GitHub Actions CI, HTML dashboard |
| **v5.0** | 2026-03-03 | Python SAST (Bandit), deep pattern analyser, CVE/CWE/CVSS v3.1 vulnerability DB |

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

### False Positives
Like all SAST tools, OverflowGuard produces false positives. The false-positive filter (false_positive_filter.py) uses dominator-based sanitizer verification to reduce noise, but manual review of findings is always recommended. Ongoing work on reducing FP rates is tracked in the issues section

## ⚠️ Disclaimer

This tool is intended for **authorized security research and educational purposes only**.  
The sample files in `samples/` are intentionally vulnerable — do not deploy them.  
The authors are not responsible for any misuse of this software.

