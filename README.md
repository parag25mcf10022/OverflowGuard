# 🛡️ OverflowGuard v11.0

**Lead Researcher:** Parag Bagade
**GitHub:** [parag25mcf10022/OverflowGuard](https://github.com/parag25mcf10022/OverflowGuard)
**Medium:** [I built a security scanner that goes beyond regex — here's why and how](https://medium.com/@bagade1122/i-built-a-security-scanner-that-goes-beyond-regex-heres-why-and-how-0713f64d03ae)

![CI](https://github.com/parag25mcf10022/OverflowGuard/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue)
![Languages](https://img.shields.io/badge/languages-14-green)
![License](https://img.shields.io/badge/license-MIT-blue)
![Version](https://img.shields.io/badge/version-11.0-red)

---

## 🚀 Overview

**OverflowGuard** is a polyglot security-orchestration framework that detects, classifies, and reports memory-corruption and logic vulnerabilities across **14 languages** — C, C++, Python, Go, Rust, Java, JavaScript, TypeScript, PHP, Ruby, C#, Kotlin, Swift, Scala — plus infrastructure-as-code, containers, and dependencies.

Unlike scanners that rely on regex matching, OverflowGuard combines **real AST parsing** (tree-sitter), **CFG-based dataflow/taint** (reaching definitions, gen/kill fixpoint), **symbolic execution** (Z3 SMT with bitvector arithmetic and counterexamples), **dynamic sanitizer fuzzing** (ASAN/UBSan), and **external SAST** (cppcheck, clang-tidy, semgrep, Infer). Findings from every engine are **merged and corroborated** into a single de-duplicated report.

When multiple engines agree on a bug, it's reported once — with the most severe label, a `corroborated by N engines` confidence boost, and per-engine attribution.

---

## ✨ Recent improvements (2026-06) — accuracy & UX

These changes substantially cut noise and false positives, and make the tool harder to misuse:

- **Cross-engine de-duplication** — the same bug found by several engines (e.g. `buffer-overflow` / `stack-buffer-overflow` / `heap-buffer-overflow` at one line) is merged into a single finding, keyed on a canonical vulnerability family + line. Each finding records its `corroborating_stages`; agreement from ≥2 engines raises confidence to HIGH. *(On the bundled samples this cut total findings ~50% with zero loss of real bugs.)*
- **False-positive fixes** — string-literal/comment masking (no more flagging `printf("…gets()…")`), prototype/declaration guards (`char *gets(char*);` is not a call), array-declaration guard (`char buf[16];` is not an out-of-bounds access), and a fixed use-after-free check (`free(p)` as the last statement is no longer reported as a use *after* free). Applied to both the tree-sitter and regex-fallback paths.
- **Smarter fuzzer** — a crash is now a process killed by a **signal** (SIGSEGV/SIGABRT/SIGFPE…) or one that emits **sanitizer diagnostics**, not merely any non-zero exit. Crashes are classified precisely: use-after-free, heap corruption, stack overflow (ASAN), integer-overflow / division-by-zero / OOB (UBSan), or by signal name.
- **Auto-relaunch into the project venv** — running `python main.py` with an interpreter that lacks tree-sitter transparently re-execs under `.venv` so you always get the full engine instead of silently degrading to regex. A loud banner warns if no suitable venv is found. (Disable with `OVERFLOWGUARD_NO_REEXEC=1`.)
- **Clean terminal output** — one concise, colour-coded line per file by default, with a live `scanning …` indicator on a TTY. Use `-v` / `--verbose` for the full per-engine detail. The HTML/JSON/SARIF reports are always complete regardless.
- **Normalized confidence** — every finding's confidence is exactly `HIGH` / `MEDIUM` / `LOW` (no mixed casing or severity leakage).
- **Quieter external tools** — non-security cppcheck style/maintainability noise (`unusedFunction`, `constParameter`, …) is dropped unless it maps to a real weakness.
- **Engine-aware trend tracking** — scans record whether they ran in `full` or `degraded` mode; a full run is never compared against a degraded baseline, so quality-gate deltas stay meaningful.
- **Clearer OWASP report** — *category coverage* (n/10 categories) and *finding mapping* (m/total findings mapped) are now reported as two distinct metrics instead of one confusing number.

---

## 🧱 Analysis pipeline

| Stage | Module(s) | Scope |
|---|---|---|
| 0 — Real AST + CFG | `tree_sitter_engine.py`, `cfg_builder.py` | 14 languages — syntax trees + basic-block CFGs + dominator trees |
| 0a — CFG dataflow | `real_dataflow.py` | source→sink taint with gen/kill fixpoint; UAF/double-free/OOB |
| 0b — Symbolic exec | `real_symbolic.py` | Z3 bitvector proofs + counterexamples (interval fallback) |
| 0c — FP filter | `false_positive_filter.py` | dominator-based sanitizer verification, dead-code/test-code suppression |
| 1 — Language SAST | `taint_analyzer.py`, `advanced_taint.py`, `deep_analyzer.py`, `dataflow.py`, `interprocedural_taint.py`, `symbolic_check.py`, `concurrency_analyzer.py`, `llvm_analyzer.py`, `ast_analyzer.py` | per-language multi-pass taint, source→sink risk scoring, concurrency |
| 2 — External SAST | `static_tools.py` | cppcheck, clang-tidy, semgrep, Infer, LLVM |
| 2b — Dynamic fuzzing | built-in fuzzer + `concolic_fuzzer.py` | ASAN/UBSan crash detection (angr → AFL++ → ASAN tiers) |
| 3 — SCA | `sca_scanner.py` | dependency CVEs (OSV API) + license compliance |
| 4 — Secrets | `secrets_scanner.py` | 30+ patterns + Shannon entropy |
| 5 — SBOM | `sbom_generator.py` | CycloneDX 1.4 |
| 6 — SARIF | `sarif_output.py` | SARIF 2.1.0 export |
| 7 — IaC | `iac_scanner.py` | Terraform, K8s, Docker, CloudFormation, Ansible (44 rules) |
| 8 — Cross-file taint | `cross_file_taint.py` | file-level call graph, multi-hop injection |
| 9 — Container | `container_scanner.py` | Dockerfile/compose, CIS Benchmark (18 rules) |
| 10 — Custom rules | `custom_rules.py` | YAML-defined regex rules |
| 11 — OWASP Top 10 | `owasp_mapper.py` | 200+ CWE→OWASP mappings + coverage report |
| 12 — Auto-fix | `autofix.py` | unified-diff patches (18 patterns) |
| 13 — Trend tracking | `trend_tracker.py` | SQLite history + quality gates |
| 14 — JSON output | `json_output.py` | machine-readable report for CI/CD |

**Output formats:** HTML dashboard, SARIF 2.1.0, CycloneDX 1.4 SBOM, JSON.
**Scan modes:** directory, single file, GitHub repo (`owner/repo[@branch]` or URL), differential (`--diff`), incremental (`--incremental`).

> If tree-sitter isn't installed, every language engine gracefully falls back to regex heuristics — but you lose Stage 0 accuracy. Run inside `.venv` (auto-relaunch handles this for you).

---

## 🔧 Feature highlights

- **Real multi-engine analysis** — tree-sitter AST, CFG dataflow, Z3 symbolic execution, and dynamic sanitizer fuzzing, corroborated into one report.
- **Source-to-sink taint** (`advanced_taint.py`) — Checkmarx/CodeQL-style tracking from attacker-controlled sources to dangerous sinks with CVSS-like risk scoring and sanitizer awareness.
- **Supply-chain security** — SCA via OSV, license compliance, OSS snippet matching, secrets scanning, CycloneDX SBOM.
- **Infrastructure & containers** — IaC scanning across 5 frameworks (44 rules) and Dockerfile/compose scanning against the CIS Benchmark with an EOL base-image database.
- **OWASP Top 10 (2021)** coverage mapping with category-coverage and finding-mapping metrics.
- **Remediation guidance** — secure-alternative code snippets for 28 vulnerability types, shown in the HTML report and CLI.
- **Auto-fix** — generates unified-diff patches for 18 common patterns (`--autofix`).
- **GitHub scanning** — clone or Contents-API fallback; private repos via `GITHUB_TOKEN`.
- **Differential & incremental** scanning for large/CI repos (git-aware, dependency-cone).
- **Custom rules** — YAML rule engine (`--init-rules`); project config via `.overflowguard.yml` (`--init-config`).
- **CI/CD templates** for GitLab, Jenkins, Bitbucket, and Azure Pipelines.

---

## 🛠️ Installation

> Tested on **Parrot OS**, **Kali Linux**, and **Ubuntu 22.04+**.

```bash
git clone https://github.com/parag25mcf10022/OverflowGuard.git
cd OverflowGuard

# One-shot bootstrap: system deps + .venv + Python deps + tree-sitter + Z3
chmod +x setup.sh && ./setup.sh
```

Or manually:

```bash
sudo apt install -y gcc g++ cppcheck clang-tidy clang llvm \
    golang-go rustc cargo openjdk-17-jdk python3-pip python3-venv git

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Optional: [Facebook Infer](https://fbinfer.com/docs/getting-started) for deep C/Java null-deref and leak analysis.

---

## ▶️ Usage

```bash
source .venv/bin/activate
python main.py                 # then enter a path / file / GitHub repo at the prompt
python main.py samples/        # or pass the target directly
```

> Even if you forget to activate `.venv`, `python main.py` auto-relaunches under it so you get the full engine.

### Common options

```bash
python main.py samples/ -v             # verbose: full per-engine detail
python main.py samples/ --format json  # JSON report (also writes HTML + SARIF)
python main.py samples/ --autofix      # generate unified-diff fix patches
python main.py samples/ --severity high        # minimum severity to report
python main.py samples/ --no-iac --no-container # disable specific stages
python main.py samples/ --max-critical 0        # quality gate (fail on any critical)

# Differential scan (git-aware)
python main.py --diff                   # working-tree changes
python main.py --diff staged            # staged files
python main.py --diff commits:3         # last 3 commits
python main.py --diff last-tag          # since last tag
python main.py --diff --diff-only       # only changed files

python main.py --incremental samples/   # changed files + dependency cone
python main.py --init-config            # write a sample .overflowguard.yml
python main.py --init-rules             # write a sample custom-rules dir
```

### GitHub repositories

```bash
python main.py                          # enter: owner/repo  |  owner/repo@branch  |  full URL
export GITHUB_TOKEN=ghp_...             # for private repos / higher rate limit
```

### Tests

```bash
python -m pytest tests/ -v
```

---

## 📊 Example output (default clean mode)

```
⛔  OVERFLOW GUARD v11.0 | Researcher: Parag Bagade
  [!] sample2.c           10 findings  (1 critical, 5 high, 4 medium)
  [!] use_after.c          7 findings  (1 critical, 3 high, 3 medium)
  [!] sample.c             7 findings  (3 critical, 1 high, 3 medium)
  [✓] test_audit.py      clean
  ...

━━━  Stage 11: OWASP Top 10 (2021) Coverage Report  ━━━
  A03:2021  Injection                 91 findings  ✓ COVERED (17 critical, 52 high, 20 medium, 2 low)
  ...
  Category coverage : 50%  (5/10 OWASP categories have at least one finding)
  Finding mapping   : 98%  (109/111 findings mapped to a category)

━━━  Stage 13: Severity Trend Tracking  ━━━
  Trend: IMPROVING
  Quality gate: PASS

📊  FINAL AUDIT SCORECARD — Total findings: 111  (CRIT:20  HIGH:56  MED:29  LOW:6)
[✔] Report: results/samples.html
```

Run with `-v` to see every engine's per-finding output (`RealDataflow`, `Symbolic(Z3)`, `AST(tree-sitter)`, `Taint`, `cppcheck`, fuzzer crashes, etc.).

---

## 🎯 Confidence levels

| Badge | Meaning |
|---|---|
| 🟢 **HIGH** | Direct sink match, confirmed taint path, or corroboration by ≥2 engines |
| 🟡 **MEDIUM** | Probable — pattern match or partial taint path |
| ⚫ **LOW** | Heuristic signal; manual review recommended |

---

## 🔬 Detection capabilities

| Vulnerability class | CWE | Languages | Primary method |
|---|---|---|---|
| Stack Buffer Overflow | CWE-121 | C/C++ | AST + CFG dataflow + Z3 + cppcheck + fuzzer |
| Heap Buffer Overflow | CWE-122 | C/C++ | AST + CFG dataflow + Z3 + cppcheck + ASAN |
| Use-After-Free | CWE-416 | C/C++ | AST variable tracking + cppcheck + ASAN |
| Double-Free | CWE-415 | C/C++ | AST variable tracking + Taint |
| Off-By-One | CWE-193 | C/C++ | Z3 + Taint + AST |
| Integer Overflow / Truncation | CWE-190/197 | C/C++, JS, TS, PHP, C# | Z3 bitvector proof + UBSan |
| Format String | CWE-134 | C/C++ | AST + clang-tidy |
| Null Pointer Deref | CWE-476 | C/C++ | cppcheck + Clang SA + Infer |
| Memory Leak | CWE-401 | C/C++ | cppcheck + Infer |
| Insecure Eval | CWE-95 | Python, JS, TS, PHP, Ruby | AST + CFG taint + Bandit |
| OS Command Injection | CWE-78 | Python, Java, Go, Rust, JS, TS, PHP, Ruby, C#, Kotlin, Swift, Scala | AST + CFG taint + Bandit + fuzzer |
| SQL Injection | CWE-89 | Python, Java, Go, PHP, Ruby, C# | AST + CFG taint + Bandit |
| XSS | CWE-79 | Python, JS, TS, PHP | AST + CFG taint |
| Path Traversal | CWE-22 | C/C++, Python, Java, PHP | AST + CFG taint |
| SSRF | CWE-918 | Python, Go, PHP | AST + CFG taint |
| Insecure Deserialization | CWE-502 | Python, Java, PHP, Ruby, C#, Kotlin, Swift, Scala | AST + CFG taint + Bandit |
| Weak RNG / Crypto | CWE-338/327 | C/C++, Python, Java, Go | Taint + Bandit + semgrep |
| Template / Open Redirect / LDAP / XXE / JWT | CWE-94/601/90/611/347 | Python, Java | Taint |
| Hardcoded Password | CWE-259 | Python, Java, Go, Rust | Taint + Bandit |
| Insecure TLS / Config | CWE-295/16 | Python, Go | Taint + Bandit |
| Unsafe Block / Transmute | CWE-119 | Rust | AST + CFG taint |
| Panic / Unwrap | CWE-248 | Rust | Taint |
| Race Condition | CWE-362 | Go, C/C++, Java, Python | Concurrency + Go race detector |

---

## 📋 Requirements

Python deps are in `requirements.txt` (`pip install -r requirements.txt`):

- **Core:** `colorama`, `libclang`, `bandit`, `semgrep`, `pytest`
- **Real engine (v9.0+):** `tree-sitter` + 11 grammar wheels, `z3-solver`
- **Optional config:** `PyYAML` (a built-in parser handles simple configs otherwise)
- **Optional advanced (gracefully skipped if absent):** `scikit-learn` (ML FP filter), `angr` (concolic fuzzer, ~1 GB)

Modules for SCA, secrets, SBOM, SARIF, IaC, cross-file taint, auto-fix, JSON, trend tracking, and OWASP mapping use only the standard library.

### System tools

| Tool | Purpose | Install |
|---|---|---|
| `gcc` / `g++` | Compile with ASAN/UBSan (dynamic fuzzing) | `apt install gcc g++` |
| `cppcheck`, `clang-tidy` | External static analysis | `apt install cppcheck clang-tidy` |
| `clang` / `llvm` | LLVM IR emission | `apt install clang llvm` |
| `semgrep` | Multi-language SAST patterns | `pip install semgrep` |
| `git` | Differential/incremental scanning, GitHub clone | `apt install git` |
| `go` / `rustc` / `java` | Go race detector, Rust & Java checks | `apt install golang-go rustc openjdk-17-jdk` |
| `afl++`, `bear`, `infer` | Optional advanced tiers | see distro / [fbinfer.com](https://fbinfer.com) |

Without tree-sitter the tool degrades to regex; without Z3, symbolic execution falls back to interval arithmetic.

---

## 🔄 CI/CD

A **GitHub Actions** workflow (`.github/workflows/ci.yml`) runs on every push to `main` / `feature/**`:

| Job | Steps |
|---|---|
| `test` | `pytest tests/ -v` |
| `static-analysis` | cppcheck on `samples/`, upload artifact |
| `bandit` | `bandit -r .`, upload artifact |
| `full-scan` | `python main.py samples/`, upload HTML report |

Ready-to-use templates for **GitLab CI**, **Jenkins**, **Bitbucket**, and **Azure Pipelines** live in `ci_templates/`. Use `--format json` and `--max-critical` / `--max-high` for machine-readable output and quality gates.

---

## 🤝 Contributing

1. Fork and branch: `git checkout -b feat/your-feature`
2. Add tests in `tests/test_audit.py` for new detection logic
3. `python -m pytest tests/ -v` — all tests must pass
4. Open a PR

> Directory scans automatically skip `.venv/`, `venv/`, `__pycache__/`, `site-packages/`, `node_modules/`, `.git/`, and build-artifact folders.

---

## 🗓️ Changelog

| Version | Date | Highlights |
|---|---|---|
| **v11.0** (hardening) | 2026-06 | Cross-engine de-dup with corroboration; FP fixes (string-literal masking, prototype/array-decl guards, UAF-on-free); sanitizer-based fuzzer crash classification; auto-relaunch into `.venv`; clean terminal output + `-v`; normalized confidence; cppcheck noise filter; engine-aware trend tracking; split OWASP coverage metrics |
| **v11.0** | 2026-03-09 | IaC scanning (5 frameworks, 44 rules); cross-file taint; auto-fix patches; JSON output; trend tracking (SQLite, quality gates); custom rule engine; container/CIS scanning; incremental analysis; OWASP Top 10 mapping; CI templates |
| **v10.0** | 2026-03-08 | Differential scanning (`--diff`, 5 modes); remediation guidance (28 vuln types); advanced source-to-sink taint with CVSS risk scoring |
| **v9.0** | 2026-03-07 | Real engine: tree-sitter AST (14 langs), CFG dataflow, Z3 symbolic execution, dominator-based FP filter |
| **v8.x** | 2026-03-07 | GitHub repo scanning; SCA (OSV); secrets scanner; CycloneDX SBOM; SARIF 2.1.0 |
| **v5–v7** | 2026-03 | Python/Bandit SAST, multi-language taint, advanced-analysis modules, HTML dashboard, CI |

---

## 📄 License

MIT — see [LICENSE](LICENSE).

## ⚠️ Disclaimer

For **authorized security research and educational purposes only**. The files in `samples/` are intentionally vulnerable — do not deploy them. Like all SAST tools, OverflowGuard can produce false positives; manual review of findings is recommended. The authors are not responsible for misuse.
