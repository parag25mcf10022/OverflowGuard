# 🛡️ Overflow Guard v3.9
**Researcher:** Parag Bagade 
**Project Type:** Hybrid C/C++ Security Audit & Vulnerability Detection Engine

---

## 🚀 Overview
**Overflow Guard** is a specialized security tool designed to identify memory corruption and logic flaws in C and C++ source code. Unlike traditional static analyzers that often produce false positives, Overflow Guard uses a **Hybrid Analysis** approach. 

By combining pattern-matching static analysis with **Dynamic Binary Instrumentation (DBI)**, the tool stress-tests binaries through iterative cycles to uncover "Time-Bomb" vulnerabilities that only trigger under specific runtime states.

## ✨ Key Features
* **Adaptive Toolchain:** Automatically detects source language (C/C++) and selects the appropriate compiler (`gcc`/`g++`).
* **Iterative Stress Testing:** Executes binaries up to 10 times per scan to trigger state-gated or count-based vulnerabilities.
* **Deep Memory Audit:** Detects Use-After-Free, Stack Overflows, and Heap Corruption using Google's AddressSanitizer (ASan).
* **Logic Flaw Detection:** Identifies Integer Overflows, Division by Zero, and Null Pointer Dereferences via UndefinedBehaviorSanitizer (UBSan).
* **Modular Intelligence:** Utilizes an external `vulnerability_db.py` for rich metadata, CWE mapping, and remediation advice.
* **Visual Dashboard:** Generates a dark-mode HTML report for professional auditing and presentations.

---

## 🛠️ Installation & Dependencies

### Prerequisites
The tool requires a Linux environment (tested on Parrot OS/Ubuntu) with the following packages:
* **Python 3.x**
* **GCC/G++** (with support for `-fsanitize`)
* **Flawfinder** (for static analysis)

### Automated Setup
Use the provided `setup.sh` to install all dependencies automatically:
```bash
git clone https://github.com/parag25mcf10022/OverflowGuard.git
cd OverflowGuard
chmod +x setup.sh
./setup.sh
```
**Run it :**
```bash
python main.py
```
