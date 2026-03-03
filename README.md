# 🛡️ Overflow Guard v5.2: Universal Deep Audit Engine

**Lead Researcher:** Parag Bagade  
**Academic Context:** M.Tech in Cyber Security & Digital Forensics, VIT Bhopal  
**Project Status:** Production Ready (v5.2 Deep Audit Edition)

---

## 🚀 Project Overview
**Overflow Guard** is an advanced, polyglot security orchestration framework designed to identify, exploit, and report critical memory corruptions and logic flaws. Unlike standard scanners, it utilizes a **Hybrid Analysis** approach—combining Static Application Security Testing (SAST) with **Iterative Mutational Fuzzing** to prove vulnerabilities through active exploitation.



## ✨ Key Features
* **Multi-Language Toolchain:** Native support for C, C++, Python (Bandit), Go (Race Detector), Rust (Safety Audit), and Java (Insecure Deserialization).
* **Automated Fuzzing Engine:** Generates real-time malicious payloads (Buffer overflows, Command Injections, Format strings) to confirm crashes and prove exploitability.
* **Deep Audit Reporting:** Generates professional HTML dashboards in the `/results` directory featuring:
* **Vulnerable Code Snippets** extracted directly from source.
* **CVE & CWE Mapping** for industry-standard classification.
* **CVSS 3.1 Scoring** to quantify risk and impact.
* **Actionable Remediation** and patches for developers.
* **Iterative Testing:** Executes C/C++ binaries through 10 stress cycles to uncover state-gated "Time-Bomb" vulnerabilities.

---

## 🛠️ Installation & Dependencies
The engine is optimized for **Parrot OS**, **Kali Linux**, or **Ubuntu**.

### 1. System Requirements
Ensure your system has the following toolchains installed:
```bash
# Update System
sudo apt update

# Install Core Toolchains
sudo apt install -y gcc g++ golang-go rustc python3-pip openjdk-17-jdk flawfinder

# Install Security Scanners
pip3 install colorama bandit --break-system-packages
```

### 2.Setup
```bash
git clone https://github.com/parag25mcf10022/OverflowGuard.git

cd OverflowGuard

chmod +x setup.sh

./setup.sh

mkdir results 
```

### 3.Usage Guide
```bash
python3 main.py
```
