import subprocess
import os
import sys
import json
import datetime
import random
from colorama import init, Fore, Style

# Initialize Colorama
init(autoreset=True)

# Load Security Intelligence from vulnerability_db.py
try:
    from vulnerability_db import VULN_DATA as VULN_INTEL
except ImportError:
    print(f"{Fore.YELLOW}[!] Warning: vulnerability_db.py not found. Fallback mode active.")
    VULN_INTEL = {}

# --- CONFIGURATION ---
RESEARCHER_NAME = "Parag Bagade"
GITHUB_REPO_URL = "https://github.com/parag25mcf10022/OverflowGuard"

class AuditManager:
    def __init__(self, target_input):
        self.report_data = {}
        self.stats = {"scanned": 0, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        self.scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        clean_target = target_input.rstrip(os.sep)
        self.output_base_name = os.path.basename(clean_target) if clean_target else "audit_report"
        
        self.results_dir = "results"
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)

    def get_vulnerable_line(self, file_path, issue_type):
        """Extracts the specific line of code likely responsible for the finding"""
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
                for i, line in enumerate(lines):
                    # Heuristic matching for code snippet extraction
                    if "overflow" in issue_type and ("strcpy" in line or "gets" in line or "[" in line):
                        return i + 1, line.strip()
                    if "injection" in issue_type and ("subprocess" in line or "os.system" in line or "shell=True" in line):
                        return i + 1, line.strip()
                    if "race" in issue_type and ("go " in line or "chan " in line):
                        return i + 1, line.strip()
                    if "unsafe" in issue_type and "unsafe" in line:
                        return i + 1, line.strip()
                    if "deserialization" in issue_type and "ObjectInputStream" in line:
                        return i + 1, line.strip()
            return "N/A", "Check logic in file."
        except: return "N/A", "N/A"

    def run_fuzzer(self, cmd_list, file_path):
        """Automated Fuzzing Engine to stress-test target binaries/scripts"""
        print(f"{Fore.BLUE}[*] Launching Automated Fuzzer on {os.path.basename(file_path)}...")
        fuzz_payloads = [
            "A" * 2048,                          # Buffer Overflow
            "%x %s %p %n" * 8,                   # Format String
            "'; whoami; cat /etc/passwd; '",     # Command Injection
            str(2147483647 + 1),                 # Integer Wrap
            "\x00\xff\x00\xff" * 10              # Binary/Null Injection
        ]
        
        for payload in fuzz_payloads:
            try:
                # Test via Arguments
                proc = subprocess.run(cmd_list + [payload], capture_output=True, timeout=1.5)
                if proc.returncode != 0 or "sanitizer" in (proc.stderr.decode().lower()):
                    return True, payload
                
                # Test via Stdin
                proc_in = subprocess.run(cmd_list, input=payload.encode(), capture_output=True, timeout=1.5)
                if proc_in.returncode != 0 or "sanitizer" in (proc_in.stderr.decode().lower()):
                    return True, payload
            except:
                continue
        return False, None

    def add_finding(self, filename, stage, finding_type):
        if filename not in self.report_data:
            self.report_data[filename] = []
        
        intel = VULN_INTEL.get(finding_type, {})
        line_num, snippet = self.get_vulnerable_line(filename, finding_type)
        
        severity = intel.get("level", "INFO")
        if severity in self.stats:
            self.stats[severity] += 1

        self.report_data[filename].append({
            "stage": stage,
            "issue": finding_type,
            "severity": severity,
            "cwe": intel.get("cwe", "N/A"),
            "cve": intel.get("cve", "N/A"),
            "cvss": intel.get("cvss", "N/A"),
            "description": intel.get("description", "Vulnerability detected during analysis."),
            "remediation": intel.get("fix", "Review security best practices."),
            "line": line_num,
            "snippet": snippet
        })

    def generate_html_report(self):
        filename_html = f"{self.output_base_name}.html"
        full_path_html = os.path.join(self.results_dir, filename_html)
        
        html_content = f"""
        <html>
        <head>
            <title>Deep Security Audit - {self.output_base_name}</title>
            <style>
                body {{ font-family: 'Segoe UI', sans-serif; background: #0c0c0c; color: #d0d0d0; padding: 40px; }}
                .header {{ border-bottom: 2px solid #333; padding-bottom: 10px; margin-bottom: 30px; }}
                .card {{ background: #181818; padding: 25px; margin-bottom: 20px; border-radius: 12px; border-left: 10px solid #cf6679; }}
                .tag {{ padding: 5px 12px; border-radius: 5px; font-weight: bold; margin-right: 10px; }}
                .CRITICAL {{ background: #ff1744; color: white; }}
                .HIGH {{ background: #ff9100; color: black; }}
                .MEDIUM {{ background: #039be5; color: white; }}
                .snippet {{ background: #000; color: #00ff00; padding: 15px; font-family: 'Courier New', monospace; border-radius: 5px; margin: 15px 0; border: 1px solid #333; overflow-x: auto; }}
                .meta-table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
                .meta-table td {{ padding: 8px; border-bottom: 1px solid #333; font-size: 0.9em; }}
                .label {{ color: #03dac6; font-weight: bold; width: 180px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ Deep Audit Report: {self.output_base_name.upper()}</h1>
                <p>Researcher: <b>{RESEARCHER_NAME}</b> | <a href="{GITHUB_REPO_URL}" style="color:#bb86fc;">GitHub Repo</a></p>
            </div>
        """
        for file, findings in self.report_data.items():
            html_content += f"<h2>File: {os.path.basename(file)}</h2>"
            for f in findings:
                html_content += f"""
                <div class="card">
                    <span class="tag {f['severity']}">{f['severity']}</span>
                    <b style="font-size: 1.2em; color: #ff5252;">{f['issue'].upper()}</b>
                    <p>{f['description']}</p>
                    <div class="snippet">Line {f['line']}: {f['snippet']}</div>
                    <table class="meta-table">
                        <tr><td class="label">Detection Stage</td><td>{f['stage']}</td></tr>
                        <tr><td class="label">CWE ID</td><td>{f['cwe']}</td></tr>
                        <tr><td class="label">CVE Reference</td><td>{f['cve']}</td></tr>
                        <tr><td class="label">CVSS Base Score</td><td>{f['cvss']}</td></tr>
                        <tr><td class="label">Remediation</td><td>{f['remediation']}</td></tr>
                    </table>
                </div>"""
        
        html_content += "</body></html>"
        with open(full_path_html, "w") as f: f.write(html_content)
        print(f"\n{Fore.GREEN}[✔] Deep Audit Dashboard generated: {Fore.WHITE}{full_path_html}")

    def save_final_summary(self):
        print(f"\n{Fore.CYAN}{'='*75}\n📊 FINAL AUDIT SCORECARD (v5.2 DEEP AUDIT)\n{Fore.CYAN}{'='*75}")
        for file, issues in self.report_data.items():
            print(f"{Fore.RED}{os.path.basename(file).ljust(35)} -> {'VULNERABLE' if issues else 'SECURE'}")
        self.generate_html_report()

# --- AUDIT MODULES ---

def audit_cpp(file_path, audit_obj):
    out_bin = "./temp_bin"
    ext = os.path.splitext(file_path)[1].lower()
    base_flags = ["-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
    cmd = ["g++" if ext in [".cpp", ".cc"] else "gcc"] + base_flags + [file_path, "-o", out_bin]

    if subprocess.run(cmd, capture_output=True).returncode == 0:
        crashed, payload = audit_obj.run_fuzzer([out_bin], file_path)
        if crashed:
            print(f"{Fore.RED}[!!!] FUZZER CRASH: Binary failed with payload: {payload[:20]}...")
            audit_obj.add_finding(file_path, "Fuzzing", "stack-buffer-overflow")
        else:
            print(f"{Fore.GREEN}[+] Fuzzer: Binary resisted all mutation payloads.")
    else:
        print(f"{Fore.RED}[-] Dynamic: Compilation failed for {os.path.basename(file_path)}")
    if os.path.exists(out_bin): os.remove(out_bin)

def audit_python(file_path, audit_obj):
    print(f"{Fore.YELLOW}[*] Running Bandit SAST & Automated Fuzzer on Python file...")
    crashed, _ = audit_obj.run_fuzzer(["python3", file_path], file_path)
    if crashed:
        print(f"{Fore.RED}[!!!] FUZZER CRASH: Python script failed on malicious input.")
        audit_obj.add_finding(file_path, "Fuzzing", "os-injection")
    try:
        res = subprocess.run(["bandit", "-q", "-f", "json", file_path], capture_output=True, text=True)
        if res.stdout:
            for issue in json.loads(res.stdout).get('results', []):
                audit_obj.add_finding(file_path, "SAST", "os-injection")
    except: pass

def audit_go(file_path, audit_obj):
    print(f"{Fore.YELLOW}[*] Running Go Race Detector & Fuzzer...")
    crashed, _ = audit_obj.run_fuzzer(["go", "run", "-race", file_path], file_path)
    if crashed:
        print(f"{Fore.RED}[!!!] Dynamic: GO Logic/Race failure confirmed.")
        audit_obj.add_finding(file_path, "Fuzzing", "race-condition")

def audit_rust(file_path, audit_obj):
    print(f"{Fore.YELLOW}[*] Running Rust Safety Audit...")
    with open(file_path, 'r') as f:
        if "unsafe" in f.read():
            print(f"{Fore.RED}[!!!] Static: Potential UNSAFE-BLOCK detected.")
            audit_obj.add_finding(file_path, "Static", "unsafe-block")

def audit_java(file_path, audit_obj):
    print(f"{Fore.YELLOW}[*] Static Analyzing Java patterns...")
    with open(file_path, 'r') as f:
        if "ObjectInputStream" in f.read():
            print(f"{Fore.RED}[!!!] Static: INSECURE-DESERIALIZATION pattern found.")
            audit_obj.add_finding(file_path, "Static", "insecure-deserialization")

def analyze_file(file_path, audit_obj):
    audit_obj.stats["scanned"] += 1
    ext = os.path.splitext(file_path)[1].lower()
    print(f"\n{Fore.MAGENTA}┌{'─'*65}┐\n│ ANALYZING: {os.path.basename(file_path).ljust(54)} │\n└{'─'*65}┘")
    if ext in [".c", ".cpp", ".cc"]: audit_cpp(file_path, audit_obj)
    elif ext == ".py": audit_python(file_path, audit_obj)
    elif ext == ".go": audit_go(file_path, audit_obj)
    elif ext == ".rs": audit_rust(file_path, audit_obj)
    elif ext == ".java": audit_java(file_path, audit_obj)

if __name__ == "__main__":
    print(f"{Fore.CYAN}🛡️  OVERFLOW GUARD v5.2 | Researcher: {RESEARCHER_NAME}")
    path_input = input("Enter Path/File: ").strip()
    if not os.path.exists(path_input):
        print(f"{Fore.RED}[x] Path does not exist!"); sys.exit(1)
    audit = AuditManager(path_input)
    if os.path.isdir(path_input):
        for root, _, files in os.walk(path_input):
            for f in files:
                if f.endswith((".c", ".cpp", ".cc", ".py", ".go", ".rs", ".java")):
                    analyze_file(os.path.join(root, f), audit)
    elif os.path.isfile(path_input):
        analyze_file(path_input, audit)
    audit.save_final_summary()
