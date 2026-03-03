import subprocess
import os
import sys
import json
import datetime
from colorama import init, Fore, Style

# Load Security Intelligence
try:
    from vulnerability_db import VULN_DATA as VULN_INTEL
except ImportError:
    VULN_INTEL = {}

init(autoreset=True)

# --- CONFIGURATION ---
RESEARCHER_NAME = "Parag Vinod Bagade"
GITHUB_REPO_URL = "https://github.com/parag-bagade/OverflowGuard"

class AuditManager:
    def __init__(self):
        self.report_data = {}
        self.stats = {"scanned": 0, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        self.scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def add_finding(self, filename, stage, finding_type):
        if filename not in self.report_data:
            self.report_data[filename] = []
        intel = VULN_INTEL.get(finding_type, {"cwe": "N/A", "level": "INFO", "fix": "Review logic."})
        
        severity = intel.get("level", "INFO")
        if severity in self.stats:
            self.stats[severity] += 1

        self.report_data[filename].append({
            "stage": stage,
            "issue": finding_type,
            "severity": severity,
            "cwe": intel.get("cwe"),
            "remediation": intel.get("fix")
        })

    def save_final_summary(self):
        print(f"\n{Fore.CYAN}{'='*70}\n{Fore.CYAN}📊 AUDIT SUMMARY SCORECARD\n{Fore.CYAN}{'='*70}")
        for file, issues in self.report_data.items():
            status = f"{Fore.RED}VULNERABLE ({len(issues)} issues)" if issues else f"{Fore.GREEN}SECURE"
            print(f"{Fore.WHITE}{os.path.basename(file).ljust(25)} -> {status}")
        
        print(f"\n{Fore.CYAN}{'-'*70}")
        print(f"{Fore.RED}CRITICAL: {self.stats['CRITICAL']}   "
              f"{Fore.YELLOW}HIGH: {self.stats['HIGH']}   "
              f"{Fore.BLUE}MEDIUM: {self.stats['MEDIUM']}   "
              f"{Fore.GREEN}TOTAL SCANNED: {self.stats['scanned']}")
        print(f"{Fore.CYAN}{'='*70}")

        self.generate_html_report()

    def generate_html_report(self):
        filename_html = "overflow_guard_report.html"
        html_content = f"""
        <html>
        <head>
            <title>Audit Report - {RESEARCHER_NAME}</title>
            <style>
                body {{ font-family: sans-serif; background: #0c0c0c; color: #d0d0d0; padding: 40px; }}
                .stat-grid {{ display: flex; gap: 20px; margin: 20px 0; }}
                .stat-item {{ padding: 20px; border-radius: 8px; flex: 1; text-align: center; font-weight: bold; border-bottom: 5px solid; }}
                .CRITICAL {{ background: #2a0005; border-color: #ff1744; color: #ff1744; }}
                .HIGH {{ background: #2a1b00; border-color: #ff9100; color: #ff9100; }}
                .card {{ background: #181818; padding: 20px; margin-bottom: 15px; border-radius: 10px; border-left: 10px solid; }}
                .vulnerable {{ border-color: #cf6679; }}
                .secure {{ border-color: #03dac6; }}
            </style>
        </head>
        <body>
            <h1>🛡️ Overflow Guard Audit Report</h1>
            <p>Researcher: <b>{RESEARCHER_NAME}</b> | Date: {self.scan_date}</p>
            <div class="stat-grid">
                <div class="stat-item CRITICAL">CRITICAL<br>{self.stats['CRITICAL']}</div>
                <div class="stat-item HIGH">HIGH<br>{self.stats['HIGH']}</div>
                <div class="stat-item secure">SECURE<br>{self.stats['scanned'] - (1 if any(self.report_data.values()) else 0)}</div>
            </div>
        """
        for file, issues in self.report_data.items():
            status_class = "vulnerable" if issues else "secure"
            html_content += f'<div class="card {status_class}"><h3>File: {os.path.basename(file)}</h3>'
            for issue in issues:
                html_content += f"<p><b style='color:#ff1744;'>[{issue['severity']}]</b> {issue['issue'].upper()} (CWE: {issue['cwe']})<br><i>Fix: {issue['remediation']}</i></p>"
            if not issues: html_content += "<p>No vulnerabilities detected.</p>"
            html_content += "</div>"
        html_content += "</body></html>"
        
        with open(filename_html, "w") as f: f.write(html_content)
        print(f"\n{Fore.GREEN}[✔] Full Dashboard: {os.path.abspath(filename_html)}")

audit = AuditManager()

def analyze_file(file_path):
    audit.stats["scanned"] += 1
    filename = os.path.basename(file_path)
    ext = os.path.splitext(filename)[1].lower()
    
    print(f"\n{Fore.MAGENTA}┌{'─'*58}┐\n│ SCANNING: {filename.ljust(47)} │\n└{'─'*58}┘")

    out_bin = "./temp_bin"
    base_flags = ["-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"]
    
    cmd = ["g++" if ext in [".cpp", ".cc"] else "gcc"] + base_flags + \
          (["-x", "c++"] if ext in [".cpp", ".cc"] else ["-Wno-implicit-function-declaration"]) + \
          [file_path, "-o", out_bin]

    comp = subprocess.run(cmd, capture_output=True, text=True)
    
    if comp.returncode == 0:
        detected = False
        for i in range(1, 11):
            exe = subprocess.run([out_bin], capture_output=True, text=True)
            err = exe.stderr.lower()
            if "addresssanitizer" in err or "runtime error" in err:
                for v_key in VULN_INTEL.keys():
                    if v_key.replace("-", " ") in err or v_key in err:
                        print(f"{Fore.RED}[!!!] Dynamic: {v_key.upper()} confirmed on cycle {i}.")
                        audit.add_finding(file_path, "Dynamic", v_key)
                        detected = True; break
                if not detected:
                    print(f"{Fore.RED}[!!!] Dynamic: UNDEFINED BEHAVIOR detected.")
                    audit.add_finding(file_path, "Dynamic", "integer-overflow")
                    detected = True
            if detected: break
        if not detected: print(f"{Fore.GREEN}[+] Dynamic: Passed all testing cycles.")
    else:
        print(f"{Fore.RED}[-] Dynamic: Compilation failed.")
    if os.path.exists(out_bin): os.remove(out_bin)

if __name__ == "__main__":
    print(f"Made By : Parag Bagade")
    path = input("Enter Path/File: ").strip()
    files = [os.path.join(path, f) for f in os.listdir(path) if f.endswith((".c", ".cpp"))] if os.path.isdir(path) else [path]
    for f in files: analyze_file(f)
    audit.save_final_summary()
