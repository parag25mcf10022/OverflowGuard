import subprocess
import os
import sys
import json
import datetime
import random
from colorama import init, Fore, Style
import re
import html as html_module

from ast_analyzer import ASTAnalyzer, CLANG_AVAILABLE
from static_tools  import run_all as run_static_tools, is_available
from taint_analyzer import TaintAnalyzer
from deep_analyzer import DeepAnalyzer

# ── v7.0 advanced analysis modules ──────────────────────────────────────────
from dataflow import DataflowAnalyzer
from call_summary import CallSummaryDB
from symbolic_check import SymbolicChecker
from interprocedural_taint import InterproceduralAnalyzer
from build_integration import BuildIntegrator
from cache_manager import CacheManager
from concurrency_analyzer import ConcurrencyAnalyzer
from ml_filter import MLFilter
from llvm_analyzer import LLVMAnalyzer
from concolic_fuzzer import ConcolicFuzzer

# Shared singletons (created once per process)
_CACHE    = CacheManager(version="7.0")
_ML       = MLFilter()
_CALL_DB  = CallSummaryDB()


init(autoreset=True)

try:
    from vulnerability_db import VULN_DATA as VULN_INTEL
except ImportError:
    print(f"{Fore.YELLOW}[!] Warning: vulnerability_db.py not found. Fallback mode active.")
    VULN_INTEL = {}

# --- CONFIGURATION ---
RESEARCHER_NAME = "Parag Bagade"
GITHUB_REPO_URL = "https://github.com/parag25mcf10022/OverflowGuard"
VERSION = "v7.0"

class AuditManager:
    def __init__(self, target_input):
        self.report_data = {}
        self.stats = {"scanned": 0, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        self.scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # tracks (filename, issue_type, line) so we never report a duplicate
        self._seen: set = set()
        
        clean_target = target_input.rstrip(os.sep)
        self.output_base_name = os.path.basename(clean_target) if clean_target else "audit_report"
        
        self.results_dir = "results"
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)

    def get_vulnerable_line(self, file_path, issue_type):
        """Extracts the specific line of code likely responsible for the finding"""
        try:
            with open(file_path, 'r', errors='ignore') as f:
                lines = f.readlines()

                # Prepare regexes for common C/C++ issues
                dangerous_calls = [r"\bstrcpy\s*\(", r"\bstrcat\s*\(", r"\bsprintf\s*\(", r"\bgets\s*\(", r"\bscanf\s*\(", r"\bmemcpy\s*\("]
                malloc_pattern = re.compile(r"\bmalloc\s*\(|\bcalloc\s*\(|\brealloc\s*\(")
                local_array_decl = re.compile(r"\bchar\s+[a-zA-Z0-9_]+\s*\[\s*\d+")
                format_vuln = re.compile(r"\bprintf\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)")

                for i, line in enumerate(lines):
                    l = line.strip()
                    # C/C++ buffer overflows (static heuristics)
                    if any(re.search(p, l) for p in dangerous_calls):
                        # try to determine stack vs heap by looking upward a few lines
                        context = " ".join(lines[max(0, i-6):i+1])
                        if malloc_pattern.search(context):
                            return i+1, l + "  // likely heap-related call"
                        if local_array_decl.search(context):
                            return i+1, l + "  // likely stack/local buffer use"
                        return i+1, l

                    # Format-string vulnerability (using user-controlled format)
                    if format_vuln.search(l):
                        return i+1, l + "  // check format string usage"

                    # Generic python injection check (for Python files)
                    if "injection" in issue_type and ("subprocess" in l or "os.system" in l or "shell=True" in l):
                        return i+1, l

                    # Race or unsafe indicators
                    if "race" in issue_type and ("go" in file_path or "chan " in l):
                        return i+1, l
                    if "unsafe" in issue_type and "unsafe" in l:
                        return i+1, l
                    if "deserialization" in issue_type and "ObjectInputStream" in l:
                        return i+1, l

            return "N/A", "No specific line matched by heuristics."
        except Exception:
            return "N/A", "N/A"

    def run_fuzzer(self, cmd_list, file_path):
        """Automated Fuzzing Engine to stress-test target binaries/scripts"""
        print(f"{Fore.BLUE}[*] Launching Automated Fuzzer on {os.path.basename(file_path)}...")
        fuzz_payloads = [
            "A" * 2048,                                  # Buffer Overflow
            "A" * 512,                                   # Medium overflow
            "%x %s %p %n" * 8,                           # Format String
            "%08x." * 40,                                # Format string leak
            "'; whoami; cat /etc/passwd; '",             # Command Injection
            "`id`",                                      # Backtick injection
            "$(cat /etc/passwd)",                        # $() injection
            str(2147483647 + 1),                         # Integer Overflow wrap
            str(-1),                                     # Negative index
            str(0),                                      # Zero / div-by-zero
            "\x00" * 100,                               # Null byte injection
            "\x00\xff\x00\xff" * 10,                    # Binary injection
            "../../../etc/passwd",                       # Path traversal
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",  # Windows traversal
            "' OR '1'='1",                               # SQL injection
            "1; DROP TABLE users;",                      # SQL injection 2
            "<script>alert(1)</script>",                 # XSS
            "\n" * 1000,                                 # Line flood
            "x" * 65536,                                 # Large input
            "\r\n" * 500,                                # CRLF injection
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

    def add_finding(self, filename, stage, finding_type,
                    line_override=None, snippet_override=None,
                    note_override=None, confidence_override=None):
        if filename not in self.report_data:
            self.report_data[filename] = []

        intel = VULN_INTEL.get(finding_type, {})

        if line_override is not None:
            line_num, snippet = line_override, (snippet_override or "")
        else:
            line_num, snippet = self.get_vulnerable_line(filename, finding_type)

        # ---- Deduplicate: same issue on the same line is the same bug ----
        dedup_key = (filename, finding_type, line_num)
        if dedup_key in self._seen:
            return
        self._seen.add(dedup_key)

        severity = intel.get("level", "INFO")
        self.stats.setdefault(severity, 0)
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
            "snippet": snippet,
            "confidence": confidence_override or "Medium",
            "note": note_override or "",
        })

    def generate_html_report(self):
        filename_html = f"{self.output_base_name}.html"
        full_path_html = os.path.join(self.results_dir, filename_html)

        # ── severity → card accent colour
        SEV_COLOUR = {
            "CRITICAL": "#ff1744",
            "HIGH":     "#ff9100",
            "MEDIUM":   "#039be5",
            "LOW":      "#69f0ae",
            "INFO":     "#9e9e9e",
        }

        # ── collect totals for dashboard
        total_findings = sum(len(v) for v in self.report_data.values())
        sev_totals = {}
        stage_totals = {}
        for findings in self.report_data.values():
            for f in findings:
                sev_totals[f["severity"]] = sev_totals.get(f["severity"], 0) + 1
                stage_totals[f["stage"]]  = stage_totals.get(f["stage"],   0) + 1

        def bar(count, total, colour):
            pct = (count / total * 100) if total else 0
            return (f'<div style="background:#111;border-radius:4px;height:14px;width:100%;'
                    f'margin-top:5px;"><div style="background:{colour};width:{pct:.1f}%;'
                    f'height:14px;border-radius:4px;"></div></div>')

        # ── severity stat boxes
        stat_boxes = ""
        for sev, colour in SEV_COLOUR.items():
            cnt = sev_totals.get(sev, 0)
            stat_boxes += (f'<div class="stat-box" style="border-top:4px solid {colour};">'  
                           f'<div class="stat-num" style="color:{colour};">{cnt}</div>'
                           f'<div class="stat-label">{sev}</div></div>')

        # ── detection-stage breakdown table
        stage_rows = ""
        for stage, cnt in sorted(stage_totals.items(), key=lambda x: -x[1]):
            pct = cnt / total_findings * 100 if total_findings else 0
            stage_rows += (f'<tr><td>{stage}</td>'
                           f'<td>{cnt}</td>'
                           f'<td style="width:60%;">{bar(cnt, total_findings, "#bb86fc")}</td></tr>')

        # ── file-level summary table
        file_summary_rows = ""
        for fpath, findings in self.report_data.items():
            vulns = len(findings)
            worst = "SECURE"
            for order in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if any(f["severity"] == order for f in findings):
                    worst = order
                    break
            colour = SEV_COLOUR.get(worst, "#9e9e9e")
            status_label = (f'<span style="background:{colour};color:#000;'
                            f'padding:2px 10px;border-radius:4px;font-weight:bold;'
                            f'font-size:.75em;">{worst}</span>')
            file_summary_rows += (f'<tr><td>{html_module.escape(os.path.basename(fpath))}</td>'
                                  f'<td>{vulns}</td>'
                                  f'<td>{status_label}</td></tr>')

        # ── per-file finding cards
        cards_html = ""
        for fpath, findings in self.report_data.items():
            cards_html += (f'<h2 style="margin-top:40px;color:#eee;'
                           f'border-bottom:1px solid #333;padding-bottom:8px;">'
                           f'📄 {html_module.escape(os.path.basename(fpath))}</h2>')
            if not findings:
                cards_html += '<p style="color:#69f0ae;">✅ No findings.</p>'
                continue
            for f in findings:
                sev   = f["severity"]
                acc   = SEV_COLOUR.get(sev, "#9e9e9e")
                snip  = html_module.escape(str(f["snippet"]))
                note  = html_module.escape(str(f.get("note", "")))
                desc  = html_module.escape(str(f["description"]))
                remed = html_module.escape(str(f["remediation"]))
                conf  = f.get("confidence", "Medium")
                conf_colour = {"High": "#69f0ae", "Medium": "#ffd740", "Low": "#9e9e9e"}.get(conf, "#9e9e9e")
                cards_html += f"""
<div style="background:#181818;padding:22px 28px;margin-bottom:18px;
            border-radius:10px;border-left:8px solid {acc};">
  <div style="display:flex;align-items:center;gap:14px;margin-bottom:10px;">
    <span style="background:{acc};color:#000;padding:3px 12px;
                border-radius:4px;font-weight:700;font-size:.8em;">{sev}</span>
    <span style="font-size:1.15em;font-weight:700;color:#ff5252;">{html_module.escape(f['issue'].upper())}</span>
    <span style="background:{conf_colour};color:#000;padding:3px 10px;
                border-radius:4px;font-weight:700;font-size:.75em;">{conf.upper()} CONFIDENCE</span>
  </div>
  <p style="color:#bbb;margin:0 0 12px;">{desc}</p>
  {'<p style="color:#aaa;font-size:.85em;font-style:italic;">' + note + '</p>' if note else ''}
  <div style="background:#000;color:#00ff00;padding:12px 16px;
              font-family:Courier New,monospace;border-radius:6px;
              border:1px solid #333;overflow-x:auto;font-size:.9em;
              margin-bottom:12px;">Line {f['line']}: {snip}</div>
  <table style="width:100%;border-collapse:collapse;font-size:.88em;">
    <tr><td style="color:#03dac6;font-weight:700;width:170px;padding:6px 0;border-bottom:1px solid #2a2a2a;">Detection Stage</td><td style="padding:6px 0;border-bottom:1px solid #2a2a2a;">{html_module.escape(f['stage'])}</td></tr>
    <tr><td style="color:#03dac6;font-weight:700;padding:6px 0;border-bottom:1px solid #2a2a2a;">CWE</td><td style="padding:6px 0;border-bottom:1px solid #2a2a2a;">{html_module.escape(str(f['cwe']))}</td></tr>
    <tr><td style="color:#03dac6;font-weight:700;padding:6px 0;border-bottom:1px solid #2a2a2a;">CVE</td><td style="padding:6px 0;border-bottom:1px solid #2a2a2a;">{html_module.escape(str(f['cve']))}</td></tr>
    <tr><td style="color:#03dac6;font-weight:700;padding:6px 0;border-bottom:1px solid #2a2a2a;">CVSS</td><td style="padding:6px 0;border-bottom:1px solid #2a2a2a;">{html_module.escape(str(f['cvss']))}</td></tr>
    <tr><td style="color:#03dac6;font-weight:700;padding:6px 0;">Remediation</td><td style="padding:6px 0;">{remed}</td></tr>
  </table>
</div>"""

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>OverflowGuard Report — {html_module.escape(self.output_base_name)}</title>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0;}}
    body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0c0c0c;color:#d0d0d0;
          padding:40px;max-width:1100px;margin:auto;line-height:1.55;}}
    a{{color:#bb86fc;}}
    h2{{font-size:1.1em;}}
    .header{{border-bottom:2px solid #333;padding-bottom:16px;margin-bottom:30px;}}
    .header h1{{font-size:1.6em;color:#fff;margin-bottom:6px;}}
    .meta{{font-size:.85em;color:#888;}}
    /* stat boxes */
    .stat-row{{display:flex;gap:16px;flex-wrap:wrap;margin:24px 0;}}
    .stat-box{{background:#161616;border-radius:10px;padding:18px 24px;
               flex:1;min-width:110px;text-align:center;}}
    .stat-num{{font-size:2em;font-weight:700;}}
    .stat-label{{font-size:.75em;color:#888;margin-top:4px;letter-spacing:.05em;text-transform:uppercase;}}
    /* tables */
    .section-title{{font-size:1em;font-weight:700;color:#bb86fc;
                    text-transform:uppercase;letter-spacing:.08em;
                    margin:30px 0 12px;}}
    table.summary{{width:100%;border-collapse:collapse;font-size:.88em;margin-bottom:28px;}}
    table.summary th{{text-align:left;color:#888;font-weight:600;
                      border-bottom:2px solid #333;padding:8px 12px;}}
    table.summary td{{padding:8px 12px;border-bottom:1px solid #222;}}
    table.summary tr:hover td{{background:#1a1a1a;}}
  </style>
</head>
<body>

<div class="header">
  <h1>🛡️ OverflowGuard — {html_module.escape(self.output_base_name.upper())}</h1>
  <p class="meta">
    Researcher: <b style="color:#eee;">{html_module.escape(RESEARCHER_NAME)}</b> &nbsp;|    Version: <b style="color:#bb86fc;">{VERSION}</b> &nbsp;|    Scan date: {self.scan_date} &nbsp;|
    <a href="{GITHUB_REPO_URL}">GitHub Repo</a>
  </p>
</div>

<!-- ── Dashboard ── -->
<div class="section-title">📊 Severity Breakdown</div>
<div class="stat-row">
  <div class="stat-box" style="border-top:4px solid #9e9e9e;">
    <div class="stat-num" style="color:#ccc;">{self.stats['scanned']}</div>
    <div class="stat-label">Files Scanned</div>
  </div>
  <div class="stat-box" style="border-top:4px solid #9e9e9e;">
    <div class="stat-num" style="color:#ccc;">{total_findings}</div>
    <div class="stat-label">Total Findings</div>
  </div>
  {stat_boxes}
</div>

<!-- ── Detection Stage Breakdown ── -->
<div class="section-title">🔍 Detection Stage Breakdown</div>
<table class="summary">
  <thead><tr><th>Stage</th><th>Count</th><th>Proportion</th></tr></thead>
  <tbody>{stage_rows}</tbody>
</table>

<!-- ── File Summary ── -->
<div class="section-title">📁 File Summary</div>
<table class="summary">
  <thead><tr><th>File</th><th>Findings</th><th>Worst Severity</th></tr></thead>
  <tbody>{file_summary_rows}</tbody>
</table>

<!-- ── Detailed Findings ── -->
<div class="section-title">🔎 Detailed Findings</div>
{cards_html}

</body>
</html>
"""
        with open(full_path_html, "w") as fh:
            fh.write(html_content)
        print(f"\n{Fore.GREEN}[✔] Report: {Fore.WHITE}{full_path_html}")

    def save_final_summary(self):
        W = 78   # total table width

        # ── helpers ──────────────────────────────────────────────────────────
        SEV_COLOUR = {
            "CRITICAL": Fore.RED,
            "HIGH":     Fore.YELLOW,
            "MEDIUM":   Fore.CYAN,
            "LOW":      Fore.GREEN,
        }

        def sev_badge(sev: str) -> str:
            c = SEV_COLOUR.get(sev, Fore.WHITE)
            return f"{c}{sev}{Style.RESET_ALL}"

        def hline(char="─"):
            print(f"{Fore.CYAN}{char * W}{Style.RESET_ALL}")

        # ── header ───────────────────────────────────────────────────────────
        print()
        hline("═")
        title = f"📊  OVERFLOW GUARD — FINAL AUDIT SCORECARD  ({VERSION})"
        print(f"{Fore.CYAN}{title.center(W)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{self.scan_date.center(W)}{Style.RESET_ALL}")
        hline("═")

        # ── collect per-file stats ────────────────────────────────────────────
        vulnerable_files = []
        safe_files       = []

        for fpath, findings in self.report_data.items():
            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for f in findings:
                counts[f["severity"]] = counts.get(f["severity"], 0) + 1
            entry = (fpath, findings, counts)
            if findings:
                vulnerable_files.append(entry)
            else:
                safe_files.append(entry)

        total_files    = self.stats["scanned"]
        total_findings = sum(len(f) for _, f, _ in vulnerable_files + safe_files)

        # ── per-file detail table ─────────────────────────────────────────────
        col_file = 30
        col_tot  = 8
        col_sev  = 10   # per severity column

        header = (
            f"{'FILE':<{col_file}} {'FINDS':>{col_tot}}"
            f"  {'CRIT':>{col_sev}}{'HIGH':>{col_sev}}"
            f"{'MED':>{col_sev}}{'LOW':>{col_sev}}"
            f"  {'STATUS'}"
        )
        hline()
        print(f"{Fore.WHITE}{Style.BRIGHT}{header}{Style.RESET_ALL}")
        hline()

        def print_row(fpath, findings, counts):
            name   = os.path.basename(fpath)[:col_file]
            total  = len(findings)
            crit   = counts.get("CRITICAL", 0)
            high   = counts.get("HIGH",     0)
            med    = counts.get("MEDIUM",   0)
            low    = counts.get("LOW",      0)

            status_colour = Fore.GREEN if not findings else (
                Fore.RED    if crit else
                Fore.YELLOW if high else
                Fore.CYAN
            )
            status = "✅ SECURE" if not findings else "⚠  VULNERABLE"

            crit_s = f"{Fore.RED}{crit:>{col_sev}}{Style.RESET_ALL}"   if crit else f"{'—':>{col_sev}}"
            high_s = f"{Fore.YELLOW}{high:>{col_sev}}{Style.RESET_ALL}" if high else f"{'—':>{col_sev}}"
            med_s  = f"{Fore.CYAN}{med:>{col_sev}}{Style.RESET_ALL}"    if med  else f"{'—':>{col_sev}}"
            low_s  = f"{Fore.GREEN}{low:>{col_sev}}{Style.RESET_ALL}"   if low  else f"{'—':>{col_sev}}"

            print(
                f"{Fore.WHITE}{name:<{col_file}}{Style.RESET_ALL}"
                f" {Fore.WHITE}{total:>{col_tot}}{Style.RESET_ALL}"
                f"  {crit_s}{high_s}{med_s}{low_s}"
                f"  {status_colour}{status}{Style.RESET_ALL}"
            )

        for entry in vulnerable_files:
            print_row(*entry)
        for entry in safe_files:
            print_row(*entry)

        # ── totals row ────────────────────────────────────────────────────────
        hline()
        total_crit = self.stats.get("CRITICAL", 0)
        total_high = self.stats.get("HIGH",     0)
        total_med  = self.stats.get("MEDIUM",   0)
        total_low  = self.stats.get("LOW",      0)

        t_crit_s = f"{Fore.RED}{total_crit:>{col_sev}}{Style.RESET_ALL}"     if total_crit else f"{'—':>{col_sev}}"
        t_high_s = f"{Fore.YELLOW}{total_high:>{col_sev}}{Style.RESET_ALL}"  if total_high else f"{'—':>{col_sev}}"
        t_med_s  = f"{Fore.CYAN}{total_med:>{col_sev}}{Style.RESET_ALL}"     if total_med  else f"{'—':>{col_sev}}"
        t_low_s  = f"{Fore.GREEN}{total_low:>{col_sev}}{Style.RESET_ALL}"    if total_low  else f"{'—':>{col_sev}}"

        print(
            f"{Fore.WHITE}{'TOTAL':<{col_file}}{Style.RESET_ALL}"
            f" {Fore.WHITE}{total_findings:>{col_tot}}{Style.RESET_ALL}"
            f"  {t_crit_s}{t_high_s}{t_med_s}{t_low_s}"
        )
        hline("═")

        # ── summary banner ────────────────────────────────────────────────────
        n_vuln = len(vulnerable_files)
        n_safe = len(safe_files)

        print(
            f"\n  Files scanned   : {Fore.WHITE}{Style.BRIGHT}{total_files}{Style.RESET_ALL}"
            f"\n  Vulnerable      : {Fore.RED}{Style.BRIGHT}{n_vuln}{Style.RESET_ALL}"
            f"\n  Safe            : {Fore.GREEN}{Style.BRIGHT}{n_safe}{Style.RESET_ALL}"
            f"\n  Total findings  : {Fore.YELLOW}{Style.BRIGHT}{total_findings}{Style.RESET_ALL}"
            f"  ({Fore.RED}CRIT:{total_crit}{Style.RESET_ALL}"
            f"  {Fore.YELLOW}HIGH:{total_high}{Style.RESET_ALL}"
            f"  {Fore.CYAN}MED:{total_med}{Style.RESET_ALL}"
            f"  {Fore.GREEN}LOW:{total_low}{Style.RESET_ALL})"
        )
        hline("═")

        self.generate_html_report()

# --- AUDIT MODULES ---

def audit_cpp(file_path, audit_obj):
    out_bin = "./temp_bin"
    ext = os.path.splitext(file_path)[1].lower()
    base_flags = ["-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
    cmd = ["g++" if ext in [".cpp", ".cc"] else "gcc"] + base_flags + [file_path, "-o", out_bin]
    # --- Stage 1: AST / regex-based sink–source analysis ---
    ast_label = "AST" if CLANG_AVAILABLE else "AST(regex)"
    ast_findings = ASTAnalyzer(file_path).analyze()
    for af in ast_findings:
        print(f"{Fore.RED}[!!!] {ast_label}: [{af.confidence}] {af.issue_type} "
              f"@ line {af.line} — {af.note}")
        audit_obj.add_finding(file_path, ast_label, af.issue_type,
                              line_override=af.line,
                              snippet_override=af.snippet,
                              note_override=af.note,
                              confidence_override=af.confidence)

    # --- Stage 1b: Taint analysis ---
    taint_findings = TaintAnalyzer().analyze(file_path)
    for tf in taint_findings:
        print(f"{Fore.RED}[!!!] Taint [{tf.confidence}] {tf.issue_type} "
              f"@ line {tf.line} — {tf.note}")
        audit_obj.add_finding(file_path, "Taint", tf.issue_type,
                              line_override=tf.line,
                              snippet_override=tf.snippet,
                              note_override=tf.note,
                              confidence_override=tf.confidence)

    # --- Stage 1c: Deep multi-pass inter-procedural analysis ---
    deep_findings = DeepAnalyzer().analyze(file_path)
    for df in deep_findings:
        print(f"{Fore.RED}[!!!] Deep [{df.confidence}] {df.issue_type} "
              f"@ line {df.line} — {df.note[:120]}")
        audit_obj.add_finding(file_path, "Deep", df.issue_type,
                              line_override=df.line,
                              snippet_override=df.snippet,
                              note_override=df.note,
                              confidence_override=df.confidence)

    # --- Stage 1d: Intra-procedural data-flow with sanitizer recognition ---
    df_findings = DataflowAnalyzer().analyze(file_path)
    df_findings  = _ML.filter(df_findings)
    for ff in df_findings:
        print(f"{Fore.RED}[!!!] Dataflow [{ff.confidence}] {ff.issue_type} "
              f"@ line {ff.line} — {ff.note[:120]}")
        audit_obj.add_finding(file_path, "Dataflow", ff.issue_type,
                              line_override=ff.line,
                              snippet_override=ff.snippet,
                              note_override=ff.note,
                              confidence_override=ff.confidence)

    # --- Stage 1e: Inter-procedural call-graph taint propagation ---
    ip_findings = InterproceduralAnalyzer().analyze_file(file_path)
    ip_findings  = _ML.filter(ip_findings)
    for ipf in ip_findings:
        print(f"{Fore.RED}[!!!] InterProc [{ipf.confidence}] {ipf.issue_type} "
              f"@ line {ipf.line} — {ipf.note[:120]}")
        audit_obj.add_finding(file_path, "Interprocedural", ipf.issue_type,
                              line_override=ipf.line,
                              snippet_override=ipf.snippet,
                              note_override=ipf.note,
                              confidence_override=ipf.confidence)

    # --- Stage 1f: Symbolic range-propagation (Z3 if available, else interval) ---
    sym_findings = SymbolicChecker().analyze(file_path)
    sym_findings  = _ML.filter(sym_findings)
    for sf in sym_findings:
        print(f"{Fore.CYAN}[~] Symbolic [{sf.confidence}] {sf.issue_type} "
              f"@ line {sf.line} — {sf.note[:120]}")
        audit_obj.add_finding(file_path, "Symbolic", sf.issue_type,
                              line_override=sf.line,
                              snippet_override=sf.snippet,
                              note_override=sf.note,
                              confidence_override=sf.confidence)

    # --- Stage 1g: Concurrency bug detection ---
    conc_findings = ConcurrencyAnalyzer().analyze(file_path)
    conc_findings  = _ML.filter(conc_findings)
    for cf in conc_findings:
        print(f"{Fore.MAGENTA}[T] Concurrency [{cf.confidence}] {cf.issue_type} "
              f"@ line {cf.line} — {cf.note[:120]}")
        audit_obj.add_finding(file_path, "Concurrency", cf.issue_type,
                              line_override=cf.line,
                              snippet_override=cf.snippet,
                              note_override=cf.note,
                              confidence_override=cf.confidence)

    # --- Stage 1h: LLVM IR analysis (runs only when clang is on PATH) ---
    if LLVMAnalyzer.is_available():
        llvm_findings = LLVMAnalyzer().analyze(file_path)
        llvm_findings  = _ML.filter(llvm_findings)
        for lf in llvm_findings:
            print(f"{Fore.RED}[!!!] LLVM [{lf.confidence}] {lf.issue_type} "
                  f"@ line {lf.line} — {lf.note[:120]}")
            audit_obj.add_finding(file_path, "LLVM", lf.issue_type,
                                  line_override=lf.line,
                                  snippet_override=lf.snippet,
                                  note_override=lf.note,
                                  confidence_override=lf.confidence)

    # --- Stage 2: cppcheck + clang-tidy ---
    tool_findings = run_static_tools(file_path)
    for tf in tool_findings:
        vtype = tf.mapped_type or tf.issue_id
        label = f"Static({tf.tool})"
        print(f"{Fore.YELLOW}[!] {tf.tool}: [{tf.severity}] {tf.message} @ line {tf.line}")
        audit_obj.add_finding(file_path, label, vtype,
                              line_override=tf.line,
                              snippet_override="",
                              note_override=tf.message)

    # --- Stage 2b: Concolic / hybrid fuzzing (Tier 1=angr, 2=AFL, 3=heuristic) ---
    conc_fuzz_findings = ConcolicFuzzer().fuzz(file_path)
    for czf in conc_fuzz_findings:
        print(f"{Fore.RED}[!!!] Concolic [{czf.confidence}] {czf.issue_type} "
              f"@ line {czf.line} — {czf.note[:120]}")
        audit_obj.add_finding(file_path, "Concolic", czf.issue_type,
                              line_override=czf.line,
                              snippet_override=czf.snippet,
                              note_override=czf.note,
                              confidence_override=czf.confidence)

    # Try to compile with sanitizers and run dynamic fuzzing
    proc_compile = subprocess.run(cmd, capture_output=True)
    if proc_compile.returncode == 0:
        crashed, payload = audit_obj.run_fuzzer([out_bin], file_path)
        if crashed:
            # Attempt to detect ASAN-style messages for classification
            # run the binary once with the payload to capture stderr
            try:
                proc = subprocess.run([out_bin, payload], capture_output=True, timeout=2)
            except Exception:
                proc = None

            asan_msg = ""
            if proc and proc.stderr:
                asan_msg = proc.stderr.decode(errors='ignore').lower()

            if "addresssanitizer" in asan_msg or "stack-buffer-overflow" in asan_msg:
                issue = "stack-buffer-overflow"
            elif "heap-buffer-overflow" in asan_msg:
                issue = "heap-buffer-overflow"
            else:
                # fallback to conservative label
                issue = "buffer-overflow"

            print(f"{Fore.RED}[!!!] FUZZER CRASH: Binary failed with payload: {payload[:20]}...")
            audit_obj.add_finding(file_path, "Fuzzing", issue)
        else:
            print(f"{Fore.GREEN}[+] Fuzzer: Binary resisted all mutation payloads.")
    else:
        print(f"{Fore.RED}[-] Dynamic: Compilation failed for {os.path.basename(file_path)}")
        # print compiler output for debugging
        if proc_compile.stderr:
            print(proc_compile.stderr.decode(errors='ignore'))
    if os.path.exists(out_bin): os.remove(out_bin)

def audit_python(file_path, audit_obj):
    print(f"{Fore.YELLOW}[*] Running Bandit SAST, Taint Analysis & Fuzzer on Python file...")

    # --- Taint analysis ---
    taint_findings = TaintAnalyzer().analyze(file_path)
    for tf in taint_findings:
        print(f"{Fore.RED}[!!!] Taint [{tf.confidence}] {tf.issue_type} "
              f"@ line {tf.line} — {tf.note}")
        audit_obj.add_finding(file_path, "Taint", tf.issue_type,
                              line_override=tf.line,
                              snippet_override=tf.snippet,
                              note_override=tf.note,
                              confidence_override=tf.confidence)

    crashed, _ = audit_obj.run_fuzzer(["python3", file_path], file_path)
    if crashed:
        print(f"{Fore.RED}[!!!] FUZZER CRASH: Python script failed on malicious input.")
        audit_obj.add_finding(file_path, "Fuzzing", "os-injection")
    try:
        res = subprocess.run(["bandit", "-q", "-f", "json", file_path],
                             capture_output=True, text=True)
        if res.stdout:
            data = json.loads(res.stdout)
            seen_types: set = set()
            for issue in data.get('results', []):
                # Map Bandit test IDs to our VULN_DATA where possible
                test_id   = issue.get("test_id", "")
                vuln_type = _bandit_map(test_id)
                line_num  = issue.get("line_number", "N/A")
                msg       = issue.get("issue_text", "")
                dedup_key = (vuln_type, line_num)
                if dedup_key in seen_types:
                    continue
                seen_types.add(dedup_key)
                print(f"{Fore.RED}[!!!] Bandit [{test_id}]: {msg} @ line {line_num}")
                audit_obj.add_finding(file_path, "SAST(bandit)", vuln_type,
                                      line_override=line_num,
                                      snippet_override=issue.get("code", "").strip(),
                                      note_override=msg)
    except Exception:
        pass


_BANDIT_MAP = {
    # OS / Command injection
    "B102": "os-injection",
    "B103": "os-injection",
    "B104": "os-injection",
    "B108": "insecure-temp-file",
    "B306": "insecure-temp-file",
    "B601": "os-command-injection",
    "B602": "os-command-injection",
    "B603": "os-command-injection",
    "B604": "os-command-injection",
    "B605": "os-command-injection",
    "B607": "os-command-injection",
    # Hardcoded secrets
    "B105": "hardcoded-password",
    "B106": "hardcoded-password",
    "B107": "hardcoded-password",
    # Deserialization
    "B301": "insecure-deserialization",
    "B302": "insecure-deserialization",
    "B303": "weak-crypto",
    "B304": "weak-crypto",
    "B305": "weak-crypto",
    "B324": "weak-crypto",
    # Eval
    "B307": "insecure-eval",
    "B322": "insecure-eval",
    # Crypto weak
    "B311": "weak-rng",
    "B323": "insecure-tls",
    "B501": "insecure-tls",
    "B502": "insecure-tls",
    "B503": "insecure-tls",
    "B504": "insecure-tls",
    "B505": "weak-crypto",
    "B506": "insecure-deserialization",  # yaml.load
    # SQL
    "B608": "sql-injection",
    # Path traversal
    "B101": "insecure-config",  # assert used for security
    "B110": "insecure-config",  # try/except pass
    "B404": "os-command-injection",  # import subprocess
}


def _bandit_map(test_id: str) -> str:
    return _BANDIT_MAP.get(test_id, "os-injection")

def audit_go(file_path, audit_obj):
    print(f"{Fore.YELLOW}[*] Running Go Race Detector, Taint Analysis & Fuzzer...")

    # Taint analysis
    taint_findings = TaintAnalyzer().analyze(file_path)
    for tf in taint_findings:
        print(f"{Fore.RED}[!!!] Taint [{tf.confidence}] {tf.issue_type} "
              f"@ line {tf.line} — {tf.note}")
        audit_obj.add_finding(file_path, "Taint", tf.issue_type,
                              line_override=tf.line,
                              snippet_override=tf.snippet,
                              note_override=tf.note,
                              confidence_override=tf.confidence)

    crashed, _ = audit_obj.run_fuzzer(["go", "run", "-race", file_path], file_path)
    if crashed:
        print(f"{Fore.RED}[!!!] Dynamic: GO Logic/Race failure confirmed.")
        audit_obj.add_finding(file_path, "Fuzzing", "race-condition")

def audit_rust(file_path, audit_obj):
    print(f"{Fore.YELLOW}[*] Running Rust Safety Audit & Taint Analysis...")

    # Taint analysis
    taint_findings = TaintAnalyzer().analyze(file_path)
    for tf in taint_findings:
        print(f"{Fore.RED}[!!!] Taint [{tf.confidence}] {tf.issue_type} "
              f"@ line {tf.line} — {tf.note}")
        audit_obj.add_finding(file_path, "Taint", tf.issue_type,
                              line_override=tf.line,
                              snippet_override=tf.snippet,
                              note_override=tf.note,
                              confidence_override=tf.confidence)

    with open(file_path, 'r') as f:
        content = f.read()
    if "unsafe" in content:
        print(f"{Fore.RED}[!!!] Static: Potential UNSAFE-BLOCK detected.")
        audit_obj.add_finding(file_path, "Static", "unsafe-block")
    if "mem::transmute" in content:
        print(f"{Fore.RED}[!!!] Static: mem::transmute() — extremely unsafe type cast.")
        audit_obj.add_finding(file_path, "Static", "unsafe-block",
                              note_override="mem::transmute found — reinterprets bits without safety")

def audit_java(file_path, audit_obj):
    print(f"{Fore.YELLOW}[*] Static Analyzing Java patterns + Taint Analysis...")

    # Taint analysis
    taint_findings = TaintAnalyzer().analyze(file_path)
    for tf in taint_findings:
        print(f"{Fore.RED}[!!!] Taint [{tf.confidence}] {tf.issue_type} "
              f"@ line {tf.line} — {tf.note}")
        audit_obj.add_finding(file_path, "Taint", tf.issue_type,
                              line_override=tf.line,
                              snippet_override=tf.snippet,
                              note_override=tf.note,
                              confidence_override=tf.confidence)

    with open(file_path, 'r') as f:
        content = f.read()
    if "ObjectInputStream" in content:
        print(f"{Fore.RED}[!!!] Static: INSECURE-DESERIALIZATION pattern found.")
        audit_obj.add_finding(file_path, "Static", "insecure-deserialization")
    if re.search(r'Runtime\.getRuntime\(\)\.exec', content):
        print(f"{Fore.RED}[!!!] Static: Runtime.exec() — command injection risk.")
        audit_obj.add_finding(file_path, "Static", "os-command-injection")
    if re.search(r'getInstance\s*\(\s*["\'](?:MD5|SHA1|DES|RC4)["\']', content):
        print(f"{Fore.RED}[!!!] Static: Weak crypto algorithm detected.")
        audit_obj.add_finding(file_path, "Static", "weak-crypto")
    if re.search(r'new\s+Random\s*\(', content):
        print(f"{Fore.YELLOW}[!] Static: java.util.Random is not cryptographically secure.")
        audit_obj.add_finding(file_path, "Static", "weak-rng")

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
    print(f"\n{Fore.CYAN}🛡️  OVERFLOW GUARD {VERSION} | Researcher: {RESEARCHER_NAME}")
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
