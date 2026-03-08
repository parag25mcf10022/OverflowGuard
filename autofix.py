"""
autofix.py — Auto-fix / patch generation for OverflowGuard v11.0

Generates unified diff patches for known vulnerability types.
Uses the remediation patterns from remediation_db.py to produce
concrete code fixes that can be applied with `git apply`.

Copyright 2026 Parag Bagade — MIT Licence
"""

from __future__ import annotations
import os
import re
import difflib
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple

# ---------------------------------------------------------------------------
# Fix result dataclass
# ---------------------------------------------------------------------------

@dataclass
class AutoFix:
    file_path: str
    line: int
    issue_type: str
    original_line: str
    fixed_line: str
    explanation: str
    confidence: str = "Medium"    # High | Medium | Low
    diff_patch: str = ""          # unified diff fragment


# ---------------------------------------------------------------------------
# Fix patterns — maps issue_type → (regex, replacement_template, explanation)
# ---------------------------------------------------------------------------

_C_FIXES: List[Dict] = [
    {
        "issue": "stack-buffer-overflow",
        "patterns": [
            {
                "match": r'(\s*)gets\s*\(\s*(\w+)\s*\)\s*;',
                "replace": r'\1fgets(\2, sizeof(\2), stdin);',
                "explain": "Replace gets() with fgets() to prevent buffer overflow",
                "confidence": "High",
            },
        ],
    },
    {
        "issue": "stack-buffer-overflow",
        "patterns": [
            {
                "match": r'(\s*)strcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)\s*;',
                "replace": r'\1strncpy(\2, \3, sizeof(\2) - 1);\n\1\2[sizeof(\2) - 1] = \'\\0\';',
                "explain": "Replace strcpy() with strncpy() with bounds checking",
                "confidence": "High",
            },
        ],
    },
    {
        "issue": "buffer-overflow",
        "patterns": [
            {
                "match": r'(\s*)strcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)\s*;',
                "replace": r'\1strncpy(\2, \3, sizeof(\2) - 1);\n\1\2[sizeof(\2) - 1] = \'\\0\';',
                "explain": "Replace strcpy() with strncpy() with null termination",
                "confidence": "High",
            },
        ],
    },
    {
        "issue": "heap-buffer-overflow",
        "patterns": [
            {
                "match": r'(\s*)sprintf\s*\(\s*(\w+)\s*,\s*(".*?")\s*,\s*(.*?)\s*\)\s*;',
                "replace": r'\1snprintf(\2, sizeof(\2), \3, \4);',
                "explain": "Replace sprintf() with snprintf() for bounded formatting",
                "confidence": "High",
            },
        ],
    },
    {
        "issue": "format-string",
        "patterns": [
            {
                "match": r'(\s*)printf\s*\(\s*(\w+)\s*\)\s*;',
                "replace": r'\1printf("%s", \2);',
                "explain": "Add explicit format string to prevent format string attacks",
                "confidence": "High",
            },
        ],
    },
    {
        "issue": "os-command-injection",
        "patterns": [
            {
                "match": r'(\s*)system\s*\(\s*(\w+)\s*\)\s*;',
                "replace": r'\1/* WARNING: system() with user input is dangerous.\n\1   Use execve() with explicit argv[] instead. */\n\1system(\2);  /* REVIEW: sanitize input */',
                "explain": "Flag system() call for manual review — use execve() instead",
                "confidence": "Low",
            },
        ],
    },
    {
        "issue": "weak-rng",
        "patterns": [
            {
                "match": r'(\s*)(?:srand\s*\(\s*time\s*\(\s*(?:NULL|0)\s*\)\s*\)\s*;?\s*\n\s*)?(\w+)\s*=\s*rand\s*\(\s*\)\s*;',
                "replace": r'\1/* Use arc4random() or read from /dev/urandom for crypto-safe RNG */\n\1\2 = arc4random();',
                "explain": "Replace rand()/srand() with arc4random() for better randomness",
                "confidence": "Medium",
            },
        ],
    },
]

_PYTHON_FIXES: List[Dict] = [
    {
        "issue": "sql-injection",
        "patterns": [
            {
                "match": r'(\s*)cursor\.execute\s*\(\s*f["\'](.+?)\1\s*\)\s*',
                "replace": r'\1cursor.execute("SELECT ... WHERE col = %s", (param,))  # Use parameterized query',
                "explain": "Replace f-string SQL with parameterized query",
                "confidence": "Medium",
            },
            {
                "match": r'(\s*)cursor\.execute\s*\(\s*["\'].*?%s.*?["\']\s*%\s*(\w+)\s*\)',
                "replace": r'\1cursor.execute("... %s ...", (\2,))  # Already parameterized — verify tuple form',
                "explain": "Ensure SQL uses tuple parameterization, not string %",
                "confidence": "Medium",
            },
        ],
    },
    {
        "issue": "os-command-injection",
        "patterns": [
            {
                "match": r'(\s*)os\.system\s*\(\s*(.+?)\s*\)',
                "replace": r'\1subprocess.run(\2, shell=False, check=True)  # Avoid shell=True',
                "explain": "Replace os.system() with subprocess.run(shell=False)",
                "confidence": "High",
            },
            {
                "match": r'(\s*)subprocess\.(?:call|run|Popen)\s*\(\s*(.+?),\s*shell\s*=\s*True',
                "replace": r'\1subprocess.run(\2, shell=False',
                "explain": "Remove shell=True to prevent command injection",
                "confidence": "High",
            },
        ],
    },
    {
        "issue": "insecure-eval",
        "patterns": [
            {
                "match": r'(\s*)eval\s*\(\s*(.+?)\s*\)',
                "replace": r'\1import ast; ast.literal_eval(\2)  # Safe evaluation of literals only',
                "explain": "Replace eval() with ast.literal_eval() for safe parsing",
                "confidence": "High",
            },
        ],
    },
    {
        "issue": "insecure-deserialization",
        "patterns": [
            {
                "match": r'(\s*)pickle\.loads?\s*\(\s*(.+?)\s*\)',
                "replace": r'\1json.loads(\2)  # Use JSON instead of pickle for untrusted data',
                "explain": "Replace pickle with JSON for untrusted data deserialization",
                "confidence": "Medium",
            },
        ],
    },
    {
        "issue": "weak-crypto",
        "patterns": [
            {
                "match": r'(\s*)hashlib\.md5\s*\(',
                "replace": r'\1hashlib.sha256(',
                "explain": "Replace MD5 with SHA-256 for cryptographic hashing",
                "confidence": "High",
            },
            {
                "match": r'(\s*)hashlib\.sha1\s*\(',
                "replace": r'\1hashlib.sha256(',
                "explain": "Replace SHA-1 with SHA-256",
                "confidence": "High",
            },
        ],
    },
    {
        "issue": "hardcoded-password",
        "patterns": [
            {
                "match": r'(\s*)(password|secret|api_key|token)\s*=\s*["\'][^"\']{4,}["\']',
                "replace": r'\1\2 = os.environ.get("\U\2\E", "")  # Load from environment variable',
                "explain": "Move hardcoded secret to environment variable",
                "confidence": "Medium",
            },
        ],
    },
    {
        "issue": "path-traversal",
        "patterns": [
            {
                "match": r'(\s*)open\s*\(\s*(\w+)\s*(?:,|\))',
                "replace": r'\1# Validate path before opening\n\1import pathlib\n\1safe_path = pathlib.Path(\2).resolve()\n\1assert str(safe_path).startswith(str(BASE_DIR)), "Path traversal"\n\1open(str(safe_path)',
                "explain": "Add path traversal validation before file open",
                "confidence": "Low",
            },
        ],
    },
]

_GO_FIXES: List[Dict] = [
    {
        "issue": "sql-injection",
        "patterns": [
            {
                "match": r'(\s*)db\.(?:Query|Exec)\s*\(\s*(?:fmt\.Sprintf\s*\(|)(.+?\+.+?)\)',
                "replace": r'\1db.Query("SELECT ... WHERE col = $1", param)  // Use parameterized query',
                "explain": "Replace string concatenation in SQL with parameterized query",
                "confidence": "Medium",
            },
        ],
    },
    {
        "issue": "insecure-tls",
        "patterns": [
            {
                "match": r'(\s*)InsecureSkipVerify\s*:\s*true',
                "replace": r'\1InsecureSkipVerify: false  // Never skip TLS verification',
                "explain": "Enable TLS certificate verification",
                "confidence": "High",
            },
        ],
    },
]

_JAVA_FIXES: List[Dict] = [
    {
        "issue": "sql-injection",
        "patterns": [
            {
                "match": r'(\s*)Statement\s+(\w+)\s*=.*?createStatement\s*\(\s*\)',
                "replace": r'\1PreparedStatement \2 = conn.prepareStatement("SELECT ... WHERE col = ?");',
                "explain": "Replace Statement with PreparedStatement for parameterized queries",
                "confidence": "High",
            },
        ],
    },
    {
        "issue": "weak-crypto",
        "patterns": [
            {
                "match": r'(\s*)getInstance\s*\(\s*"(?:MD5|SHA1|DES|RC4)"\s*\)',
                "replace": r'\1getInstance("SHA-256")  // Use strong algorithm',
                "explain": "Replace weak crypto algorithm with SHA-256",
                "confidence": "High",
            },
        ],
    },
]

# ---------------------------------------------------------------------------
# Language → fixes map
# ---------------------------------------------------------------------------

_LANG_FIX_MAP: Dict[str, List[Dict]] = {
    "c": _C_FIXES,
    "cpp": _C_FIXES,
    "python": _PYTHON_FIXES,
    "go": _GO_FIXES,
    "java": _JAVA_FIXES,
}

_EXT_LANG = {
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp",
    ".py": "python",
    ".go": "go",
    ".java": "java",
    ".rs": "rust",
    ".js": "js", ".ts": "js",
}


# ---------------------------------------------------------------------------
# Auto-fix engine
# ---------------------------------------------------------------------------

class AutoFixEngine:
    """Generate fixes for known vulnerability patterns."""

    def generate_fixes(self, findings: List[Dict], file_path: str) -> List[AutoFix]:
        """Given a list of findings (from AuditManager.report_data[path]),
        attempt to generate auto-fixes for each."""
        ext = os.path.splitext(file_path)[1].lower()
        lang = _EXT_LANG.get(ext)
        if not lang:
            return []

        fix_rules = _LANG_FIX_MAP.get(lang, [])
        if not fix_rules:
            return []

        try:
            with open(file_path, "r", errors="ignore") as fh:
                lines = fh.readlines()
        except (OSError, UnicodeDecodeError):
            return []

        fixes: List[AutoFix] = []
        for finding in findings:
            issue = finding.get("issue", "")
            line_no = finding.get("line")
            if not line_no or line_no == "N/A":
                continue

            try:
                line_no = int(line_no)
            except (ValueError, TypeError):
                continue

            if line_no < 1 or line_no > len(lines):
                continue

            original = lines[line_no - 1]

            # Find matching fix rule
            for rule in fix_rules:
                if rule["issue"] != issue:
                    continue
                for pattern in rule["patterns"]:
                    m = re.search(pattern["match"], original)
                    if m:
                        fixed = re.sub(pattern["match"], pattern["replace"], original)
                        if fixed != original:
                            # Generate unified diff
                            orig_lines = lines[:]
                            fixed_lines = lines[:]
                            fixed_lines[line_no - 1] = fixed
                            diff = difflib.unified_diff(
                                orig_lines,
                                fixed_lines,
                                fromfile=f"a/{os.path.basename(file_path)}",
                                tofile=f"b/{os.path.basename(file_path)}",
                                lineterm="",
                            )
                            diff_text = "\n".join(diff)

                            fixes.append(AutoFix(
                                file_path=file_path,
                                line=line_no,
                                issue_type=issue,
                                original_line=original.rstrip(),
                                fixed_line=fixed.rstrip(),
                                explanation=pattern["explain"],
                                confidence=pattern.get("confidence", "Medium"),
                                diff_patch=diff_text,
                            ))
                        break  # first matching pattern wins
                break  # first matching rule wins

        return fixes

    def generate_patch_file(self, all_fixes: List[AutoFix], output_path: str) -> str:
        """Write a combined patch file that can be applied with git apply."""
        patches = []
        for fix in all_fixes:
            if fix.diff_patch:
                patches.append(f"# Fix: {fix.explanation}")
                patches.append(f"# File: {fix.file_path}:{fix.line}")
                patches.append(f"# Issue: {fix.issue_type}")
                patches.append(fix.diff_patch)
                patches.append("")

        content = "\n".join(patches)
        with open(output_path, "w") as fh:
            fh.write(content)
        return output_path

    def apply_fixes(self, fixes: List[AutoFix], dry_run: bool = True) -> List[str]:
        """Apply fixes to files. If dry_run=True, only report what would change."""
        results = []
        # Group by file
        by_file: Dict[str, List[AutoFix]] = {}
        for fix in fixes:
            by_file.setdefault(fix.file_path, []).append(fix)

        for file_path, file_fixes in by_file.items():
            # Sort by line number descending to avoid offset issues
            file_fixes.sort(key=lambda f: f.line, reverse=True)

            try:
                with open(file_path, "r") as fh:
                    lines = fh.readlines()
            except OSError:
                continue

            for fix in file_fixes:
                idx = fix.line - 1
                if 0 <= idx < len(lines):
                    if dry_run:
                        results.append(
                            f"[DRY-RUN] {file_path}:{fix.line} — {fix.explanation}\n"
                            f"  - {fix.original_line}\n"
                            f"  + {fix.fixed_line}"
                        )
                    else:
                        lines[idx] = fix.fixed_line + "\n"
                        results.append(f"[APPLIED] {file_path}:{fix.line} — {fix.explanation}")

            if not dry_run:
                with open(file_path, "w") as fh:
                    fh.writelines(lines)

        return results


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------

def generate_fixes_for_report(report_data: Dict[str, List[Dict]]) -> Tuple[List[AutoFix], str]:
    """Generate auto-fixes for all findings in a report.
    Returns (list of fixes, summary string)."""
    engine = AutoFixEngine()
    all_fixes: List[AutoFix] = []

    for file_path, findings in report_data.items():
        fixes = engine.generate_fixes(findings, file_path)
        all_fixes.extend(fixes)

    if all_fixes:
        summary = f"{len(all_fixes)} auto-fix(es) generated for {len(set(f.file_path for f in all_fixes))} file(s)"
    else:
        summary = "No auto-fixes available for the detected findings"

    return all_fixes, summary
