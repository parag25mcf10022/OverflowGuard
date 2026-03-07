"""
secrets_scanner.py — Credentials & secrets detection module for OverflowGuard v8.0

Detects hard-coded secrets, API keys, tokens, and high-entropy strings in source
code and configuration files.  Comparable to TruffleHog / Gitleaks.

Detection methods
-----------------
1. Pattern matching  — 30+ regex rules for well-known secret formats
2. Entropy analysis  — Shannon entropy on non-trivial assignment RHS values;
                       strings with entropy > 4.5 on 20+ chars flagged as secrets
3. .env / config     — explicit .env, config.ini, appsettings.json scanning
4. Context filter    — suppresses test files, example values, and placeholder text

Author : Parag Bagade
"""

from __future__ import annotations

import math
import os
import re
import sys
from dataclasses import dataclass
from typing import List, Optional

# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------

@dataclass
class SecretFinding:
    file_path:   str
    line:        int
    secret_type: str
    redacted:    str   # e.g. "AKIA***************XYZ"
    entropy:     float
    raw_match:   str   # full matched line (used internally, not exported to HTML)

    def to_dict(self) -> dict:
        return {
            "file":        self.file_path,
            "line":        self.line,
            "type":        self.secret_type,
            "redacted":    self.redacted,
            "entropy":     round(self.entropy, 3),
            "severity":    "HIGH",
            "confidence":  "HIGH" if self.entropy > 4.5 else "MEDIUM",
        }


# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# Each tuple: (rule_name, compiled_regex, group_to_redact)
_PATTERNS: List[tuple] = [
    # AWS
    ("AWS Access Key",       re.compile(r"AKIA[0-9A-Z]{16}"),                         0),
    ("AWS Secret Key",       re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+]{40})['\"]"), 1),
    # GitHub
    ("GitHub Token",         re.compile(r"ghp_[A-Za-z0-9]{36}"),                      0),
    ("GitHub OAuth",         re.compile(r"gho_[A-Za-z0-9]{36}"),                      0),
    ("GitHub App Token",     re.compile(r"(ghu_|ghs_)[A-Za-z0-9]{36}"),               0),
    # Google
    ("Google API Key",       re.compile(r"AIza[0-9A-Za-z_\-]{35}"),                   0),
    ("Google OAuth",         re.compile(r"ya29\.[0-9A-Za-z_\-]{60,}"),               0),
    # Slack
    ("Slack Token",          re.compile(r"xox[baprs]-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{24}"), 0),
    ("Slack Webhook",        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}"), 0),
    # Stripe
    ("Stripe Live Key",      re.compile(r"sk_live_[0-9a-zA-Z]{24}"),                  0),
    ("Stripe Test Key",      re.compile(r"sk_test_[0-9a-zA-Z]{24}"),                  0),
    # Twilio
    ("Twilio SID",           re.compile(r"AC[a-z0-9]{32}"),                            0),
    ("Twilio Auth Token",    re.compile(r"(?i)twilio.{0,10}['\"]([a-z0-9]{32})['\"]"), 1),
    # SendGrid
    ("SendGrid Key",         re.compile(r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}"), 0),
    # Private keys
    ("RSA Private Key",      re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),           0),
    ("EC Private Key",       re.compile(r"-----BEGIN EC PRIVATE KEY-----"),            0),
    ("OpenSSH Private Key",  re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),       0),
    ("PGP Private Key",      re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),     0),
    # JWT
    ("JWT Token",            re.compile(r"eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"), 0),
    # Database URLs
    ("DB Connection String", re.compile(
        r"(?i)(mysql|postgres|postgresql|mongodb|redis|mssql)\+?://[^:@\s]+:[^@\s]+@[^\s\"']+"), 0),
    # Generic password in assignment
    ("Hardcoded Password",   re.compile(
        r"""(?i)(?:password|passwd|pwd|secret|token|api_?key)\s*[=:]\s*['"][^'"]{8,}['"]"""), 0),
    # Basic auth in URL
    ("Basic Auth URL",       re.compile(r"https?://[^:@\s]{1,50}:[^@\s]{4,}@[^\s\"']+"), 0),
    # Azure
    ("Azure Storage Key",    re.compile(r"DefaultEndpointsProtocol=https;AccountName="), 0),
    ("Azure SAS Token",      re.compile(r"sig=[A-Za-z0-9%+/]{30,}"),                   0),
    # NPM
    ("NPM Auth Token",       re.compile(r"npm_[A-Za-z0-9]{36}"),                       0),
    # PyPI / Twine
    ("PyPI API Token",       re.compile(r"pypi-[A-Za-z0-9_\-]{40,}"),                  0),
    # Heroku
    ("Heroku API Key",       re.compile(r"(?i)heroku.{0,10}['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]"), 1),
    # Generic high-entropy (caught by entropy scan, listed here for completeness)
]

# Files/patterns to SKIP (test data, example configs, this file itself)
_SKIP_PATTERNS = re.compile(
    r"(?i)(example|sample|placeholder|dummy|test|fake|mock|fixture|template|\.pyc)"
)
_SKIP_VALUE_PATTERNS = re.compile(
    r"(?i)(your[_\-]?(?:key|secret|token)|<[^>]+>|\*{3,}|xxx+|todo|changeme|"
    r"password123|replace.?me|insert.?here|0{8,}|1{8,})"
)
_SKIP_EXTENSIONS = {".pyc", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".min.js"}

# ---------------------------------------------------------------------------
# Entropy helper
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq: dict = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


_HIGH_ENTROPY_RE = re.compile(
    r"""(?i)(?:key|secret|token|password|passwd|pwd|credential|auth|api)\s*"""
    r"""[=:]\s*['"]([A-Za-z0-9+/=_\-]{20,})['"]"""
)

_ENTROPY_THRESHOLD = 4.5
_MIN_SECRET_LEN    = 20


def _redact(value: str) -> str:
    """Show first 4 + *** + last 4 chars."""
    if len(value) <= 8:
        return "****"
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


# ---------------------------------------------------------------------------
# File-level scanner
# ---------------------------------------------------------------------------

def _should_skip_file(path: str) -> bool:
    _, ext = os.path.splitext(path)
    if ext.lower() in _SKIP_EXTENSIONS:
        return True
    basename = os.path.basename(path).lower()
    if _SKIP_PATTERNS.search(basename):
        return True
    return False


def scan_file(file_path: str) -> List[SecretFinding]:
    """Scan a single file for secrets and return a list of SecretFinding objects."""
    if _should_skip_file(file_path):
        return []
    findings: List[SecretFinding] = []
    try:
        with open(file_path, errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return []

    for line_no, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip("\n")

        # Skip comment-only lines and obvious placeholder lines
        stripped = line.lstrip()
        if stripped.startswith(("#", "//", "*", "<!--")):
            continue
        if _SKIP_VALUE_PATTERNS.search(line):
            continue

        # 1. Pattern matching
        for rule_name, pattern, group in _PATTERNS:
            m = pattern.search(line)
            if not m:
                continue
            matched_val = m.group(group) if group > 0 and len(m.groups()) >= group else m.group(0)
            if _SKIP_VALUE_PATTERNS.search(matched_val):
                continue
            entropy = _shannon_entropy(matched_val)
            findings.append(SecretFinding(
                file_path=file_path, line=line_no,
                secret_type=rule_name,
                redacted=_redact(matched_val),
                entropy=entropy,
                raw_match=line[:200],
            ))
            break   # only one finding per line from pattern scan

        # 2. High-entropy assignment scan
        em = _HIGH_ENTROPY_RE.search(line)
        if em:
            val = em.group(1)
            if len(val) >= _MIN_SECRET_LEN and not _SKIP_VALUE_PATTERNS.search(val):
                ent = _shannon_entropy(val)
                if ent >= _ENTROPY_THRESHOLD:
                    # Don't duplicate if already caught by pattern scan
                    already = any(f.line == line_no and f.file_path == file_path
                                  for f in findings)
                    if not already:
                        findings.append(SecretFinding(
                            file_path=file_path, line=line_no,
                            secret_type="High-Entropy Secret",
                            redacted=_redact(val),
                            entropy=ent,
                            raw_match=line[:200],
                        ))

    return findings


# ---------------------------------------------------------------------------
# Directory scanner
# ---------------------------------------------------------------------------

_SOURCE_EXTS = {
    ".py", ".js", ".ts", ".go", ".rs", ".java", ".c", ".cpp", ".cc", ".h",
    ".rb", ".php", ".sh", ".bash", ".env", ".env.local", ".env.production",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".json", ".xml",
    ".properties", ".pem", ".key", ".crt",
}

_SKIP_DIRS = {
    ".venv", "venv", "env", "__pycache__", "node_modules", ".git",
    "site-packages", "dist-packages", "build", "dist", "target",
    ".tox", ".mypy_cache", ".pytest_cache",
}


def run_secrets_scan(root_path: str, verbose: bool = True) -> List[SecretFinding]:
    """
    Recursively scan *root_path* for hard-coded secrets.
    Returns a list of SecretFinding objects sorted by (file, line).
    """
    all_findings: List[SecretFinding] = []

    if os.path.isfile(root_path):
        return scan_file(root_path)

    for dirpath, dirs, files in os.walk(root_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fname in files:
            _, ext = os.path.splitext(fname)
            if ext.lower() not in _SOURCE_EXTS and fname not in (".env",):
                continue
            fpath = os.path.join(dirpath, fname)
            found = scan_file(fpath)
            if found and verbose:
                for f in found:
                    print(f"  [SECRETS] {f.secret_type} in "
                          f"{os.path.relpath(f.file_path)} L{f.line} "
                          f"({f.redacted})  entropy={f.entropy:.2f}")
            all_findings.extend(found)

    all_findings.sort(key=lambda x: (x.file_path, x.line))
    return all_findings


# ---------------------------------------------------------------------------
# CLI smoke-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    results = run_secrets_scan(target)
    print(f"\n=== SECRETS SCAN RESULTS: {len(results)} finding(s) ===")
    for r in results:
        print(f"  {r.secret_type:30s}  {os.path.basename(r.file_path)}:{r.line}  "
              f"{r.redacted}  entropy={r.entropy:.2f}")
