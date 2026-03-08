"""
custom_rules.py — YAML-based custom rule engine for OverflowGuard v11.0

Users create YAML rule files in a rules/ directory (configurable via
.overflowguard.yml). Each rule specifies a pattern, message, severity,
languages, and optional fix text.

Example rule file (rules/no-eval.yml):

    rules:
      - id: custom-no-eval
        pattern: "eval\\s*\\("
        message: "eval() usage detected — potential code injection"
        severity: HIGH
        languages: [python, javascript, php]
        cwe: CWE-95
        fix: "Use ast.literal_eval() for Python or a JSON parser instead."

Copyright 2026 Parag Bagade — MIT Licence
"""

from __future__ import annotations
import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any

# ---------------------------------------------------------------------------
# YAML loader (same approach as project_config.py)
# ---------------------------------------------------------------------------
try:
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


def _load_yaml_file(path: str) -> dict:
    with open(path, "r") as fh:
        text = fh.read()
    if _HAS_YAML:
        return _yaml.safe_load(text) or {}
    # Minimal fallback for rule files — limited subset
    return _parse_rules_fallback(text)


def _parse_rules_fallback(text: str) -> dict:
    """Very basic fallback YAML parser for rule files."""
    rules = []
    current: Dict[str, Any] = {}
    in_list_field = None

    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # New rule item
        if stripped.startswith("- id:"):
            if current:
                rules.append(current)
            current = {"id": stripped.split(":", 1)[1].strip().strip('"').strip("'")}
            in_list_field = None
            continue

        # List under languages
        if stripped.startswith("- ") and in_list_field:
            val = stripped[2:].strip().strip('"').strip("'")
            current.setdefault(in_list_field, []).append(val)
            continue

        if ":" in stripped:
            key, _, val = stripped.partition(":")
            key = key.strip().strip("-").strip()
            val = val.strip().strip('"').strip("'")
            if val.startswith("[") and val.endswith("]"):
                # Inline list
                items = [x.strip().strip('"').strip("'") for x in val[1:-1].split(",")]
                current[key] = [i for i in items if i]
                in_list_field = None
            elif val == "" or val == "[]":
                in_list_field = key
                current[key] = []
            else:
                current[key] = val
                in_list_field = None

    if current:
        rules.append(current)

    return {"rules": rules}


# ---------------------------------------------------------------------------
# CustomRule dataclass
# ---------------------------------------------------------------------------

@dataclass
class CustomRule:
    id: str
    pattern: str                           # regex pattern
    message: str
    severity: str = "MEDIUM"               # CRITICAL | HIGH | MEDIUM | LOW
    languages: List[str] = field(default_factory=list)   # empty = all
    cwe: str = ""
    fix: str = ""
    compiled: Optional[re.Pattern] = field(default=None, repr=False)

    def __post_init__(self):
        try:
            self.compiled = re.compile(self.pattern, re.MULTILINE)
        except re.error:
            self.compiled = None


@dataclass
class CustomRuleFinding:
    file_path: str
    line: int
    rule_id: str
    severity: str
    message: str
    snippet: str
    cwe: str = ""
    fix: str = ""


# ---------------------------------------------------------------------------
# Rule loader
# ---------------------------------------------------------------------------

_EXT_LANG_MAP = {
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".py": "python",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".php": "php",
    ".rb": "ruby",
    ".cs": "csharp",
    ".kt": "kotlin", ".kts": "kotlin",
    ".swift": "swift",
    ".scala": "scala", ".sc": "scala",
}


def load_rules_from_dir(rules_dir: str) -> List[CustomRule]:
    """Load all .yml/.yaml rule files from a directory."""
    rules: List[CustomRule] = []

    if not os.path.isdir(rules_dir):
        return rules

    for fname in sorted(os.listdir(rules_dir)):
        if not fname.endswith((".yml", ".yaml")):
            continue
        fpath = os.path.join(rules_dir, fname)
        try:
            data = _load_yaml_file(fpath)
            raw_rules = data.get("rules", [])
            for raw in raw_rules:
                if not isinstance(raw, dict):
                    continue
                rule = CustomRule(
                    id=raw.get("id", f"custom-{fname}"),
                    pattern=raw.get("pattern", ""),
                    message=raw.get("message", "Custom rule violation"),
                    severity=raw.get("severity", "MEDIUM").upper(),
                    languages=raw.get("languages", []),
                    cwe=raw.get("cwe", ""),
                    fix=raw.get("fix", ""),
                )
                if rule.compiled:
                    rules.append(rule)
        except Exception:
            continue

    return rules


def load_rules_from_file(rule_file: str) -> List[CustomRule]:
    """Load rules from a single YAML file."""
    try:
        data = _load_yaml_file(rule_file)
        raw_rules = data.get("rules", [])
        rules = []
        for raw in raw_rules:
            if not isinstance(raw, dict):
                continue
            rule = CustomRule(
                id=raw.get("id", "custom"),
                pattern=raw.get("pattern", ""),
                message=raw.get("message", "Custom rule violation"),
                severity=raw.get("severity", "MEDIUM").upper(),
                languages=raw.get("languages", []),
                cwe=raw.get("cwe", ""),
                fix=raw.get("fix", ""),
            )
            if rule.compiled:
                rules.append(rule)
        return rules
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Custom rule scanner
# ---------------------------------------------------------------------------

class CustomRuleEngine:
    """Apply custom YAML-defined rules to source files."""

    def __init__(self, rules: List[CustomRule] = None):
        self.rules = rules or []

    def load_from_directory(self, rules_dir: str) -> None:
        """Load additional rules from a directory."""
        self.rules.extend(load_rules_from_dir(rules_dir))

    def scan_file(self, file_path: str) -> List[CustomRuleFinding]:
        """Scan a single file against all loaded custom rules."""
        ext = os.path.splitext(file_path)[1].lower()
        lang = _EXT_LANG_MAP.get(ext)

        try:
            with open(file_path, "r", errors="ignore") as fh:
                content = fh.read()
            lines = content.splitlines()
        except (OSError, UnicodeDecodeError):
            return []

        findings: List[CustomRuleFinding] = []

        for rule in self.rules:
            # Check language filter
            if rule.languages and lang and lang not in rule.languages:
                continue

            if rule.compiled is None:
                continue

            for m in rule.compiled.finditer(content):
                line_no = content[:m.start()].count("\n") + 1
                snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""

                findings.append(CustomRuleFinding(
                    file_path=file_path,
                    line=line_no,
                    rule_id=rule.id,
                    severity=rule.severity,
                    message=rule.message,
                    snippet=snippet,
                    cwe=rule.cwe,
                    fix=rule.fix,
                ))

        return findings

    def scan_directory(self, root_path: str, scan_exts: set = None, verbose: bool = False) -> List[CustomRuleFinding]:
        """Scan an entire directory with custom rules."""
        if not self.rules:
            return []

        SKIP_DIRS = {
            ".git", ".hg", ".svn", "node_modules", "__pycache__",
            ".venv", "venv", ".tox", "target", "build", "dist",
        }

        if scan_exts is None:
            scan_exts = set(_EXT_LANG_MAP.keys())

        all_findings: List[CustomRuleFinding] = []

        for dirpath, dirs, files in os.walk(root_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext in scan_exts:
                    fpath = os.path.join(dirpath, fname)
                    findings = self.scan_file(fpath)
                    all_findings.extend(findings)

        if verbose and all_findings:
            for f in all_findings:
                print(f"  [{f.severity}] {f.rule_id}: {f.message} "
                      f"({os.path.relpath(f.file_path, root_path)}:{f.line})")

        return all_findings


# ---------------------------------------------------------------------------
# Sample rule generator
# ---------------------------------------------------------------------------

SAMPLE_RULES = """\
# Custom rules for OverflowGuard
# Place this file in your project's rules/ directory.
# See: https://github.com/parag25mcf10022/OverflowGuard

rules:
  - id: custom-no-eval
    pattern: "eval\\\\s*\\\\("
    message: "eval() usage detected — potential code injection"
    severity: HIGH
    languages: [python, javascript, php]
    cwe: CWE-95
    fix: "Use ast.literal_eval() for Python or a JSON parser instead."

  - id: custom-no-todo-fixme
    pattern: "(?:TODO|FIXME|HACK|XXX)\\\\b"
    message: "Unresolved TODO/FIXME in production code"
    severity: LOW
    languages: []
    cwe: ""
    fix: "Resolve the TODO before merging to main."

  - id: custom-no-console-log
    pattern: "console\\\\.log\\\\("
    message: "console.log() left in production code"
    severity: LOW
    languages: [javascript, typescript]
    cwe: ""
    fix: "Remove console.log or use a proper logging library."

  - id: custom-no-debug-true
    pattern: "DEBUG\\\\s*=\\\\s*True"
    message: "Debug mode enabled in configuration"
    severity: HIGH
    languages: [python]
    cwe: CWE-489
    fix: "Set DEBUG = False for production deployments."
"""


def generate_sample_rules(directory: str) -> str:
    """Write sample custom rules to a directory."""
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, "sample_rules.yml")
    with open(path, "w") as fh:
        fh.write(SAMPLE_RULES)
    return path
