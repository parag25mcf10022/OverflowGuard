"""
project_config.py — Project configuration loader for OverflowGuard v11.0

Reads `.overflowguard.yml` (or `.overflowguard.yaml`) from the project root
and provides a typed ProjectConfig object consumed by the scanner pipeline.

Example `.overflowguard.yml`:

    version: 1
    severity_threshold: MEDIUM          # fail CI if any finding >= this
    exclude_paths:
      - "vendor/**"
      - "third_party/**"
      - "**/*_test.go"
    exclude_rules:
      - weak-rng
      - insecure-temp-file
    include_only_rules: []              # empty = all rules enabled
    languages:                          # empty = all languages
      - c
      - cpp
      - python
    custom_rules: "rules/"             # path to custom YAML rules dir
    output_format: html                 # html | json | sarif | all
    max_findings: 0                     # 0 = unlimited
    diff_mode: null                     # null | staged | working | head | last_tag
    enable_sca: true
    enable_secrets: true
    enable_sbom: true
    enable_iac: true
    enable_container_scan: true
    enable_advanced_taint: true
    enable_cross_file_taint: true
    enable_trend_tracking: true
    owasp_report: true
    autofix: false

Copyright 2026 Parag Bagade — MIT Licence
"""

from __future__ import annotations
import os
import re
import fnmatch
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

# ---------------------------------------------------------------------------
# YAML loader — stdlib-only fallback if PyYAML is absent
# ---------------------------------------------------------------------------
try:
    import yaml as _yaml          # type: ignore
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


def _simple_yaml_parse(text: str) -> dict:
    """Ultra-minimal YAML-like parser for flat key: value and list items.
    Handles the subset used by .overflowguard.yml without requiring PyYAML."""
    result: dict = {}
    current_key: Optional[str] = None
    current_list: Optional[list] = None

    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # List item under a key
        if stripped.startswith("- "):
            val = stripped[2:].strip().strip('"').strip("'")
            if current_list is not None:
                current_list.append(val)
            continue

        if ":" in stripped:
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            # Remove inline comments
            if " #" in val:
                val = val[:val.index(" #")].strip()
            # Determine value type
            if val == "" or val.lower() == "[]":
                current_key = key
                current_list = []
                result[key] = current_list
            elif val.lower() in ("true", "yes"):
                result[key] = True
                current_key = None
                current_list = None
            elif val.lower() in ("false", "no"):
                result[key] = False
                current_key = None
                current_list = None
            elif val.lower() in ("null", "none", "~"):
                result[key] = None
                current_key = None
                current_list = None
            else:
                # Try int
                try:
                    result[key] = int(val)
                except ValueError:
                    try:
                        result[key] = float(val)
                    except ValueError:
                        result[key] = val
                current_key = None
                current_list = None
        else:
            current_key = None
            current_list = None

    return result


def _load_yaml(path: str) -> dict:
    with open(path, "r") as fh:
        text = fh.read()
    if _HAS_YAML:
        return _yaml.safe_load(text) or {}
    return _simple_yaml_parse(text)


# ---------------------------------------------------------------------------
# ProjectConfig dataclass
# ---------------------------------------------------------------------------
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

@dataclass
class ProjectConfig:
    """Typed project configuration consumed by the scanner pipeline."""

    # ── path filtering ────────────────────────────────────────────────────
    exclude_paths: List[str]       = field(default_factory=list)
    exclude_rules: List[str]       = field(default_factory=list)
    include_only_rules: List[str]  = field(default_factory=list)
    languages: List[str]           = field(default_factory=list)

    # ── thresholds ────────────────────────────────────────────────────────
    severity_threshold: str        = "LOW"      # fail if >= this in CI
    max_findings: int              = 0          # 0 = unlimited

    # ── scan mode ─────────────────────────────────────────────────────────
    diff_mode: Optional[str]       = None
    output_format: str             = "html"     # html | json | sarif | all

    # ── feature toggles ──────────────────────────────────────────────────
    enable_sca: bool               = True
    enable_secrets: bool           = True
    enable_sbom: bool              = True
    enable_iac: bool               = True
    enable_container_scan: bool    = True
    enable_advanced_taint: bool    = True
    enable_cross_file_taint: bool  = True
    enable_trend_tracking: bool    = True
    owasp_report: bool             = True
    autofix: bool                  = False

    # ── custom rules ──────────────────────────────────────────────────────
    custom_rules_dir: Optional[str] = None

    # ── internal ──────────────────────────────────────────────────────────
    config_path: Optional[str]     = None       # path to the loaded file

    # -- helpers -----------------------------------------------------------

    def should_scan_file(self, rel_path: str) -> bool:
        """Return False if *rel_path* matches any exclude glob."""
        for pattern in self.exclude_paths:
            if fnmatch.fnmatch(rel_path, pattern):
                return False
            # Also try matching just the filename
            if fnmatch.fnmatch(os.path.basename(rel_path), pattern):
                return False
        return True

    def should_report_rule(self, rule_id: str) -> bool:
        """Return False if the rule is excluded or not in the include-only list."""
        if rule_id in self.exclude_rules:
            return False
        if self.include_only_rules and rule_id not in self.include_only_rules:
            return False
        return True

    def meets_severity_threshold(self, severity: str) -> bool:
        """Return True if *severity* is >= the configured threshold."""
        return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(self.severity_threshold, 0)

    def should_scan_language(self, lang: str) -> bool:
        """Return True if the language is in the configured list (empty = all)."""
        if not self.languages:
            return True
        return lang.lower() in [l.lower() for l in self.languages]

    def exit_code_for_findings(self, stats: dict) -> int:
        """Return 0 (pass) or 1 (fail) based on severity_threshold."""
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if self.meets_severity_threshold(sev) and stats.get(sev, 0) > 0:
                return 1
        return 0


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------
_CONFIG_NAMES = (".overflowguard.yml", ".overflowguard.yaml", "overflowguard.yml", "overflowguard.yaml")


def find_config(start_dir: str) -> Optional[str]:
    """Walk upward from *start_dir* until we find a config file (or hit /)."""
    d = os.path.abspath(start_dir)
    for _ in range(20):  # safety limit
        for name in _CONFIG_NAMES:
            candidate = os.path.join(d, name)
            if os.path.isfile(candidate):
                return candidate
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return None


def load_config(start_dir: str) -> ProjectConfig:
    """Load project config from the nearest `.overflowguard.yml`.
    Returns a default config if no file is found."""
    path = find_config(start_dir)
    if path is None:
        return ProjectConfig()

    raw = _load_yaml(path)
    cfg = ProjectConfig(config_path=path)

    # Map raw dict → typed fields
    _list_fields = ("exclude_paths", "exclude_rules", "include_only_rules", "languages")
    for fld in _list_fields:
        v = raw.get(fld)
        if isinstance(v, list):
            setattr(cfg, fld, v)
        elif isinstance(v, str) and v:
            setattr(cfg, fld, [v])

    _bool_fields = (
        "enable_sca", "enable_secrets", "enable_sbom", "enable_iac",
        "enable_container_scan", "enable_advanced_taint", "enable_cross_file_taint",
        "enable_trend_tracking", "owasp_report", "autofix",
    )
    for fld in _bool_fields:
        v = raw.get(fld)
        if isinstance(v, bool):
            setattr(cfg, fld, v)

    _str_fields = ("severity_threshold", "diff_mode", "output_format")
    for fld in _str_fields:
        v = raw.get(fld)
        if isinstance(v, str):
            setattr(cfg, fld, v.upper() if fld == "severity_threshold" else v)

    _int_fields = ("max_findings",)
    for fld in _int_fields:
        v = raw.get(fld)
        if isinstance(v, int):
            setattr(cfg, fld, v)

    v = raw.get("custom_rules")
    if isinstance(v, str):
        cfg.custom_rules_dir = v

    return cfg


# ---------------------------------------------------------------------------
# Sample config generator
# ---------------------------------------------------------------------------
SAMPLE_CONFIG = """\
# .overflowguard.yml — OverflowGuard v11.0 project configuration
# Place this file in your project root.

version: 1

# ── Severity threshold (for CI exit codes) ─────────────────────────────────
# Options: CRITICAL | HIGH | MEDIUM | LOW | INFO
# The scanner will exit with code 1 if any finding >= this level is found.
severity_threshold: MEDIUM

# ── Path exclusions (glob patterns, matched against relative paths) ────────
exclude_paths:
  - "vendor/**"
  - "third_party/**"
  - "**/*_test.go"
  - "**/*.min.js"
  - "node_modules/**"

# ── Rule exclusions (by issue-type identifier) ────────────────────────────
exclude_rules: []
  # - weak-rng
  # - insecure-temp-file

# ── Include-only rules (empty = all rules active) ─────────────────────────
include_only_rules: []

# ── Languages to scan (empty = all 14 supported) ──────────────────────────
languages: []
  # - c
  # - cpp
  # - python

# ── Output format ─────────────────────────────────────────────────────────
# Options: html | json | sarif | all
output_format: all

# ── Maximum findings (0 = unlimited) ──────────────────────────────────────
max_findings: 0

# ── Diff mode (null = full scan) ──────────────────────────────────────────
# Options: null | staged | working | head | last_tag
diff_mode: null

# ── Custom rules directory (YAML rule files) ──────────────────────────────
custom_rules: null

# ── Feature toggles ──────────────────────────────────────────────────────
enable_sca: true
enable_secrets: true
enable_sbom: true
enable_iac: true
enable_container_scan: true
enable_advanced_taint: true
enable_cross_file_taint: true
enable_trend_tracking: true
owasp_report: true
autofix: false
"""


def generate_sample_config(directory: str) -> str:
    """Write a sample `.overflowguard.yml` into *directory* and return its path."""
    path = os.path.join(directory, ".overflowguard.yml")
    with open(path, "w") as fh:
        fh.write(SAMPLE_CONFIG)
    return path
