"""
sarif_output.py — SARIF 2.1.0 report generator for OverflowGuard v8.0

SARIF (Static Analysis Results Interchange Format) is the industry-standard
output format consumed by:
  • GitHub Code Scanning  (shows findings on PR diff lines, free for public repos)
  • Azure DevOps Security  (native SARIF upload action)
  • VS Code Problems panel (SARIF Viewer extension)
  • All major SIEM / ASPM tools

Usage
-----
    from sarif_output import generate_sarif
    sarif_path = generate_sarif(audit_manager, sca_findings, secrets_findings, out_dir="results")

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

Author : Parag Bagade
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SARIF_VERSION  = "2.1.0"
SARIF_SCHEMA   = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
TOOL_NAME      = "OverflowGuard"
TOOL_VERSION   = "8.0"
TOOL_URI       = "https://github.com/parag25mcf10022/OverflowGuard"
TOOL_RULES_URI = "https://github.com/parag25mcf10022/OverflowGuard/blob/main/vulnerability_db.py"

# Map OverflowGuard severity / confidence to SARIF level
_LEVEL_MAP = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
}

# CWE → SARIF taxonomy tag helpers (partial mapping)
_CWE_TAGS = {
    "buffer-overflow":          "CWE-120",
    "stack-overflow":           "CWE-121",
    "heap-overflow":            "CWE-122",
    "use-after-free":           "CWE-416",
    "double-free":              "CWE-415",
    "null-pointer-deref":       "CWE-476",
    "integer-overflow":         "CWE-190",
    "format-string":            "CWE-134",
    "sql-injection":            "CWE-89",
    "os-command-injection":     "CWE-78",
    "path-traversal":           "CWE-22",
    "ssrf":                     "CWE-918",
    "xss":                      "CWE-79",
    "insecure-deserialization": "CWE-502",
    "hardcoded-password":       "CWE-259",
    "weak-crypto":              "CWE-327",
    "weak-rng":                 "CWE-338",
    "memory-leak":              "CWE-401",
    "race-condition":           "CWE-362",
    "insecure-eval":            "CWE-95",
    "secret-in-code":           "CWE-312",
    "vulnerable-dependency":    "CWE-1395",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _make_rule(rule_id: str, vuln_intel: dict) -> Dict[str, Any]:
    """Build a SARIF reportingDescriptor object for a vulnerability type."""
    intel = vuln_intel.get(rule_id, {})
    name  = rule_id.replace("-", " ").title()
    cwe   = _CWE_TAGS.get(rule_id) or intel.get("cwe", "")
    cvss  = intel.get("cvss", "")
    cve   = intel.get("cve", "")
    desc  = intel.get("description", name)
    fix   = intel.get("remediation", "Follow secure coding best practices.")

    tags = []
    if cwe:
        tags.append(cwe)
    if cve:
        tags.append(cve)

    rule: Dict[str, Any] = {
        "id":   rule_id,
        "name": re.sub(r"[^A-Za-z0-9]", "_", name),
        "shortDescription": {"text": name},
        "fullDescription":  {"text": desc},
        "helpUri": TOOL_RULES_URI,
        "help": {"text": fix, "markdown": f"**Remediation:** {fix}"},
        "properties": {
            "tags": tags,
            "precision": "high",
        },
    }
    if cvss:
        rule["properties"]["security-severity"] = str(cvss)
    return rule


def _make_location(abs_path: str, line: Any, snippet: str = "") -> Dict[str, Any]:
    """Build a SARIF physicalLocation object."""
    try:
        line_int = int(line)
    except (TypeError, ValueError):
        line_int = 1

    loc: Dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {
                "uri": abs_path.replace("\\", "/"),
                "uriBaseId": "%SRCROOT%",
            },
            "region": {
                "startLine": max(1, line_int),
                "startColumn": 1,
            },
        }
    }
    if snippet:
        loc["physicalLocation"]["region"]["snippet"] = {"text": snippet[:300]}
    return loc


def _severity_to_level(severity: str) -> str:
    return _LEVEL_MAP.get(severity.upper(), "warning")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_sarif(
    audit_manager,
    sca_findings:     list = None,
    secrets_findings: list = None,
    out_dir:          str  = "results",
    vuln_intel:       dict = None,
) -> str:
    """
    Convert all OverflowGuard findings to a SARIF 2.1.0 JSON file.

    Parameters
    ----------
    audit_manager    : AuditManager instance (holds .report_data, .output_base_name)
    sca_findings     : list of ScaFinding objects from sca_scanner
    secrets_findings : list of SecretFinding objects from secrets_scanner
    out_dir          : directory to write the .sarif file into
    vuln_intel       : VULN_INTEL dict from vulnerability_db (optional, for enrichment)

    Returns
    -------
    str — absolute path to the generated .sarif file
    """
    sca_findings     = sca_findings or []
    secrets_findings = secrets_findings or []
    vuln_intel       = vuln_intel or {}

    rules_seen: Dict[str, Dict] = {}
    results: List[Dict[str, Any]] = []

    # ── 1. SAST findings from AuditManager ────────────────────────────────
    for file_path, findings_list in audit_manager.report_data.items():
        for finding in findings_list:
            rule_id  = finding.get("type", "unknown")
            severity = finding.get("severity", "MEDIUM")
            line     = finding.get("line", 1)
            snippet  = finding.get("snippet", "")
            note     = finding.get("note", "")
            conf     = finding.get("confidence", "MEDIUM")

            if rule_id not in rules_seen:
                rules_seen[rule_id] = _make_rule(rule_id, vuln_intel)

            result: Dict[str, Any] = {
                "ruleId":  rule_id,
                "level":   _severity_to_level(severity),
                "message": {
                    "text": (
                        f"{rule_id.replace('-', ' ').title()} detected "
                        f"(confidence: {conf})"
                        + (f" — {note}" if note else "")
                    )
                },
                "locations": [_make_location(file_path, line, snippet)],
                "properties": {
                    "severity":   severity,
                    "confidence": conf,
                },
            }
            results.append(result)

    # ── 2. SCA (dependency CVE) findings ──────────────────────────────────
    sca_rule_id = "vulnerable-dependency"
    if sca_findings and sca_rule_id not in rules_seen:
        rules_seen[sca_rule_id] = _make_rule(sca_rule_id, vuln_intel)

    for sf in sca_findings:
        fix_note = f" Safe version: {sf.fixed_version}." if sf.fixed_version else ""
        result = {
            "ruleId": sca_rule_id,
            "level":  _severity_to_level(sf.severity),
            "message": {
                "text": (
                    f"{sf.dep.name} {sf.dep.version} is affected by {sf.cve_id} "
                    f"(CVSS {sf.cvss:.1f}).{fix_note} {sf.summary}"
                )
            },
            "locations": [_make_location(sf.dep.source_file, 1)],
            "properties": {
                "severity": sf.severity,
                "cvss":     sf.cvss,
                "cve":      sf.cve_id,
                "fixedVersion": sf.fixed_version or "unknown",
            },
        }
        results.append(result)

    # ── 3. Secrets findings ───────────────────────────────────────────────
    secret_rule_id = "secret-in-code"
    if secrets_findings and secret_rule_id not in rules_seen:
        rules_seen[secret_rule_id] = _make_rule(secret_rule_id, vuln_intel)

    for sec in secrets_findings:
        result = {
            "ruleId": secret_rule_id,
            "level":  "error",
            "message": {
                "text": (
                    f"{sec.secret_type} detected in {os.path.basename(sec.file_path)} "
                    f"(entropy: {sec.entropy:.2f}).  "
                    "Rotate the credential immediately and remove from version control."
                )
            },
            "locations": [_make_location(sec.file_path, sec.line, sec.redacted)],
            "properties": {
                "severity":   "HIGH",
                "secretType": sec.secret_type,
                "entropy":    round(sec.entropy, 3),
            },
        }
        results.append(result)

    # ── Assemble SARIF document ────────────────────────────────────────────
    sarif_doc: Dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name":            TOOL_NAME,
                        "version":         TOOL_VERSION,
                        "informationUri":  TOOL_URI,
                        "rules":           list(rules_seen.values()),
                        "organization":    "Parag Bagade",
                        "semanticVersion": TOOL_VERSION,
                    }
                },
                "results": results,
                "columnKind": "unicodeCodePoints",
            }
        ],
    }

    os.makedirs(out_dir, exist_ok=True)
    base_name = getattr(audit_manager, "output_base_name", "report")
    out_path  = os.path.join(out_dir, f"{base_name}.sarif")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(sarif_doc, fh, indent=2, ensure_ascii=False)

    return out_path
