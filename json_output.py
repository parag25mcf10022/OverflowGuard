"""
json_output.py — JSON / machine-readable output for OverflowGuard v11.0

Generates structured JSON reports for CI/CD pipeline consumption.
Supports: --format json on the CLI.

Copyright 2026 Parag Bagade — MIT Licence
"""

from __future__ import annotations
import json
import os
import datetime
from typing import Dict, List, Any, Optional


def generate_json_report(
    audit_manager,
    sca_findings: list = None,
    license_findings: list = None,
    secrets_findings: list = None,
    iac_findings: list = None,
    cross_file_findings: list = None,
    owasp_mapping: dict = None,
    trend_data: dict = None,
    auto_fixes: list = None,
    out_dir: str = "results",
    extra_meta: dict = None,
) -> str:
    """Generate a comprehensive JSON report.

    Returns the path to the written JSON file.
    """
    sca_findings = sca_findings or []
    license_findings = license_findings or []
    secrets_findings = secrets_findings or []
    iac_findings = iac_findings or []
    cross_file_findings = cross_file_findings or []
    auto_fixes = auto_fixes or []

    # ── Build findings list ──────────────────────────────────────────────────
    findings: List[Dict[str, Any]] = []
    for file_path, file_findings in audit_manager.report_data.items():
        for f in file_findings:
            findings.append({
                "file": file_path,
                "line": f.get("line"),
                "issue": f.get("issue", ""),
                "severity": f.get("severity", "INFO"),
                "confidence": f.get("confidence", "Medium"),
                "stage": f.get("stage", ""),
                "cwe": f.get("cwe", ""),
                "cve": f.get("cve", ""),
                "cvss": f.get("cvss", ""),
                "description": f.get("description", ""),
                "remediation": f.get("remediation", ""),
                "snippet": f.get("snippet", ""),
                "note": f.get("note", ""),
            })

    # ── Severity totals ──────────────────────────────────────────────────────
    sev_totals: Dict[str, int] = {}
    for f in findings:
        sev = f["severity"]
        sev_totals[sev] = sev_totals.get(sev, 0) + 1

    # ── Stage breakdown ──────────────────────────────────────────────────────
    stage_totals: Dict[str, int] = {}
    for f in findings:
        stage = f["stage"]
        stage_totals[stage] = stage_totals.get(stage, 0) + 1

    # ── SCA ───────────────────────────────────────────────────────────────────
    sca_list = []
    for sf in sca_findings:
        sca_list.append({
            "package": sf.dep.name if hasattr(sf, "dep") else str(sf),
            "version": sf.dep.version if hasattr(sf, "dep") else "",
            "cve_id": sf.cve_id if hasattr(sf, "cve_id") else "",
            "cvss": sf.cvss if hasattr(sf, "cvss") else "",
            "severity": sf.severity if hasattr(sf, "severity") else "",
            "summary": sf.summary if hasattr(sf, "summary") else "",
            "fixed_version": sf.fixed_version if hasattr(sf, "fixed_version") else "",
        })

    # ── IaC ───────────────────────────────────────────────────────────────────
    iac_list = []
    for iac in iac_findings:
        iac_list.append({
            "file": iac.file_path if hasattr(iac, "file_path") else str(iac),
            "line": iac.line if hasattr(iac, "line") else 0,
            "rule_id": iac.rule_id if hasattr(iac, "rule_id") else "",
            "severity": iac.severity if hasattr(iac, "severity") else "",
            "issue_type": iac.issue_type if hasattr(iac, "issue_type") else "",
            "description": iac.description if hasattr(iac, "description") else "",
            "framework": iac.framework if hasattr(iac, "framework") else "",
        })

    # ── Cross-file taint ──────────────────────────────────────────────────────
    xf_list = []
    for xf in cross_file_findings:
        xf_list.append({
            "source_file": xf.source_file if hasattr(xf, "source_file") else "",
            "source_line": xf.source_line if hasattr(xf, "source_line") else 0,
            "sink_file": xf.sink_file if hasattr(xf, "sink_file") else "",
            "sink_function": xf.sink_function if hasattr(xf, "sink_function") else "",
            "issue_type": xf.issue_type if hasattr(xf, "issue_type") else "",
            "severity": xf.severity if hasattr(xf, "severity") else "",
            "description": xf.description if hasattr(xf, "description") else "",
            "taint_chain": xf.taint_chain if hasattr(xf, "taint_chain") else [],
            "risk_score": xf.risk_score if hasattr(xf, "risk_score") else 0,
        })

    # ── Auto-fixes ────────────────────────────────────────────────────────────
    fix_list = []
    for fx in auto_fixes:
        fix_list.append({
            "file": fx.file_path if hasattr(fx, "file_path") else "",
            "line": fx.line if hasattr(fx, "line") else 0,
            "issue_type": fx.issue_type if hasattr(fx, "issue_type") else "",
            "original": fx.original_line if hasattr(fx, "original_line") else "",
            "fixed": fx.fixed_line if hasattr(fx, "fixed_line") else "",
            "explanation": fx.explanation if hasattr(fx, "explanation") else "",
            "confidence": fx.confidence if hasattr(fx, "confidence") else "",
        })

    # ── Assemble report ──────────────────────────────────────────────────────
    report: Dict[str, Any] = {
        "tool": "OverflowGuard",
        "version": getattr(audit_manager, "_version", "v11.0"),
        "scan_date": datetime.datetime.now().isoformat(),
        "target": getattr(audit_manager, "output_base_name", ""),
        "summary": {
            "files_scanned": audit_manager.stats.get("scanned", 0),
            "total_findings": len(findings),
            "severity_breakdown": sev_totals,
            "stage_breakdown": stage_totals,
            "sca_vulnerabilities": len(sca_findings),
            "license_issues": len(license_findings),
            "secrets_detected": len(secrets_findings) if secrets_findings else 0,
            "iac_misconfigurations": len(iac_findings),
            "cross_file_flows": len(cross_file_findings),
            "auto_fixes_available": len(auto_fixes),
        },
        "findings": findings,
        "sca": sca_list,
        "iac": iac_list,
        "cross_file_taint": xf_list,
        "auto_fixes": fix_list,
    }

    if owasp_mapping:
        report["owasp_top_10"] = owasp_mapping

    if trend_data:
        report["trend"] = trend_data

    if extra_meta:
        report["metadata"] = extra_meta

    # ── Write ─────────────────────────────────────────────────────────────────
    os.makedirs(out_dir, exist_ok=True)
    filename = f"{getattr(audit_manager, 'output_base_name', 'report')}.json"
    out_path = os.path.join(out_dir, filename)
    with open(out_path, "w") as fh:
        json.dump(report, fh, indent=2, default=str)

    return out_path


def print_json_summary(report_path: str) -> None:
    """Print a minimal JSON summary to stdout for CI consumption."""
    with open(report_path) as fh:
        data = json.load(fh)
    summary = data.get("summary", {})
    print(json.dumps(summary, indent=2))
