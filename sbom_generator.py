"""
sbom_generator.py — Software Bill of Materials (SBOM) generator for OverflowGuard v8.0

Produces a CycloneDX 1.4 JSON SBOM listing all detected dependencies plus any
known CVEs found by the SCA scanner.

CycloneDX is the industry-standard SBOM format required by:
  • US Executive Order 14028 (federal software supply chain security)
  • NTIA minimum elements for an SBOM
  • CISA SBOM guidance

Spec: https://cyclonedx.org/docs/1.4/json/

Usage
-----
    from sbom_generator import generate_sbom
    sbom_path = generate_sbom(deps, sca_findings, license_findings, out_dir="results")

Author : Parag Bagade
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import sys
import uuid
from typing import List, Optional

# ---------------------------------------------------------------------------
# Lightweight type stubs so this module works without importing sca_scanner
# ---------------------------------------------------------------------------
try:
    from sca_scanner import Dependency, ScaFinding, LicenseFinding
except ImportError:
    # Fallback dataclasses if sca_scanner is unavailable
    from dataclasses import dataclass, field

    @dataclass
    class Dependency:
        name: str
        version: Optional[str]
        ecosystem: str
        license: Optional[str] = None
        source_file: str = ""

    @dataclass
    class ScaFinding:
        dep: "Dependency"
        cve_id: str
        summary: str
        severity: str
        cvss: float
        fixed_version: Optional[str]
        aliases: List[str] = field(default_factory=list)

    @dataclass
    class LicenseFinding:
        dep: "Dependency"
        license_name: str
        risk_level: str
        reason: str


# ---------------------------------------------------------------------------
# Ecosystem → CycloneDX package-url (purl) type map
# ---------------------------------------------------------------------------

_PURL_TYPES = {
    "PyPI":      "pypi",
    "npm":       "npm",
    "crates.io": "cargo",
    "Go":        "golang",
    "Maven":     "maven",
    "NuGet":     "nuget",
    "RubyGems":  "gem",
}


def _make_purl(dep: Dependency) -> str:
    """Build a Package URL (purl) string for a dependency."""
    ptype = _PURL_TYPES.get(dep.ecosystem, dep.ecosystem.lower())
    name  = dep.name.replace(" ", "-").lower()
    ver   = dep.version or ""
    if dep.ecosystem == "Maven":
        # Maven uses group:artifact notation
        parts = name.split(":", 1)
        if len(parts) == 2:
            return f"pkg:{ptype}/{parts[0]}/{parts[1]}@{ver}"
    if dep.ecosystem == "Go":
        return f"pkg:{ptype}/{name}@{ver}"
    return f"pkg:{ptype}/{name}@{ver}"


def _severity_score(severity: str) -> str:
    """Map severity label to CycloneDX severity string."""
    return {
        "CRITICAL": "critical",
        "HIGH":     "high",
        "MEDIUM":   "medium",
        "LOW":      "low",
    }.get(severity.upper(), "unknown")


# ---------------------------------------------------------------------------
# Component builder
# ---------------------------------------------------------------------------

def _build_component(
    dep: Dependency,
    vuln_findings: List[ScaFinding],
    lic_findings:  List[LicenseFinding],
) -> dict:
    """Build a CycloneDX component object."""
    comp: dict = {
        "type":    "library",
        "name":    dep.name,
        "purl":    _make_purl(dep),
        "bom-ref": f"{dep.ecosystem.lower()}-{dep.name.lower()}-{dep.version or 'unknown'}",
    }
    if dep.version:
        comp["version"] = dep.version

    # License
    lic_match = next((lf for lf in lic_findings if lf.dep.name == dep.name), None)
    lic_name  = lic_match.license_name if lic_match else (dep.license or "")
    if lic_name:
        comp["licenses"] = [{"license": {"name": lic_name}}]

    # Evidence of where this dep was found
    if dep.source_file:
        comp["evidence"] = {
            "occurrences": [{"location": dep.source_file.replace("\\", "/")}]
        }

    return comp


# ---------------------------------------------------------------------------
# Vulnerability builder
# ---------------------------------------------------------------------------

def _build_vulnerability(sf: ScaFinding) -> dict:
    """Build a CycloneDX vulnerability object from an ScaFinding."""
    vuln: dict = {
        "bom-ref": f"vuln-{sf.cve_id}-{sf.dep.name}",
        "id":      sf.cve_id,
        "source":  {
            "name": "OSV",
            "url":  f"https://osv.dev/vulnerability/{sf.cve_id}",
        },
        "description": sf.summary,
        "ratings": [
            {
                "score": sf.cvss,
                "severity": _severity_score(sf.severity),
                "method":   "CVSSv3",
            }
        ],
        "affects": [
            {
                "ref": (f"{sf.dep.ecosystem.lower()}-"
                        f"{sf.dep.name.lower()}-"
                        f"{sf.dep.version or 'unknown'}"),
                "versions": [{"version": sf.dep.version or "unknown", "status": "affected"}],
            }
        ],
    }

    if sf.aliases:
        vuln["advisories"] = [
            {"url": f"https://nvd.nist.gov/vuln/detail/{a}"}
            for a in sf.aliases if a.startswith("CVE-")
        ]

    if sf.fixed_version:
        vuln["recommendation"] = f"Upgrade to {sf.dep.name} {sf.fixed_version} or later."

    return vuln


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_sbom(
    deps:             List[Dependency],
    sca_findings:     List[ScaFinding]     = None,
    license_findings: List[LicenseFinding] = None,
    project_name:     str                  = "OverflowGuard-scan",
    project_version:  str                  = "unknown",
    out_dir:          str                  = "results",
) -> str:
    """
    Generate a CycloneDX 1.4 JSON SBOM.

    Parameters
    ----------
    deps              : list of Dependency objects from sca_scanner
    sca_findings      : list of ScaFinding objects (CVE hits)
    license_findings  : list of LicenseFinding objects
    project_name      : name to use for the root metadata component
    project_version   : version to use for the root metadata component
    out_dir           : directory to write the .json SBOM into

    Returns
    -------
    str — absolute path to the generated sbom_*.json file
    """
    sca_findings     = sca_findings or []
    license_findings = license_findings or []

    serial_number = f"urn:uuid:{uuid.uuid4()}"
    now           = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    # De-duplicate deps
    seen: set = set()
    unique_deps: List[Dependency] = []
    for d in deps:
        key = (d.name.lower(), d.version, d.ecosystem)
        if key not in seen:
            seen.add(key)
            unique_deps.append(d)

    components = [
        _build_component(d, sca_findings, license_findings)
        for d in unique_deps
    ]
    vulnerabilities = [_build_vulnerability(sf) for sf in sca_findings]

    sbom: dict = {
        "bomFormat":   "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [
                {
                    "vendor":  "Parag Bagade",
                    "name":    "OverflowGuard",
                    "version": "8.0",
                }
            ],
            "component": {
                "type":    "application",
                "name":    project_name,
                "version": project_version,
                "bom-ref": f"root-{project_name}",
            },
        },
        "components":     components,
        "vulnerabilities": vulnerabilities,
    }

    os.makedirs(out_dir, exist_ok=True)
    safe_name = project_name.replace(" ", "_").replace("/", "_")
    out_path  = os.path.join(out_dir, f"sbom_{safe_name}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(sbom, fh, indent=2, ensure_ascii=False)

    return out_path


# ---------------------------------------------------------------------------
# CLI smoke-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Quick test with a synthetic dependency
    d = Dependency(name="requests", version="2.27.0", ecosystem="PyPI",
                   source_file="requirements.txt")
    path = generate_sbom([d], project_name="test-project", out_dir="/tmp")
    print(f"SBOM written to: {path}")
    with open(path) as fh:
        doc = json.load(fh)
    print(f"  bomFormat   : {doc['bomFormat']}")
    print(f"  specVersion : {doc['specVersion']}")
    print(f"  components  : {len(doc['components'])}")
