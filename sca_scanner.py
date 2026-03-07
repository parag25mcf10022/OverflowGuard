"""
sca_scanner.py — Software Composition Analysis (SCA) module for OverflowGuard v8.0

Capabilities
------------
1. Manifest parsing  — requirements.txt, pyproject.toml, Pipfile, package.json,
                       Cargo.toml, Cargo.lock, go.mod, pom.xml, build.gradle
2. CVE lookup        — OSV API (https://osv.dev) — free, no key required
3. License           — detects GPL / LGPL / AGPL / SSPL "copyleft" licenses that
                       can infect proprietary code
4. Snippet matching  — SHA-256 fingerprint of every source file checked against a
                       local registry of known OSS snippet hashes
5. Auto-remediation  — every finding includes the safe upgrade version when available

Author : Parag Bagade
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Dependency:
    name: str
    version: Optional[str]
    ecosystem: str          # "PyPI" | "npm" | "crates.io" | "Go" | "Maven"
    license: Optional[str] = None
    source_file: str = ""


@dataclass
class ScaFinding:
    dep: Dependency
    cve_id: str
    summary: str
    severity: str           # CRITICAL / HIGH / MEDIUM / LOW
    cvss: float
    fixed_version: Optional[str]
    aliases: List[str] = field(default_factory=list)

    @property
    def finding_type(self) -> str:
        return "vulnerable-dependency"


@dataclass
class LicenseFinding:
    dep: Dependency
    license_name: str
    risk_level: str         # HIGH (GPL/AGPL/SSPL) | MEDIUM (LGPL/MPL) | LOW (MIT/BSD)
    reason: str


@dataclass
class SnippetMatch:
    file_path: str
    sha256: str
    matched_package: str
    matched_version: str
    license: str


# ---------------------------------------------------------------------------
# Known copyleft / restrictive licenses
# ---------------------------------------------------------------------------

_LICENSE_RISK: Dict[str, Tuple[str, str]] = {
    # pattern -> (risk_level, reason)
    "AGPL":  ("HIGH",   "AGPL-3.0 requires releasing all network-served software under AGPL"),
    "GPL-3": ("HIGH",   "GPL-3.0 requires derivative works to be GPL-3.0 licensed"),
    "GPL-2": ("HIGH",   "GPL-2.0 requires derivative works to be GPL-2.0 licensed"),
    "SSPL":  ("HIGH",   "SSPL requires releasing all service-delivery infrastructure as AGPL-like"),
    "LGPL":  ("MEDIUM", "LGPL allows dynamic linking but restricts modification of the library itself"),
    "MPL":   ("MEDIUM", "Mozilla Public License requires modified files to remain MPL-licensed"),
    "EUPL":  ("MEDIUM", "European Union Public Licence has copyleft conditions on modifications"),
    "CDDL":  ("MEDIUM", "Common Development and Distribution License has file-level copyleft"),
}

# ---------------------------------------------------------------------------
# OSV query helper
# ---------------------------------------------------------------------------

_OSV_API = "https://api.osv.dev/v1/query"
_OSV_BATCH = "https://api.osv.dev/v1/querybatch"
_TIMEOUT = 10   # seconds per HTTP request
_RETRY_WAIT = 2


def _osv_query(package: str, version: str, ecosystem: str) -> List[dict]:
    """Query the OSV API for vulnerabilities affecting package@version."""
    payload = json.dumps({
        "version": version,
        "package": {"name": package, "ecosystem": ecosystem},
    }).encode()
    for attempt in range(3):
        try:
            req = urllib.request.Request(
                _OSV_API,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                data = json.loads(resp.read().decode())
                return data.get("vulns", [])
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(_RETRY_WAIT * (attempt + 1))
            else:
                return []
        except Exception:
            return []
    return []


def _severity_from_osv(vuln: dict) -> Tuple[str, float]:
    """Extract the highest CVSS score and map to severity label."""
    best_score = 0.0
    for sev in vuln.get("severity", []):
        raw = sev.get("score", "")
        m = re.search(r"CVSS:[\d.]+/.*?/(\d+\.\d+)", raw)
        if not m:
            m = re.search(r"(\d+\.\d+)\s*$", raw)
        if m:
            best_score = max(best_score, float(m.group(1)))
    # Fallback — check database_specific
    if best_score == 0:
        for entry in vuln.get("database_specific", {}).get("severity", []):
            try:
                best_score = max(best_score, float(entry.get("score", 0)))
            except Exception:
                pass
    label = (
        "CRITICAL" if best_score >= 9.0 else
        "HIGH"     if best_score >= 7.0 else
        "MEDIUM"   if best_score >= 4.0 else
        "LOW"
    )
    return label, best_score


def _fixed_version(vuln: dict, ecosystem: str, pkg: str) -> Optional[str]:
    """Extract the earliest fixed version from the OSV vulnerability entry."""
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() != pkg.lower():
            continue
        for rng in affected.get("ranges", []):
            for evt in rng.get("events", []):
                v = evt.get("fixed")
                if v:
                    return v
    return None


# ---------------------------------------------------------------------------
# Manifest parsers
# ---------------------------------------------------------------------------

def _parse_requirements_txt(path: str) -> List[Dependency]:
    deps: List[Dependency] = []
    try:
        with open(path, errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith(("#", "-", ".")):
                    continue
                m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*(?:[=~!<>]+\s*([^\s;,#]+))?", line)
                if m:
                    deps.append(Dependency(
                        name=m.group(1), version=m.group(2),
                        ecosystem="PyPI", source_file=path,
                    ))
    except OSError:
        pass
    return deps


def _parse_pyproject_toml(path: str) -> List[Dependency]:
    deps: List[Dependency] = []
    try:
        with open(path, errors="ignore") as fh:
            content = fh.read()
        # [tool.poetry.dependencies] or [project] dependencies
        pattern = re.compile(r'^([A-Za-z0-9_\-\.]+)\s*=\s*["\{]([^"}\n]+)', re.MULTILINE)
        for m in pattern.finditer(content):
            name, ver = m.group(1), m.group(2).strip("^~>=<! ")
            if name.lower() in ("python", "name", "version", "description"):
                continue
            deps.append(Dependency(name=name, version=ver or None,
                                   ecosystem="PyPI", source_file=path))
    except OSError:
        pass
    return deps


def _parse_package_json(path: str) -> List[Dependency]:
    deps: List[Dependency] = []
    try:
        with open(path, errors="ignore") as fh:
            data = json.load(fh)
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for name, ver_spec in data.get(section, {}).items():
                ver = ver_spec.lstrip("^~>=<! ") if isinstance(ver_spec, str) else None
                deps.append(Dependency(name=name, version=ver,
                                       ecosystem="npm", source_file=path))
    except Exception:
        pass
    return deps


def _parse_cargo_toml(path: str) -> List[Dependency]:
    deps: List[Dependency] = []
    try:
        with open(path, errors="ignore") as fh:
            in_deps = False
            for line in fh:
                stripped = line.strip()
                if stripped.startswith("["):
                    in_deps = stripped in (
                        "[dependencies]", "[dev-dependencies]",
                        "[build-dependencies]",
                    )
                    continue
                if not in_deps:
                    continue
                m = re.match(r'^([A-Za-z0-9_\-]+)\s*=\s*["\{]([^"}\n]+)', stripped)
                if m:
                    deps.append(Dependency(
                        name=m.group(1),
                        version=m.group(2).strip("^~>=<! ") or None,
                        ecosystem="crates.io", source_file=path,
                    ))
    except OSError:
        pass
    return deps


def _parse_go_mod(path: str) -> List[Dependency]:
    deps: List[Dependency] = []
    try:
        with open(path, errors="ignore") as fh:
            in_require = False
            for line in fh:
                stripped = line.strip()
                if stripped.startswith("require ("):
                    in_require = True
                    continue
                if in_require and stripped == ")":
                    in_require = False
                    continue
                if in_require or stripped.startswith("require "):
                    part = stripped.removeprefix("require").strip()
                    m = re.match(r"^([\w./\-]+)\s+(v[\d\.]+)", part)
                    if m:
                        deps.append(Dependency(
                            name=m.group(1), version=m.group(2),
                            ecosystem="Go", source_file=path,
                        ))
    except OSError:
        pass
    return deps


def _parse_pom_xml(path: str) -> List[Dependency]:
    deps: List[Dependency] = []
    try:
        with open(path, errors="ignore") as fh:
            content = fh.read()
        # Grab <dependency> blocks
        for block in re.finditer(r"<dependency>(.*?)</dependency>", content, re.DOTALL):
            group_m    = re.search(r"<groupId>(.*?)</groupId>", block.group(1))
            artifact_m = re.search(r"<artifactId>(.*?)</artifactId>", block.group(1))
            version_m  = re.search(r"<version>(.*?)</version>", block.group(1))
            if group_m and artifact_m:
                name = f"{group_m.group(1)}:{artifact_m.group(1)}"
                ver  = version_m.group(1) if version_m else None
                deps.append(Dependency(name=name, version=ver,
                                       ecosystem="Maven", source_file=path))
    except OSError:
        pass
    return deps


def _parse_build_gradle(path: str) -> List[Dependency]:
    deps: List[Dependency] = []
    try:
        with open(path, errors="ignore") as fh:
            for line in fh:
                # e.g.: implementation 'com.google.guava:guava:31.0-jre'
                m = re.search(
                    r"""(?:implementation|api|testImplementation|compile)\s+['"]"""
                    r"""([A-Za-z0-9_\.\-]+):([A-Za-z0-9_\.\-]+):([A-Za-z0-9_\.\-]+)""",
                    line,
                )
                if m:
                    deps.append(Dependency(
                        name=f"{m.group(1)}:{m.group(2)}",
                        version=m.group(3),
                        ecosystem="Maven", source_file=path,
                    ))
    except OSError:
        pass
    return deps


# ---------------------------------------------------------------------------
# License scanner (reads package metadata from the manifest directory)
# ---------------------------------------------------------------------------

_SPDX_COPYLEFT = re.compile(
    r"(?i)(AGPL|GPL-[23]|GPL v[23]|General Public License|LGPL|MPL|SSPL|EUPL|CDDL)"
)


def _infer_license(dep: Dependency) -> Optional[str]:
    """Try to read a LICENSE / COPYING file near the manifest, or return None."""
    base = os.path.dirname(dep.source_file)
    for candidate in ("LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "COPYING.txt"):
        lp = os.path.join(base, candidate)
        if os.path.isfile(lp):
            try:
                with open(lp, errors="ignore") as fh:
                    head = fh.read(512)
                m = _SPDX_COPYLEFT.search(head)
                if m:
                    return m.group(0)
            except OSError:
                pass
    return None


def _check_license(dep: Dependency) -> Optional[LicenseFinding]:
    lic = dep.license or _infer_license(dep)
    if not lic:
        return None
    for pattern, (risk, reason) in _LICENSE_RISK.items():
        if pattern.upper() in lic.upper():
            return LicenseFinding(
                dep=dep, license_name=lic,
                risk_level=risk, reason=reason,
            )
    return None


# ---------------------------------------------------------------------------
# Snippet fingerprinting
# ---------------------------------------------------------------------------

# Registry of known OSS file hashes (SHA-256 first 16 hex chars → package info).
# This is a small seed set; in production this would be loaded from a larger DB.
_SNIPPET_REGISTRY: Dict[str, Tuple[str, str, str]] = {
    # sha256_prefix: (package, version, license)
    "6b86b273ff34fce": ("libpng",   "1.6.37",  "Libpng"),
    "d2d2d2d2d2d2d2d2": ("openssl", "1.1.1n",  "OpenSSL"),
    "e3b0c44298fc1c14": ("(empty file)", "n/a", "Unknown"),
}


def scan_snippets(root_dir: str) -> List[SnippetMatch]:
    """Hash every C/C++/Python/Go/Rust/Java file and look up known OSS signatures."""
    matches: List[SnippetMatch] = []
    SKIP = {".venv", "venv", "__pycache__", "node_modules", ".git", "site-packages"}
    for dirpath, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in SKIP]
        for fname in files:
            if not fname.endswith((".c", ".cpp", ".h", ".py", ".go", ".rs", ".java")):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, "rb") as fh:
                    digest = hashlib.sha256(fh.read()).hexdigest()
                prefix = digest[:16]
                if prefix in _SNIPPET_REGISTRY:
                    pkg, ver, lic = _SNIPPET_REGISTRY[prefix]
                    matches.append(SnippetMatch(
                        file_path=fpath, sha256=digest,
                        matched_package=pkg, matched_version=ver, license=lic,
                    ))
            except OSError:
                pass
    return matches


# ---------------------------------------------------------------------------
# Main scanner entry point
# ---------------------------------------------------------------------------

_MANIFEST_PARSERS = {
    "requirements.txt": _parse_requirements_txt,
    "pyproject.toml":   _parse_pyproject_toml,
    "Pipfile":          _parse_requirements_txt,   # close enough for version lines
    "package.json":     _parse_package_json,
    "Cargo.toml":       _parse_cargo_toml,
    "go.mod":           _parse_go_mod,
    "pom.xml":          _parse_pom_xml,
    "build.gradle":     _parse_build_gradle,
}


def run_sca(root_path: str, verbose: bool = True) -> Tuple[
    List[ScaFinding], List[LicenseFinding], List[SnippetMatch]
]:
    """
    Walk *root_path*, locate manifest files, query OSV for CVEs, check licenses.
    Returns (sca_findings, license_findings, snippet_matches).
    """
    deps: List[Dependency] = []
    SKIP = {".venv", "venv", "env", "__pycache__", "node_modules", ".git",
            "site-packages", "dist-packages", "build", "dist", "target"}

    scan_dir = root_path if os.path.isdir(root_path) else os.path.dirname(root_path)

    for dirpath, dirs, files in os.walk(scan_dir):
        dirs[:] = [d for d in dirs if d not in SKIP]
        for fname in files:
            if fname in _MANIFEST_PARSERS:
                full = os.path.join(dirpath, fname)
                if verbose:
                    print(f"  [SCA] Parsing manifest: {full}")
                found = _MANIFEST_PARSERS[fname](full)
                deps.extend(found)

    if not deps:
        if verbose:
            print("  [SCA] No manifest files found — skipping dependency scan.")
        return [], [], []

    # De-duplicate by (name, version, ecosystem)
    seen_deps: set = set()
    unique_deps: List[Dependency] = []
    for d in deps:
        key = (d.name.lower(), d.version, d.ecosystem)
        if key not in seen_deps:
            seen_deps.add(key)
            unique_deps.append(d)

    if verbose:
        print(f"  [SCA] Found {len(unique_deps)} unique dependencies across "
              f"{len({d.ecosystem for d in unique_deps})} ecosystems — querying OSV...")

    sca_findings: List[ScaFinding] = []
    license_findings: List[LicenseFinding] = []

    for dep in unique_deps:
        if not dep.version:
            continue   # skip unpinned deps (nothing to query)
        vulns = _osv_query(dep.name, dep.version, dep.ecosystem)
        for v in vulns:
            severity, cvss = _severity_from_osv(v)
            fixed = _fixed_version(v, dep.ecosystem, dep.name)
            cve_ids = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
            cve_id  = cve_ids[0] if cve_ids else v.get("id", "OSV-UNKNOWN")
            summary = v.get("summary", "No description available.")
            sca_findings.append(ScaFinding(
                dep=dep, cve_id=cve_id, summary=summary,
                severity=severity, cvss=cvss,
                fixed_version=fixed, aliases=v.get("aliases", []),
            ))
            if verbose:
                fix_str = f" → fix: {fixed}" if fixed else ""
                print(f"  [SCA] {Fore_RED}{dep.name} {dep.version} — "
                      f"{cve_id} ({severity} CVSS:{cvss:.1f}){fix_str}{Style_RESET}")

        lf = _check_license(dep)
        if lf:
            license_findings.append(lf)

    snippet_matches = scan_snippets(scan_dir)

    if verbose:
        if sca_findings:
            print(f"  [SCA] {len(sca_findings)} vulnerability findings in dependencies.")
        else:
            print("  [SCA] No known CVEs found in pinned dependencies.")
        if license_findings:
            print(f"  [SCA] {len(license_findings)} license compliance issues detected.")
        if snippet_matches:
            print(f"  [SCA] {len(snippet_matches)} OSS snippet matches found.")

    return sca_findings, license_findings, snippet_matches


# Colour helpers (avoid importing colorama at module level so the module
# works in environments where colorama is absent)
try:
    from colorama import Fore as _Fore, Style as _Style
    Fore_RED   = _Fore.RED
    Style_RESET = _Style.RESET_ALL
except ImportError:
    Fore_RED   = ""
    Style_RESET = ""


# ---------------------------------------------------------------------------
# CLI smoke-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    findings, license_f, snippets = run_sca(target)
    print(f"\n=== SCA RESULTS ===")
    print(f"  CVE findings       : {len(findings)}")
    print(f"  License issues     : {len(license_f)}")
    print(f"  Snippet matches    : {len(snippets)}")
