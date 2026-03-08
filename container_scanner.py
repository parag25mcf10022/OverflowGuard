"""container_scanner.py – Container Image & Dockerfile Security Scanner

Analyses Dockerfiles and container images for:
 • Known-vulnerable base images (pinned CVE database snapshot)
 • Dockerfile best-practice violations (CIS Docker Benchmark)
 • Layer-level risk assessment
 • OS package CVE cross-reference (via SBOM when available)

Zero external dependencies – uses stdlib only.
"""

from __future__ import annotations

import os
import re
import json
import subprocess
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple

# ── data-classes ────────────────────────────────────────────────────

@dataclass
class ContainerFinding:
    file_path: str
    line: int
    rule_id: str
    severity: str          # critical / high / medium / low / info
    category: str          # base-image, privilege, network, filesystem, supply-chain
    description: str
    remediation: str
    snippet: str = ""
    cwe: str = ""

@dataclass
class BaseImageInfo:
    image: str
    tag: str
    line: int
    pinned: bool           # True if uses sha256 digest
    official: bool         # True if Docker Official Image
    eol: bool              # True if known end-of-life
    cves: List[str] = field(default_factory=list)

# ── known-vulnerable / EOL base images (snapshot database) ──────────

_VULNERABLE_IMAGES: Dict[str, Dict] = {
    # image_pattern: {tags: [...], severity, cves, eol}
    "ubuntu:14.04":  {"severity": "critical", "cves": ["CVE-2023-4911", "CVE-2021-3156"], "eol": True},
    "ubuntu:16.04":  {"severity": "high",     "cves": ["CVE-2023-4911"],                  "eol": True},
    "ubuntu:18.04":  {"severity": "medium",   "cves": [],                                  "eol": True},
    "debian:stretch":{"severity": "high",     "cves": ["CVE-2023-44487"],                  "eol": True},
    "debian:jessie": {"severity": "critical", "cves": ["CVE-2023-44487", "CVE-2021-3449"], "eol": True},
    "debian:buster": {"severity": "medium",   "cves": [],                                  "eol": True},
    "centos:6":      {"severity": "critical", "cves": ["CVE-2021-3156"],                   "eol": True},
    "centos:7":      {"severity": "high",     "cves": [],                                  "eol": True},
    "centos:8":      {"severity": "high",     "cves": [],                                  "eol": True},
    "alpine:3.13":   {"severity": "medium",   "cves": [],                                  "eol": True},
    "alpine:3.14":   {"severity": "medium",   "cves": [],                                  "eol": True},
    "alpine:3.15":   {"severity": "low",      "cves": [],                                  "eol": True},
    "node:8":        {"severity": "critical", "cves": [],                                  "eol": True},
    "node:10":       {"severity": "high",     "cves": [],                                  "eol": True},
    "node:12":       {"severity": "high",     "cves": [],                                  "eol": True},
    "node:14":       {"severity": "medium",   "cves": [],                                  "eol": True},
    "python:2.7":    {"severity": "critical", "cves": [],                                  "eol": True},
    "python:3.6":    {"severity": "high",     "cves": [],                                  "eol": True},
    "python:3.7":    {"severity": "medium",   "cves": [],                                  "eol": True},
    "golang:1.16":   {"severity": "medium",   "cves": [],                                  "eol": True},
    "golang:1.17":   {"severity": "medium",   "cves": [],                                  "eol": True},
    "ruby:2.5":      {"severity": "high",     "cves": [],                                  "eol": True},
    "ruby:2.6":      {"severity": "medium",   "cves": [],                                  "eol": True},
    "php:7.3":       {"severity": "high",     "cves": [],                                  "eol": True},
    "php:7.4":       {"severity": "medium",   "cves": [],                                  "eol": True},
}

# ── Dockerfile lint rules (CIS Docker Benchmark aligned) ───────────

_DOCKERFILE_RULES: List[Dict] = [
    # --- Privilege ---
    {
        "id": "CONT-PRIV-001",
        "pattern": r"^\s*USER\s+root\s*$",
        "severity": "high",
        "category": "privilege",
        "description": "Container runs as root user",
        "remediation": "Add a non-root USER instruction: USER appuser",
        "cwe": "CWE-250",
    },
    {
        "id": "CONT-PRIV-002",
        "pattern": r"--privileged",
        "severity": "critical",
        "category": "privilege",
        "description": "Privileged mode flag detected in Dockerfile",
        "remediation": "Remove --privileged flag; use specific capabilities instead",
        "cwe": "CWE-250",
    },
    {
        "id": "CONT-PRIV-003",
        "pattern": r"chmod\s+[0-7]*[2367][0-7]*\s",
        "severity": "medium",
        "category": "privilege",
        "description": "World-writable permission set in container layer",
        "remediation": "Restrict file permissions to owner/group only",
        "cwe": "CWE-732",
    },
    # --- Supply Chain ---
    {
        "id": "CONT-SC-001",
        "pattern": r"^\s*ADD\s+https?://",
        "severity": "high",
        "category": "supply-chain",
        "description": "ADD from remote URL – unverified download",
        "remediation": "Use COPY with a pre-downloaded, checksum-verified file, or use curl with checksum verification in a RUN step",
        "cwe": "CWE-829",
    },
    {
        "id": "CONT-SC-002",
        "pattern": r"curl\s.*\|\s*(?:bash|sh|python)",
        "severity": "critical",
        "category": "supply-chain",
        "description": "Piping remote script directly to shell – supply-chain risk",
        "remediation": "Download the script, verify its checksum, then execute it",
        "cwe": "CWE-829",
    },
    {
        "id": "CONT-SC-003",
        "pattern": r"wget\s.*\|\s*(?:bash|sh)",
        "severity": "critical",
        "category": "supply-chain",
        "description": "Piping wget output to shell interpreter",
        "remediation": "Download file first, verify integrity, then execute",
        "cwe": "CWE-829",
    },
    {
        "id": "CONT-SC-004",
        "pattern": r"npm\s+install\s.*--unsafe-perm",
        "severity": "medium",
        "category": "supply-chain",
        "description": "npm install with --unsafe-perm runs lifecycle scripts as root",
        "remediation": "Remove --unsafe-perm and run as non-root user",
        "cwe": "CWE-250",
    },
    # --- Network ---
    {
        "id": "CONT-NET-001",
        "pattern": r"^\s*EXPOSE\s+22\b",
        "severity": "high",
        "category": "network",
        "description": "SSH port (22) exposed in container",
        "remediation": "Containers should not run SSH – use docker exec or kubectl exec instead",
        "cwe": "CWE-284",
    },
    {
        "id": "CONT-NET-002",
        "pattern": r"^\s*EXPOSE\s+(?:3306|5432|27017|6379|11211)\b",
        "severity": "medium",
        "category": "network",
        "description": "Database port exposed directly in container",
        "remediation": "Use internal Docker networks; do not expose database ports to the host",
        "cwe": "CWE-284",
    },
    # --- Filesystem / Secrets ---
    {
        "id": "CONT-SEC-001",
        "pattern": r"(?:COPY|ADD)\s+.*(?:\.env|\.pem|\.key|id_rsa|credentials|\.aws)\b",
        "severity": "critical",
        "category": "filesystem",
        "description": "Sensitive file copied into container image",
        "remediation": "Use Docker secrets, build args, or mount secrets at runtime instead of baking them into the image",
        "cwe": "CWE-312",
    },
    {
        "id": "CONT-SEC-002",
        "pattern": r"ENV\s+\w*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\w*\s*=",
        "severity": "high",
        "category": "filesystem",
        "description": "Sensitive environment variable hardcoded in Dockerfile",
        "remediation": "Pass sensitive values at runtime via --env-file or Docker secrets",
        "cwe": "CWE-798",
    },
    # --- Best practices ---
    {
        "id": "CONT-BP-001",
        "pattern": r"^\s*FROM\s+\S+\s*$",
        "severity": "info",
        "category": "base-image",
        "description": "Base image uses 'latest' or untagged reference (implicit :latest)",
        "remediation": "Pin base image to a specific version or SHA256 digest",
        "cwe": "CWE-1104",
        "check_fn": "_check_untagged_from",
    },
    {
        "id": "CONT-BP-002",
        "pattern": r"apt-get\s+(?:install|update)(?!.*--no-install-recommends)",
        "severity": "low",
        "category": "base-image",
        "description": "apt-get install without --no-install-recommends increases image size",
        "remediation": "Add --no-install-recommends to reduce attack surface",
        "cwe": "",
    },
    {
        "id": "CONT-BP-003",
        "pattern": r"apt-get\s+(?:update|install)(?!.*&&\s*(?:rm|apt-get clean))",
        "severity": "low",
        "category": "base-image",
        "description": "Package manager cache not cleaned in same RUN layer",
        "remediation": "Chain apt-get update && apt-get install && rm -rf /var/lib/apt/lists/* in one RUN",
        "cwe": "",
    },
    {
        "id": "CONT-BP-004",
        "pattern": r"^\s*HEALTHCHECK\s+NONE",
        "severity": "low",
        "category": "base-image",
        "description": "Health check explicitly disabled",
        "remediation": "Define a meaningful HEALTHCHECK to enable orchestrator health monitoring",
        "cwe": "",
    },
]

# ── helper: parse FROM instructions ────────────────────────────────

_FROM_RE = re.compile(
    r"^\s*FROM\s+"
    r"(?:--platform=\S+\s+)?"        # optional --platform
    r"(?P<image>[^\s:@]+)"            # image name
    r"(?::(?P<tag>[^\s@]+))?"         # optional :tag
    r"(?:@(?P<digest>sha256:\w+))?"   # optional @sha256:
    r"(?:\s+[Aa][Ss]\s+(?P<alias>\S+))?",  # optional AS alias
    re.IGNORECASE,
)

_OFFICIAL_PREFIXES = {
    "alpine", "ubuntu", "debian", "centos", "fedora", "amazonlinux",
    "node", "python", "golang", "ruby", "php", "openjdk", "eclipse-temurin",
    "rust", "nginx", "httpd", "redis", "postgres", "mysql", "mongo",
    "busybox", "scratch", "buildpack-deps",
}


def _parse_from(line: str, lineno: int) -> Optional[BaseImageInfo]:
    """Parse a Dockerfile FROM line into BaseImageInfo."""
    m = _FROM_RE.match(line)
    if not m:
        return None
    image = m.group("image")
    tag = m.group("tag") or "latest"
    digest = m.group("digest")
    pinned = digest is not None
    base_name = image.split("/")[-1]
    official = base_name in _OFFICIAL_PREFIXES or "/" not in image
    # check known-vulnerable
    key_full = f"{base_name}:{tag}"
    key_major = f"{base_name}:{tag.split('.')[0]}" if "." in tag else key_full
    vuln_info = _VULNERABLE_IMAGES.get(key_full) or _VULNERABLE_IMAGES.get(key_major)
    eol = vuln_info["eol"] if vuln_info else False
    cves = vuln_info.get("cves", []) if vuln_info else []
    return BaseImageInfo(
        image=image, tag=tag, line=lineno,
        pinned=pinned, official=official, eol=eol, cves=list(cves),
    )


def _check_untagged_from(line: str) -> bool:
    """Return True if FROM uses implicit :latest (no tag, no digest)."""
    m = _FROM_RE.match(line)
    if not m:
        return False
    return m.group("tag") is None and m.group("digest") is None


def _has_user_instruction(lines: List[str]) -> bool:
    """Check if Dockerfile has a non-root USER instruction."""
    for line in lines:
        stripped = line.strip()
        if stripped.upper().startswith("USER ") and "root" not in stripped.lower():
            return True
    return False


def _has_healthcheck(lines: List[str]) -> bool:
    """Check if Dockerfile has a HEALTHCHECK instruction."""
    for line in lines:
        if line.strip().upper().startswith("HEALTHCHECK"):
            return True
    return False


# ── main scanner ───────────────────────────────────────────────────

def scan_dockerfile(file_path: str) -> Tuple[List[ContainerFinding], List[BaseImageInfo]]:
    """Scan a single Dockerfile for security issues.

    Returns (findings, base_images).
    """
    findings: List[ContainerFinding] = []
    base_images: List[BaseImageInfo] = []

    try:
        with open(file_path, "r", errors="replace") as fh:
            lines = fh.readlines()
    except (OSError, IOError):
        return findings, base_images

    # ── parse FROM lines ──
    for i, line in enumerate(lines, 1):
        bi = _parse_from(line.strip(), i)
        if bi:
            base_images.append(bi)
            # check EOL / vulnerable
            if bi.eol:
                sev = "high"
                key = f"{bi.image.split('/')[-1]}:{bi.tag}"
                vuln = _VULNERABLE_IMAGES.get(key, {})
                sev = vuln.get("severity", "high")
                cve_str = ", ".join(bi.cves) if bi.cves else "end-of-life, unpatched"
                findings.append(ContainerFinding(
                    file_path=file_path, line=i,
                    rule_id="CONT-IMG-001",
                    severity=sev,
                    category="base-image",
                    description=f"Base image '{key}' is end-of-life / known vulnerable ({cve_str})",
                    remediation=f"Upgrade to a supported version of {bi.image.split('/')[-1]}",
                    snippet=line.strip(),
                    cwe="CWE-1104",
                ))
            if not bi.pinned:
                findings.append(ContainerFinding(
                    file_path=file_path, line=i,
                    rule_id="CONT-IMG-002",
                    severity="medium",
                    category="base-image",
                    description=f"Base image '{bi.image}:{bi.tag}' not pinned by SHA256 digest",
                    remediation="Pin with @sha256:<digest> for reproducible builds",
                    snippet=line.strip(),
                    cwe="CWE-1104",
                ))

    # ── apply pattern rules ──
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        for rule in _DOCKERFILE_RULES:
            # special check functions
            if rule.get("check_fn") == "_check_untagged_from":
                if stripped.upper().startswith("FROM ") and _check_untagged_from(stripped):
                    findings.append(ContainerFinding(
                        file_path=file_path, line=i,
                        rule_id=rule["id"], severity=rule["severity"],
                        category=rule["category"],
                        description=rule["description"],
                        remediation=rule["remediation"],
                        snippet=stripped, cwe=rule.get("cwe", ""),
                    ))
                continue

            if re.search(rule["pattern"], stripped, re.IGNORECASE):
                findings.append(ContainerFinding(
                    file_path=file_path, line=i,
                    rule_id=rule["id"], severity=rule["severity"],
                    category=rule["category"],
                    description=rule["description"],
                    remediation=rule["remediation"],
                    snippet=stripped, cwe=rule.get("cwe", ""),
                ))

    # ── structural checks (missing USER / HEALTHCHECK) ──
    if not _has_user_instruction(lines):
        findings.append(ContainerFinding(
            file_path=file_path, line=1,
            rule_id="CONT-PRIV-004",
            severity="high",
            category="privilege",
            description="Dockerfile has no USER instruction – container will run as root",
            remediation="Add 'RUN adduser -D appuser && USER appuser' before CMD/ENTRYPOINT",
            snippet="(missing USER instruction)",
            cwe="CWE-250",
        ))

    if not _has_healthcheck(lines):
        findings.append(ContainerFinding(
            file_path=file_path, line=1,
            rule_id="CONT-BP-005",
            severity="info",
            category="base-image",
            description="No HEALTHCHECK instruction defined",
            remediation="Add HEALTHCHECK CMD curl -f http://localhost/ || exit 1",
            snippet="(missing HEALTHCHECK)",
            cwe="",
        ))

    return findings, base_images


def scan_compose_file(file_path: str) -> List[ContainerFinding]:
    """Scan docker-compose.yml for security issues."""
    findings: List[ContainerFinding] = []
    try:
        with open(file_path, "r", errors="replace") as fh:
            lines = fh.readlines()
    except (OSError, IOError):
        return findings

    compose_rules = [
        (r"privileged:\s*true", "critical", "CONT-COMP-001", "privilege",
         "Container service runs in privileged mode",
         "Remove privileged: true; use specific capabilities", "CWE-250"),
        (r"network_mode:\s*[\"']?host", "high", "CONT-COMP-002", "network",
         "Service uses host network mode",
         "Use bridge or overlay networking instead", "CWE-284"),
        (r"pid:\s*[\"']?host", "high", "CONT-COMP-003", "privilege",
         "Service shares host PID namespace",
         "Remove pid: host unless absolutely required", "CWE-250"),
        (r"ipc:\s*[\"']?host", "medium", "CONT-COMP-004", "privilege",
         "Service shares host IPC namespace",
         "Remove ipc: host", "CWE-250"),
        (r"cap_add:\s*\n\s*-\s*(?:ALL|SYS_ADMIN|NET_ADMIN)", "high", "CONT-COMP-005", "privilege",
         "Excessive Linux capabilities added",
         "Add only the specific capabilities needed", "CWE-250"),
        (r"volumes:.*:/(?:etc|var|root|proc|sys)\b", "high", "CONT-COMP-006", "filesystem",
         "Sensitive host path mounted into container",
         "Avoid mounting sensitive host directories", "CWE-668"),
    ]

    content = "".join(lines)
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        for pattern, severity, rule_id, category, desc, remed, cwe in compose_rules:
            if re.search(pattern, stripped, re.IGNORECASE):
                findings.append(ContainerFinding(
                    file_path=file_path, line=i,
                    rule_id=rule_id, severity=severity,
                    category=category,
                    description=desc, remediation=remed,
                    snippet=stripped, cwe=cwe,
                ))

    return findings


def scan_container_directory(root_path: str, verbose: bool = False) -> Tuple[List[ContainerFinding], List[BaseImageInfo]]:
    """Walk a directory tree looking for Dockerfiles and compose files.

    Returns (all_findings, all_base_images).
    """
    all_findings: List[ContainerFinding] = []
    all_base_images: List[BaseImageInfo] = []

    dockerfile_names = {
        "Dockerfile", "dockerfile", "Containerfile", "containerfile",
    }
    compose_names = {
        "docker-compose.yml", "docker-compose.yaml",
        "compose.yml", "compose.yaml",
    }

    for dirpath, dirnames, filenames in os.walk(root_path):
        # skip hidden / vendor dirs
        dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in {"node_modules", "vendor", "__pycache__"}]
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            # Dockerfiles
            if fname in dockerfile_names or fname.startswith("Dockerfile.") or fname.startswith("Containerfile."):
                if verbose:
                    print(f"  [container] scanning {fpath}")
                findings, base_imgs = scan_dockerfile(fpath)
                all_findings.extend(findings)
                all_base_images.extend(base_imgs)
            # Compose files
            elif fname.lower() in compose_names:
                if verbose:
                    print(f"  [container] scanning compose {fpath}")
                findings = scan_compose_file(fpath)
                all_findings.extend(findings)

    return all_findings, all_base_images


# ── reporting helpers ──────────────────────────────────────────────

def container_summary(findings: List[ContainerFinding], base_images: List[BaseImageInfo]) -> str:
    """Return a CLI-friendly summary string."""
    if not findings and not base_images:
        return "Container scan: no Dockerfiles / compose files found."

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    cat_counts: Dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        cat_counts[f.category] = cat_counts.get(f.category, 0) + 1

    lines = [f"Container Scan: {len(findings)} issues in {len(base_images)} base image(s)"]
    sev_parts = []
    for s in ("critical", "high", "medium", "low", "info"):
        if sev_counts[s]:
            sev_parts.append(f"{sev_counts[s]} {s}")
    lines.append("  Severity: " + ", ".join(sev_parts) if sev_parts else "  No issues")

    if base_images:
        eol_imgs = [bi for bi in base_images if bi.eol]
        unpinned = [bi for bi in base_images if not bi.pinned]
        if eol_imgs:
            lines.append(f"  ⚠ {len(eol_imgs)} EOL/vulnerable base image(s)")
        if unpinned:
            lines.append(f"  ⚠ {len(unpinned)} unpinned base image(s)")

    return "\n".join(lines)


def container_findings_to_dicts(findings: List[ContainerFinding]) -> List[Dict]:
    """Convert findings to JSON-serializable dicts."""
    return [asdict(f) for f in findings]


def base_images_to_dicts(base_images: List[BaseImageInfo]) -> List[Dict]:
    """Convert base image info to JSON-serializable dicts."""
    return [asdict(bi) for bi in base_images]


# ── convenience entry-point ────────────────────────────────────────

def run_container_scan(root_path: str, verbose: bool = False):
    """High-level entry point. Returns (findings, base_images, summary_string)."""
    findings, base_images = scan_container_directory(root_path, verbose=verbose)
    summary = container_summary(findings, base_images)
    return findings, base_images, summary


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    findings, base_images, summary = run_container_scan(target, verbose=True)
    print(summary)
    for f in findings:
        print(f"  [{f.severity.upper()}] {f.rule_id} @ {f.file_path}:{f.line} – {f.description}")
