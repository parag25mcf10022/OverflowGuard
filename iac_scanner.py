"""
iac_scanner.py — Infrastructure-as-Code security scanner for OverflowGuard v11.0

Scans Terraform (.tf), Kubernetes YAML, Dockerfiles, CloudFormation (YAML/JSON),
Ansible playbooks, and Helm charts for security misconfigurations.

No external dependencies — all detection is regex/pattern-based.

Copyright 2026 Parag Bagade — MIT Licence
"""

from __future__ import annotations
import os
import re
import json
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple

# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class IaCFinding:
    file_path: str
    line: int
    rule_id: str
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    issue_type: str        # e.g. "iac-public-s3-bucket"
    description: str
    remediation: str
    snippet: str = ""
    cwe: str = "CWE-16"   # default: Configuration
    framework: str = ""    # terraform | kubernetes | docker | cloudformation | ansible

# ---------------------------------------------------------------------------
# Terraform scanner
# ---------------------------------------------------------------------------

_TF_RULES: List[Dict] = [
    {
        "id": "TF001", "severity": "CRITICAL",
        "pattern": r'acl\s*=\s*"public-read"',
        "issue": "iac-public-s3-bucket",
        "desc": "S3 bucket has public-read ACL — anyone on the internet can read its contents.",
        "fix": 'Set acl = "private" and use bucket policies for controlled access.',
    },
    {
        "id": "TF002", "severity": "CRITICAL",
        "pattern": r'acl\s*=\s*"public-read-write"',
        "issue": "iac-public-s3-bucket",
        "desc": "S3 bucket has public-read-write ACL — anyone can read AND write.",
        "fix": 'Set acl = "private" immediately. Enable S3 Block Public Access.',
    },
    {
        "id": "TF003", "severity": "HIGH",
        "pattern": r'ingress\s*\{[^}]*cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
        "issue": "iac-open-security-group",
        "desc": "Security group ingress allows traffic from 0.0.0.0/0 (entire internet).",
        "fix": "Restrict cidr_blocks to known IP ranges or VPC CIDR.",
    },
    {
        "id": "TF004", "severity": "HIGH",
        "pattern": r'(?:from_port|to_port)\s*=\s*0.*(?:from_port|to_port)\s*=\s*65535',
        "issue": "iac-overly-permissive-ports",
        "desc": "Security group rule opens all ports (0-65535).",
        "fix": "Open only the specific ports your application needs.",
    },
    {
        "id": "TF005", "severity": "HIGH",
        "pattern": r'encrypted\s*=\s*false',
        "issue": "iac-unencrypted-storage",
        "desc": "Storage resource has encryption disabled.",
        "fix": "Set encrypted = true and configure a KMS key.",
    },
    {
        "id": "TF006", "severity": "MEDIUM",
        "pattern": r'versioning\s*\{[^}]*enabled\s*=\s*false',
        "issue": "iac-no-versioning",
        "desc": "S3 bucket versioning is disabled — data loss risk.",
        "fix": "Enable versioning: versioning { enabled = true }",
    },
    {
        "id": "TF007", "severity": "MEDIUM",
        "pattern": r'logging\s*\{?\s*\}|access_logs\s*\{?\s*enabled\s*=\s*false',
        "issue": "iac-no-logging",
        "desc": "Resource has logging disabled — incident response will be blind.",
        "fix": "Enable access logging and ship logs to a central SIEM.",
    },
    {
        "id": "TF008", "severity": "HIGH",
        "pattern": r'(?:password|secret|api_key|token)\s*=\s*"[^"]{4,}"',
        "issue": "iac-hardcoded-secret",
        "desc": "Hardcoded secret/password in Terraform configuration.",
        "fix": "Use terraform variables with sensitive=true or a secrets manager (Vault, AWS SSM).",
    },
    {
        "id": "TF009", "severity": "HIGH",
        "pattern": r'publicly_accessible\s*=\s*true',
        "issue": "iac-public-database",
        "desc": "Database is publicly accessible from the internet.",
        "fix": "Set publicly_accessible = false and use VPC private subnets.",
    },
    {
        "id": "TF010", "severity": "MEDIUM",
        "pattern": r'protocol\s*=\s*"-1"',
        "issue": "iac-all-protocols",
        "desc": 'Security group allows all protocols (protocol = "-1").',
        "fix": "Specify only the required protocols (tcp, udp).",
    },
    {
        "id": "TF011", "severity": "HIGH",
        "pattern": r'deletion_protection\s*=\s*false',
        "issue": "iac-no-deletion-protection",
        "desc": "Deletion protection disabled on critical resource.",
        "fix": "Set deletion_protection = true for production databases and load balancers.",
    },
    {
        "id": "TF012", "severity": "MEDIUM",
        "pattern": r'multi_az\s*=\s*false',
        "issue": "iac-single-az",
        "desc": "Resource deployed in single availability zone — no HA.",
        "fix": "Set multi_az = true for production workloads.",
    },
    {
        "id": "TF013", "severity": "HIGH",
        "pattern": r'ssl_policy\s*=\s*"(?:ELBSecurityPolicy-2016-08|ELBSecurityPolicy-TLS-1-0)"',
        "issue": "iac-weak-tls",
        "desc": "Load balancer using outdated TLS policy (TLS 1.0/1.1).",
        "fix": 'Use ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06" or newer.',
    },
    {
        "id": "TF014", "severity": "MEDIUM",
        "pattern": r'enable_key_rotation\s*=\s*false',
        "issue": "iac-no-key-rotation",
        "desc": "KMS key rotation is disabled.",
        "fix": "Set enable_key_rotation = true.",
    },
]


# ---------------------------------------------------------------------------
# Kubernetes YAML scanner
# ---------------------------------------------------------------------------

_K8S_RULES: List[Dict] = [
    {
        "id": "K8S001", "severity": "CRITICAL",
        "pattern": r'privileged\s*:\s*true',
        "issue": "iac-privileged-container",
        "desc": "Container running in privileged mode — full host access.",
        "fix": "Set securityContext.privileged: false.",
    },
    {
        "id": "K8S002", "severity": "HIGH",
        "pattern": r'runAsUser\s*:\s*0\b',
        "issue": "iac-run-as-root",
        "desc": "Container running as root (UID 0).",
        "fix": "Set runAsUser to a non-root UID (e.g., 1000) and runAsNonRoot: true.",
    },
    {
        "id": "K8S003", "severity": "HIGH",
        "pattern": r'allowPrivilegeEscalation\s*:\s*true',
        "issue": "iac-privilege-escalation",
        "desc": "Container allows privilege escalation.",
        "fix": "Set allowPrivilegeEscalation: false.",
    },
    {
        "id": "K8S004", "severity": "MEDIUM",
        "pattern": r'readOnlyRootFilesystem\s*:\s*false',
        "issue": "iac-writable-rootfs",
        "desc": "Container has writable root filesystem.",
        "fix": "Set readOnlyRootFilesystem: true and use volumeMounts for writable dirs.",
    },
    {
        "id": "K8S005", "severity": "HIGH",
        "pattern": r'hostNetwork\s*:\s*true',
        "issue": "iac-host-network",
        "desc": "Pod uses host network namespace — bypasses network policies.",
        "fix": "Remove hostNetwork: true unless absolutely required.",
    },
    {
        "id": "K8S006", "severity": "HIGH",
        "pattern": r'hostPID\s*:\s*true',
        "issue": "iac-host-pid",
        "desc": "Pod shares host PID namespace — can see all host processes.",
        "fix": "Remove hostPID: true.",
    },
    {
        "id": "K8S007", "severity": "MEDIUM",
        "pattern": r'(?:image|Image)\s*:\s*\S+(?::latest\b|[^:])\s*$',
        "issue": "iac-latest-tag",
        "desc": "Container image uses :latest tag or no tag — unpredictable deployments.",
        "fix": "Pin image to a specific digest or semantic version tag.",
    },
    {
        "id": "K8S008", "severity": "MEDIUM",
        "pattern": r'capabilities\s*:\s*\n\s*add\s*:\s*\n\s*-\s*(?:ALL|SYS_ADMIN|NET_ADMIN)',
        "issue": "iac-excessive-capabilities",
        "desc": "Container granted dangerous Linux capabilities.",
        "fix": "Drop ALL capabilities and add back only what's needed.",
    },
    {
        "id": "K8S009", "severity": "HIGH",
        "pattern": r'type\s*:\s*(?:NodePort|LoadBalancer)',
        "issue": "iac-exposed-service",
        "desc": "Service exposed externally (NodePort/LoadBalancer) without explicit need.",
        "fix": "Use ClusterIP for internal services. Use an Ingress controller for controlled exposure.",
    },
    {
        "id": "K8S010", "severity": "MEDIUM",
        "pattern": r'(?:limits|requests)\s*:(?!\s*\n\s+(?:cpu|memory))',
        "issue": "iac-no-resource-limits",
        "desc": "Container without CPU/memory resource limits — risk of resource exhaustion.",
        "fix": "Set resources.limits and resources.requests for cpu and memory.",
    },
    {
        "id": "K8S011", "severity": "HIGH",
        "pattern": r'automountServiceAccountToken\s*:\s*true',
        "issue": "iac-automount-sa-token",
        "desc": "Service account token auto-mounted — can be used for lateral movement.",
        "fix": "Set automountServiceAccountToken: false unless the pod needs Kubernetes API access.",
    },
]

# ---------------------------------------------------------------------------
# Dockerfile scanner
# ---------------------------------------------------------------------------

_DOCKER_RULES: List[Dict] = [
    {
        "id": "DF001", "severity": "HIGH",
        "pattern": r'^FROM\s+\S+:latest\b',
        "issue": "iac-docker-latest-base",
        "desc": "Dockerfile uses :latest base image — unpredictable builds.",
        "fix": "Pin to a specific version: FROM python:3.11-slim-bookworm",
    },
    {
        "id": "DF002", "severity": "CRITICAL",
        "pattern": r'^USER\s+root\s*$',
        "issue": "iac-docker-root-user",
        "desc": "Container explicitly runs as root.",
        "fix": "Add a non-root USER: RUN adduser --disabled-password app && USER app",
    },
    {
        "id": "DF003", "severity": "HIGH",
        "pattern": r'(?:ENV|ARG)\s+(?:PASSWORD|SECRET|API_KEY|TOKEN|AWS_SECRET)\s*=\s*\S+',
        "issue": "iac-docker-secret-env",
        "desc": "Secret value hardcoded in Dockerfile ENV/ARG — visible in image history.",
        "fix": "Use Docker secrets, BuildKit secrets (--mount=type=secret), or runtime env vars.",
    },
    {
        "id": "DF004", "severity": "MEDIUM",
        "pattern": r'^ADD\s+https?://',
        "issue": "iac-docker-add-url",
        "desc": "ADD with remote URL — no checksum verification, prone to MITM.",
        "fix": "Use RUN curl + sha256sum verification, or COPY from a build stage.",
    },
    {
        "id": "DF005", "severity": "LOW",
        "pattern": r'apt-get\s+install(?!.*--no-install-recommends)',
        "issue": "iac-docker-no-recommends",
        "desc": "apt-get install without --no-install-recommends — bloated image.",
        "fix": "Add --no-install-recommends to reduce attack surface.",
    },
    {
        "id": "DF006", "severity": "MEDIUM",
        "pattern": r'EXPOSE\s+(?:22|23|3389|5900)\b',
        "issue": "iac-docker-admin-port",
        "desc": "Container exposes administrative port (SSH/Telnet/RDP/VNC).",
        "fix": "Remove the EXPOSE directive. Use kubectl exec or docker exec for debugging.",
    },
    {
        "id": "DF007", "severity": "MEDIUM",
        "pattern": r'COPY\s+\.\s+\.',
        "issue": "iac-docker-copy-all",
        "desc": "COPY . . copies everything including .git, secrets, dev files.",
        "fix": "Add a .dockerignore file and COPY only needed files.",
    },
    {
        "id": "DF008", "severity": "MEDIUM",
        "pattern": r'chmod\s+777\b',
        "issue": "iac-docker-chmod-777",
        "desc": "chmod 777 in Dockerfile — world-writable files.",
        "fix": "Use the least-privilege permissions (e.g., chmod 755 or 644).",
    },
    {
        "id": "DF009", "severity": "HIGH",
        "pattern": r'--security-opt\s+(?:no-new-privileges\s*=\s*false|apparmor\s*=\s*unconfined|seccomp\s*=\s*unconfined)',
        "issue": "iac-docker-security-disabled",
        "desc": "Docker security features explicitly disabled.",
        "fix": "Keep security options enabled: --security-opt no-new-privileges=true",
    },
]

# ---------------------------------------------------------------------------
# CloudFormation scanner
# ---------------------------------------------------------------------------

_CFN_RULES: List[Dict] = [
    {
        "id": "CFN001", "severity": "CRITICAL",
        "pattern": r'(?:PublicAccessBlockConfiguration|BlockPublicAcls)\s*:\s*(?:false|"false")',
        "issue": "iac-cfn-public-s3",
        "desc": "S3 bucket public access block is disabled.",
        "fix": "Set BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets to true.",
    },
    {
        "id": "CFN002", "severity": "HIGH",
        "pattern": r'CidrIp\s*:\s*(?:")?0\.0\.0\.0/0',
        "issue": "iac-cfn-open-sg",
        "desc": "Security group ingress from 0.0.0.0/0.",
        "fix": "Restrict CidrIp to specific ranges.",
    },
    {
        "id": "CFN003", "severity": "HIGH",
        "pattern": r'(?:SSEAlgorithm|ServerSideEncryptionConfiguration)\s*:\s*(?:false|"false"|"none")',
        "issue": "iac-cfn-no-encryption",
        "desc": "Server-side encryption disabled.",
        "fix": "Enable SSE with SSEAlgorithm: aws:kms or AES256.",
    },
    {
        "id": "CFN004", "severity": "HIGH",
        "pattern": r'PubliclyAccessible\s*:\s*(?:true|"true")',
        "issue": "iac-cfn-public-rds",
        "desc": "RDS instance publicly accessible.",
        "fix": "Set PubliclyAccessible to false.",
    },
    {
        "id": "CFN005", "severity": "MEDIUM",
        "pattern": r'DeletionPolicy\s*:\s*(?:Delete|"Delete")',
        "issue": "iac-cfn-no-retain",
        "desc": "Resource will be deleted on stack deletion — data loss risk.",
        "fix": "Set DeletionPolicy to Retain or Snapshot for critical resources.",
    },
    {
        "id": "CFN006", "severity": "MEDIUM",
        "pattern": r'MultiAZ\s*:\s*(?:false|"false")',
        "issue": "iac-cfn-single-az",
        "desc": "RDS not configured for Multi-AZ — no automatic failover.",
        "fix": "Set MultiAZ to true for production databases.",
    },
]

# ---------------------------------------------------------------------------
# Ansible scanner
# ---------------------------------------------------------------------------

_ANSIBLE_RULES: List[Dict] = [
    {
        "id": "ANS001", "severity": "HIGH",
        "pattern": r'(?:password|secret|token)\s*:\s*(?!"\{\{)["\'][^"\']{4,}',
        "issue": "iac-ansible-hardcoded-secret",
        "desc": "Hardcoded secret in Ansible playbook (not using vault).",
        "fix": "Use ansible-vault to encrypt secrets or reference external vault.",
    },
    {
        "id": "ANS002", "severity": "MEDIUM",
        "pattern": r'become\s*:\s*(?:yes|true)(?!.*become_user)',
        "issue": "iac-ansible-become-root",
        "desc": "Task uses become without specifying become_user — defaults to root.",
        "fix": "Specify become_user with least-privilege account.",
    },
    {
        "id": "ANS003", "severity": "HIGH",
        "pattern": r'(?:shell|command)\s*:.*(?:curl|wget)\s+.*\|\s*(?:sh|bash)',
        "issue": "iac-ansible-pipe-to-shell",
        "desc": "Downloading and piping to shell — MITM / supply-chain risk.",
        "fix": "Download file, verify checksum, then execute.",
    },
    {
        "id": "ANS004", "severity": "MEDIUM",
        "pattern": r'mode\s*:\s*["\']?0?777',
        "issue": "iac-ansible-chmod-777",
        "desc": "File permissions set to 777 — world-writable.",
        "fix": "Use minimum required permissions (e.g., 0644, 0755).",
    },
]

# ---------------------------------------------------------------------------
# Framework detector
# ---------------------------------------------------------------------------

_FRAMEWORK_EXTENSIONS: Dict[str, str] = {
    ".tf": "terraform",
    ".tfvars": "terraform",
}

_FRAMEWORK_FILENAMES: Dict[str, str] = {
    "Dockerfile": "docker",
    "docker-compose.yml": "docker",
    "docker-compose.yaml": "docker",
}


def _detect_framework(file_path: str) -> Optional[str]:
    """Detect the IaC framework from the file path/extension."""
    basename = os.path.basename(file_path)
    ext = os.path.splitext(file_path)[1].lower()

    # Exact filename match
    if basename in _FRAMEWORK_FILENAMES:
        return _FRAMEWORK_FILENAMES[basename]
    if basename.startswith("Dockerfile"):
        return "docker"

    # Extension match
    if ext in _FRAMEWORK_EXTENSIONS:
        return _FRAMEWORK_EXTENSIONS[ext]

    # YAML-based detection (K8s, CloudFormation, Ansible)
    if ext in (".yml", ".yaml"):
        try:
            with open(file_path, "r", errors="ignore") as fh:
                head = fh.read(4096)
            if "AWSTemplateFormatVersion" in head or "AWS::" in head:
                return "cloudformation"
            if "apiVersion:" in head and "kind:" in head:
                return "kubernetes"
            if "hosts:" in head and ("tasks:" in head or "roles:" in head):
                return "ansible"
            # Helm — check parent dir
            if os.path.basename(os.path.dirname(file_path)) == "templates":
                chart_path = os.path.join(os.path.dirname(os.path.dirname(file_path)), "Chart.yaml")
                if os.path.isfile(chart_path):
                    return "kubernetes"  # Helm template
        except (OSError, UnicodeDecodeError):
            pass

    # JSON CloudFormation
    if ext == ".json":
        try:
            with open(file_path, "r", errors="ignore") as fh:
                head = fh.read(2048)
            if "AWSTemplateFormatVersion" in head:
                return "cloudformation"
        except (OSError, UnicodeDecodeError):
            pass

    return None


# ---------------------------------------------------------------------------
# Scanner engine
# ---------------------------------------------------------------------------

_RULE_MAP: Dict[str, List[Dict]] = {
    "terraform": _TF_RULES,
    "kubernetes": _K8S_RULES,
    "docker": _DOCKER_RULES,
    "cloudformation": _CFN_RULES,
    "ansible": _ANSIBLE_RULES,
}

# IaC-relevant extensions for directory walking
IAC_EXTENSIONS = {".tf", ".tfvars", ".yml", ".yaml", ".json"}
IAC_FILENAMES = {"Dockerfile", "docker-compose.yml", "docker-compose.yaml"}


def _scan_file(file_path: str, framework: str) -> List[IaCFinding]:
    """Scan a single IaC file against the rules for its framework."""
    rules = _RULE_MAP.get(framework, [])
    if not rules:
        return []

    try:
        with open(file_path, "r", errors="ignore") as fh:
            content = fh.read()
        lines = content.splitlines()
    except (OSError, UnicodeDecodeError):
        return []

    findings: List[IaCFinding] = []
    for rule in rules:
        flags = re.MULTILINE | re.IGNORECASE if framework == "docker" else re.MULTILINE
        for m in re.finditer(rule["pattern"], content, flags):
            # Find line number
            line_no = content[:m.start()].count("\n") + 1
            snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""
            findings.append(IaCFinding(
                file_path=file_path,
                line=line_no,
                rule_id=rule["id"],
                severity=rule["severity"],
                issue_type=rule["issue"],
                description=rule["desc"],
                remediation=rule["fix"],
                snippet=snippet,
                framework=framework,
            ))

    return findings


def scan_iac_file(file_path: str) -> List[IaCFinding]:
    """Scan a single file for IaC misconfigurations (auto-detects framework)."""
    fw = _detect_framework(file_path)
    if fw is None:
        return []
    return _scan_file(file_path, fw)


def scan_iac_directory(root_path: str, verbose: bool = False) -> List[IaCFinding]:
    """Walk a directory tree and scan all IaC files."""
    SKIP_DIRS = {
        ".git", ".hg", ".svn", "node_modules", "__pycache__",
        ".venv", "venv", ".tox", ".terraform",
    }

    all_findings: List[IaCFinding] = []
    files_scanned = 0

    for dirpath, dirs, files in os.walk(root_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            fpath = os.path.join(dirpath, fname)
            ext = os.path.splitext(fname)[1].lower()
            if fname in IAC_FILENAMES or ext in IAC_EXTENSIONS or fname.startswith("Dockerfile"):
                fw = _detect_framework(fpath)
                if fw:
                    findings = _scan_file(fpath, fw)
                    if findings:
                        all_findings.extend(findings)
                        files_scanned += 1
                        if verbose:
                            for f in findings:
                                print(f"  [{f.severity}] {f.rule_id}: {f.description[:80]} "
                                      f"({os.path.relpath(fpath, root_path)}:{f.line})")

    if verbose:
        if all_findings:
            print(f"  IaC scan: {len(all_findings)} finding(s) in {files_scanned} file(s)")
        else:
            print(f"  IaC scan: No misconfigurations found")

    return all_findings


# ---------------------------------------------------------------------------
# Summary helpers
# ---------------------------------------------------------------------------

def iac_summary(findings: List[IaCFinding]) -> str:
    """Return a one-line summary string."""
    if not findings:
        return "No IaC misconfigurations detected"
    by_sev = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    parts = [f"{cnt} {sev}" for sev, cnt in sorted(by_sev.items(), key=lambda x: -{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x[0], 0))]
    return f"{len(findings)} IaC misconfig(s): {', '.join(parts)}"


def get_iac_frameworks_found(findings: List[IaCFinding]) -> List[str]:
    """Return deduplicated list of frameworks with findings."""
    return sorted(set(f.framework for f in findings))
