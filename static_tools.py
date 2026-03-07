"""
static_tools.py — cppcheck and clang-tidy integration.

Runs external tools, parses their output, and returns structured findings
that map into the same VULN_DATA keys used by the rest of the pipeline.
"""

import subprocess
import shutil
import re
import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional, List


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------
@dataclass
class ToolFinding:
    tool: str
    issue_id: str          # cppcheck id or clang-tidy check name
    severity: str          # "error" | "warning" | "style" | "performance" etc.
    message: str
    file: str
    line: int
    col: int = 0
    mapped_type: Optional[str] = None   # key into VULN_DATA; None = best-effort


# ---------------------------------------------------------------------------
# cppcheck id → VULN_DATA key
# ---------------------------------------------------------------------------
CPPCHECK_MAP = {
    "bufferAccessOutOfBounds":      "heap-buffer-overflow",
    "bufferOverflow":               "stack-buffer-overflow",
    "stackBufferOverflow":          "stack-buffer-overflow",
    "heapBufferOverflow":           "heap-buffer-overflow",
    "arrayIndexOutOfBounds":        "stack-buffer-overflow",
    "outOfBounds":                  "heap-buffer-overflow",
    "writeOutsideBufferSize":       "heap-buffer-overflow",
    "useAfterFree":                 "use-after-free",
    "doubleFree":                   "use-after-free",
    "memleakOnRealloc":             "memory-leak",
    "memleak":                      "memory-leak",
    "resourceLeak":                 "memory-leak",
    "nullPointer":                  "null-pointer",
    "nullPointerRedundantCheck":    "null-pointer",
    "integerOverflow":              "integer-overflow",
    "signedIntegerOverflow":        "integer-overflow",
    "unsignedIntegerOverflow":      "integer-overflow",
    "integerOverflowCond":          "integer-overflow",
    "divisionByZero":               "division-by-zero",
}

# ---------------------------------------------------------------------------
# clang-tidy check prefix → VULN_DATA key
# ---------------------------------------------------------------------------
CLANG_TIDY_MAP = {
    "clang-analyzer-security.insecureAPI.strcpy":   "stack-buffer-overflow",
    "clang-analyzer-security.insecureAPI.gets":     "stack-buffer-overflow",
    "clang-analyzer-security.insecureAPI.sprintf":  "stack-buffer-overflow",
    "clang-analyzer-security.insecureAPI.scanf":    "stack-buffer-overflow",
    "clang-analyzer-security.insecureAPI.strncat":  "stack-buffer-overflow",
    "clang-analyzer-security.insecureAPI.vfork":    "os-injection",
    "clang-analyzer-alpha.security.ArrayBound":     "stack-buffer-overflow",
    "clang-analyzer-cplusplus.NewDelete":           "use-after-free",
    "clang-analyzer-cplusplus.NewDeleteLeaks":      "memory-leak",
    "clang-analyzer-unix.Malloc":                   "heap-buffer-overflow",
    "clang-analyzer-unix.API":                      "heap-buffer-overflow",
    "clang-analyzer-core.NullDereference":          "null-pointer",
    "clang-analyzer-core.DivideZero":               "division-by-zero",
    "bugprone-integer-division":                    "integer-overflow",
    "bugprone-use-after-move":                      "use-after-free",
    "cert-err34-c":                                 "integer-overflow",
    "cert-str31-c":                                 "stack-buffer-overflow",
    "cert-msc30-c":                                 "integer-overflow",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def is_available(tool: str) -> bool:
    return shutil.which(tool) is not None


def _map_clang_tidy_check(check: str) -> Optional[str]:
    """Return mapped vulnerability type for a clang-tidy check name."""
    # Exact match first
    if check in CLANG_TIDY_MAP:
        return CLANG_TIDY_MAP[check]
    # Prefix match
    for key, val in CLANG_TIDY_MAP.items():
        if check.startswith(key):
            return val
    return None


# ---------------------------------------------------------------------------
# cppcheck runner
# ---------------------------------------------------------------------------
def run_cppcheck(file_path: str) -> List[ToolFinding]:
    """Run cppcheck with XML-v2 output and return parsed ToolFinding list."""
    findings: List[ToolFinding] = []

    if not is_available("cppcheck"):
        return findings

    try:
        result = subprocess.run(
            [
                "cppcheck",
                "--enable=all",
                "--inconclusive",
                "--xml",
                "--xml-version=2",
                "--suppress=missingIncludeSystem",
                "--suppress=missingInclude",
                "--suppress=unmatchedSuppression",
                file_path,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        # cppcheck writes XML to stderr
        xml_text = result.stderr.strip()
        if not xml_text:
            return findings

        root = ET.fromstring(xml_text)

        for error in root.iter("error"):
            error_id  = error.get("id", "")
            severity  = error.get("severity", "unknown")
            message   = error.get("msg", "No message")
            cwe       = error.get("cwe", "")
            if cwe:
                message = f"[CWE-{cwe}] {message}"

            # Skip pure informational/noise
            if severity in ("information",) or error_id in (
                "toomanyconfigs", "checkLibraryFunction",
                "checkLibraryNoReturn", "checkLibraryUseReturnValue",
            ):
                continue

            location = error.find("location")
            if location is not None:
                err_file = location.get("file", file_path)
                line = int(location.get("line", "0"))
                col  = int(location.get("column", "0"))
            else:
                err_file = file_path
                line = 0
                col  = 0

            findings.append(ToolFinding(
                tool="cppcheck",
                issue_id=error_id,
                severity=severity,
                message=message,
                file=err_file,
                line=line,
                col=col,
                mapped_type=CPPCHECK_MAP.get(error_id),
            ))

    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        pass
    except ET.ParseError:
        pass

    return findings


# ---------------------------------------------------------------------------
# clang-tidy runner
# ---------------------------------------------------------------------------
def run_clang_tidy(file_path: str) -> List[ToolFinding]:
    """Run clang-tidy with security/bugprone checks and return findings."""
    findings: List[ToolFinding] = []

    if not is_available("clang-tidy"):
        return findings

    checks = ",".join([
        "clang-analyzer-security.*",
        "clang-analyzer-cplusplus.*",
        "clang-analyzer-core.*",
        "clang-analyzer-unix.*",
        "clang-analyzer-alpha.security.*",
        "bugprone-*",
        "cert-*",
    ])

    try:
        result = subprocess.run(
            [
                "clang-tidy",
                f"--checks=-*,{checks}",
                "--warnings-as-errors=", 
                "--",
                file_path,
                "-std=c11",
                "-I/usr/include",
                "-I/usr/local/include",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        output = result.stdout + result.stderr

        # Pattern: /path/file.c:10:5: warning: message [check-name]
        pattern = re.compile(
            r"^(?P<file>[^:]+):(?P<line>\d+):(?P<col>\d+):\s+"
            r"(?P<severity>error|warning|note):\s+(?P<message>.+?)"
            r"\s+\[(?P<check>[^\]]+)\]$",
            re.MULTILINE,
        )

        for m in pattern.finditer(output):
            check = m.group("check")
            # Drop pure compiler diagnostics
            if check.startswith("clang-diagnostic-"):
                continue

            findings.append(ToolFinding(
                tool="clang-tidy",
                issue_id=check,
                severity=m.group("severity"),
                message=m.group("message"),
                file=m.group("file"),
                line=int(m.group("line")),
                col=int(m.group("col")),
                mapped_type=_map_clang_tidy_check(check),
            ))

    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        pass

    return findings


# ---------------------------------------------------------------------------
# Convenience: run all available tools and deduplicate
# ---------------------------------------------------------------------------
def run_all(file_path: str) -> List[ToolFinding]:
    """Run cppcheck and clang-tidy, return deduplicated findings."""
    all_findings: List[ToolFinding] = []
    all_findings.extend(run_cppcheck(file_path))
    all_findings.extend(run_clang_tidy(file_path))

    # Deduplicate by (mapped_type or issue_id, line)
    seen: set = set()
    unique: List[ToolFinding] = []
    for f in all_findings:
        key = (f.mapped_type or f.issue_id, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique
