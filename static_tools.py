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
    "doubleFree":                   "double-free",
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
    "invalidScanfArgType_int":      "stack-buffer-overflow",
    "invalidScanfFormatWidth":      "stack-buffer-overflow",
    "insecureRandSeed":             "weak-rng",
    "prohibitedFunction":           "stack-buffer-overflow",  # gets / scanf family
    "uninitvar":                    "null-pointer",
    "danglingTempReference":        "use-after-free",
    "autoVariables":                "stack-buffer-overflow",
    "returnDanglingLifetime":       "use-after-free",
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
    "clang-analyzer-security.insecureAPI.vfork":    "os-command-injection",
    "clang-analyzer-security.insecureAPI.mktemp":   "insecure-temp-file",
    "clang-analyzer-security.insecureAPI.mkstemp":  "insecure-temp-file",
    "clang-analyzer-security.insecureAPI.rand":     "weak-rng",
    "clang-analyzer-alpha.security.ArrayBound":     "stack-buffer-overflow",
    "clang-analyzer-cplusplus.NewDelete":           "use-after-free",
    "clang-analyzer-cplusplus.NewDeleteLeaks":      "memory-leak",
    "clang-analyzer-unix.Malloc":                   "heap-buffer-overflow",
    "clang-analyzer-unix.API":                      "heap-buffer-overflow",
    "clang-analyzer-core.NullDereference":          "null-pointer",
    "clang-analyzer-core.DivideZero":               "division-by-zero",
    "bugprone-integer-division":                    "integer-overflow",
    "bugprone-use-after-move":                      "use-after-free",
    "bugprone-infinite-loop":                       "off-by-one",
    "bugprone-too-small-loop-variable":             "off-by-one",
    "bugprone-signed-char-misuse":                  "integer-overflow",
    "bugprone-misplaced-widening-cast":             "integer-overflow",
    "cert-err34-c":                                 "integer-overflow",
    "cert-str31-c":                                 "stack-buffer-overflow",
    "cert-msc30-c":                                 "weak-rng",
    "cert-msc50-cpp":                               "weak-rng",
    "cert-fio47-c":                                 "stack-buffer-overflow",
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

# semgrep rule set mapping: partial rule-id → VULN_DATA key
SEMGREP_MAP = {
    "buffer-overflow":                "buffer-overflow",
    "stack-buffer-overflow":          "stack-buffer-overflow",
    "heap-buffer-overflow":           "heap-buffer-overflow",
    "use-after-free":                 "use-after-free",
    "double-free":                    "double-free",
    "off-by-one":                     "off-by-one",
    "integer-overflow":               "integer-overflow",
    "null-dereference":               "null-pointer",
    "format-string":                  "format-string",
    "hardcoded-credential":           "hardcoded-password",
    "hardcoded-secret":               "hardcoded-password",
    "sql-injection":                  "sql-injection",
    "command-injection":              "os-command-injection",
    "path-traversal":                 "path-traversal",
    "ssrf":                           "ssrf",
    "xss":                            "xss",
    "xxe":                            "xxe-injection",
    "insecure-deserialization":       "insecure-deserialization",
    "weak-hash":                      "weak-crypto",
    "weak-crypto":                    "weak-crypto",
    "tls-verification":               "insecure-tls",
    "race-condition":                 "race-condition",
    "use-of-goto":                    "stack-buffer-overflow",
    "dangerous-function":             "stack-buffer-overflow",
    "eval":                           "insecure-eval",
    "pickle":                         "insecure-deserialization",
    "yaml-load":                      "insecure-deserialization",
}


def _map_semgrep_rule(rule_id: str) -> Optional[str]:
    """Map a semgrep rule-id to a VULN_DATA key."""
    rule_lower = rule_id.lower()
    for key, val in SEMGREP_MAP.items():
        if key in rule_lower:
            return val
    return None


def run_semgrep(file_path: str) -> List[ToolFinding]:
    """Run semgrep with the auto ruleset and return parsed ToolFinding list."""
    findings: List[ToolFinding] = []

    if not is_available("semgrep"):
        return findings

    ext = os.path.splitext(file_path)[1].lower()
    # semgrep supports C/C++, Python, Java, Go, Rust
    if ext not in (".c", ".cpp", ".cc", ".py", ".java", ".go", ".rs"):
        return findings

    try:
        result = subprocess.run(
            [
                "semgrep",
                "--config", "auto",
                "--json",
                "--quiet",
                "--timeout", "30",
                file_path,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if not result.stdout.strip():
            return findings

        import json
        data = json.loads(result.stdout)

        for result_item in data.get("results", []):
            rule_id  = result_item.get("check_id", "semgrep")
            message  = result_item.get("extra", {}).get("message", "")
            severity = result_item.get("extra", {}).get("severity", "WARNING").lower()
            start    = result_item.get("start", {})
            line     = int(start.get("line", 0))
            col      = int(start.get("col", 0))

            findings.append(ToolFinding(
                tool="semgrep",
                issue_id=rule_id,
                severity=severity,
                message=message[:200],
                file=file_path,
                line=line,
                col=col,
                mapped_type=_map_semgrep_rule(rule_id),
            ))

    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    return findings


def run_infer(file_path: str) -> List[ToolFinding]:
    """Run Facebook Infer on a C/Java file and return findings.
    Infer writes a report.json to infer-out/ which we parse.
    Only runs for .c/.cpp/.java files.
    """
    findings: List[ToolFinding] = []

    if not is_available("infer"):
        return findings

    ext = os.path.splitext(file_path)[1].lower()
    if ext not in (".c", ".cpp", ".cc", ".java"):
        return findings

    INFER_MAP = {
        "NULL_DEREFERENCE":            "null-pointer",
        "USE_AFTER_FREE":              "use-after-free",
        "DOUBLE_FREE":                 "double-free",
        "MEMORY_LEAK":                 "memory-leak",
        "BUFFER_OVERRUN_L1":           "buffer-overflow",
        "BUFFER_OVERRUN_L2":           "buffer-overflow",
        "BUFFER_OVERRUN_L3":           "buffer-overflow",
        "BUFFER_OVERRUN_U5":           "buffer-overflow",
        "INFERBO_ALLOC_MAY_BE_BIG":    "integer-overflow",
        "INFERBO_ALLOC_IS_ZERO":       "null-pointer",
        "INTEGER_OVERFLOW_L1":         "integer-overflow",
        "INTEGER_OVERFLOW_L2":         "integer-overflow",
        "INTEGER_OVERFLOW_U5":         "integer-overflow",
        "PULSE_USE_AFTER_FREE":        "use-after-free",
        "RESOURCE_LEAK":               "memory-leak",
        "DIVIDE_BY_ZERO":              "division-by-zero",
        "UNINITIALIZED_VALUE":         "null-pointer",
    }

    import tempfile
    import json
    import shutil as _shutil

    outdir = tempfile.mkdtemp(prefix="infer_out_")
    try:
        if ext in (".c", ".cpp", ".cc"):
            compile_cmd = ["gcc" if ext == ".c" else "g++",
                           "-c", file_path, "-o", "/dev/null"]
            cmd = ["infer", "run", "--results-dir", outdir,
                   "--"] + compile_cmd
        else:  # Java
            cmd = ["infer", "run", "--results-dir", outdir,
                   "--", "javac", file_path]

        subprocess.run(cmd, capture_output=True, timeout=60)

        report_path = os.path.join(outdir, "report.json")
        if not os.path.exists(report_path):
            return findings

        with open(report_path) as fh:
            report = json.load(fh)

        for bug in report:
            bug_type = bug.get("bug_type", "")
            line     = int(bug.get("line", 0))
            message  = bug.get("qualifier", "")
            findings.append(ToolFinding(
                tool="infer",
                issue_id=bug_type,
                severity="error",
                message=message[:200],
                file=file_path,
                line=line,
                col=0,
                mapped_type=INFER_MAP.get(bug_type),
            ))

    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    finally:
        _shutil.rmtree(outdir, ignore_errors=True)

    return findings


def run_all(file_path: str) -> List[ToolFinding]:
    """Run cppcheck, clang-tidy, semgrep, and Infer (if available).
    Returns deduplicated findings."""
    all_findings: List[ToolFinding] = []
    all_findings.extend(run_cppcheck(file_path))
    all_findings.extend(run_clang_tidy(file_path))
    all_findings.extend(run_semgrep(file_path))
    all_findings.extend(run_infer(file_path))

    # Deduplicate by (mapped_type or issue_id, line)
    seen: set = set()
    unique: List[ToolFinding] = []
    for f in all_findings:
        key = (f.mapped_type or f.issue_id, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique
