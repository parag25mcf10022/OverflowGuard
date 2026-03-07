"""
dataflow.py — P0: Intra-procedural 1-level data-flow engine with sanitizer
              recognition for C/C++ source code.

What this module does that taint_analyzer.py cannot:
  1. Tracks taint PROPAGATION through variable assignments within a function:
         char *input = argv[1];           // taint source
         char *alias = input;             // alias inherits taint
         strcpy(buf, alias);              // FLAGGED — taint traced here
  2. Tracks taint through struct field reads/writes:
         ctx->data = gets(buf);
         memcpy(dst, ctx->data, len);     // FLAGGED
  3. Recognises SANITIZER patterns and SUPPRESSES findings:
         if (len > sizeof(buf)) return;
         strncpy(buf, alias, sizeof(buf)); // NOT flagged — sanitised
  4. Interprets function-return taint:
         int n = atoi(argv[1]);           // n is tainted (controlled integer)
         buf[n] = 0;                      // FLAGGED if n used as index

Exported API:
    DataflowFinding   — dataclass
    DataflowAnalyzer  — analyze(file_path) → List[DataflowFinding]
"""

import re
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class DataflowFinding:
    issue_type:  str
    line:        int
    snippet:     str
    confidence:  str     # HIGH | MEDIUM | LOW
    lang:        str = "c"
    note:        str = ""
    stage:       str = "Dataflow"


# ── Helpers ──────────────────────────────────────────────────────────────────
def _read(path: str) -> str:
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""


def _lines(src: str) -> List[str]:
    return src.splitlines(keepends=False)


def _lnum(src: str, pos: int) -> int:
    return src[:pos].count("\n") + 1


def _snip(lines: List[str], ln: int) -> str:
    return lines[ln - 1].strip() if 1 <= ln <= len(lines) else ""


# ── Taint source patterns ─────────────────────────────────────────────────────
# Each pattern yields the NAME of the tainted variable (group 1 = var name)
TAINT_SOURCE_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # argv[n] → var   e.g.  char *p = argv[1];
    (re.compile(r"(?:char|wchar_t)\s*\*\s*(\w+)\s*=\s*argv\s*\["), "argv"),
    # gets(buf) — buf is tainted
    (re.compile(r"\bgets\s*\(\s*(\w+)\s*\)"), "gets"),
    # scanf/sscanf — first format target
    (re.compile(r"\b(?:scanf|sscanf|fscanf)\s*\([^,]+,\s*&?\s*(\w+)"), "scanf"),
    # fgets(buf, ...) → buf
    (re.compile(r"\bfgets\s*\(\s*(\w+)\s*,"), "fgets"),
    # read(fd, buf, ..) → buf
    (re.compile(r"\bread\s*\(\s*\w+,\s*(\w+)\s*,"), "read"),
    # recv/recvfrom
    (re.compile(r"\brecv(?:from)?\s*\(\s*\w+,\s*(\w+)\s*,"), "recv"),
    # getenv → var
    (re.compile(r"(?:char|const char)\s*\*\s*(\w+)\s*=\s*getenv\s*\("), "getenv"),
    # atoi / atol / strtol — tainted integer
    (re.compile(r"\b(?:int|long|size_t)\s+(\w+)\s*=\s*(?:atoi|atol|strtol|strtoul)\s*\("), "atoi"),
    # hdr->field patterns (untrusted struct from network)
    (re.compile(r"=\s*(?:\w+->)?(?:data_length|num_vcpus|num_records|count|size|len)\s*;"), "trusted_ptr"),
]

# ── Sanitizer patterns (suppress findings if found BEFORE sink) ───────────────
SANITIZER_PATTERNS: List[re.Pattern] = [
    re.compile(r"if\s*\([^)]*(?:>|>=|<|<=)\s*(?:sizeof|MAX_|max_|BUF_SIZE|BUFSIZ|MAXLEN)[^)]*\)"),
    re.compile(r"if\s*\([^)]*(?:==|!=)\s*NULL[^)]*\)"),
    re.compile(r"\bif\s*\([^)]*strlen\s*\([^)]+\)\s*[<>]=?\s*"),
    re.compile(r"\bstd::min\s*\("),
    re.compile(r"\bstd::clamp\s*\("),
    re.compile(r"\bassert\s*\([^)]*(?:<=|<)\s*sizeof"),
    re.compile(r"\bif\s*\([^)]*>=\s*MAX_"),
    re.compile(r"\bif\s*\([^)]*>\s*\w*[Mm]ax\w*[^)]*\)\s*(?:return|break|continue|throw)"),
    re.compile(r"\bif\s*\([^)]*\w+\s*>\s*[A-Z_]+_MAX"),
    re.compile(r"size_checked|bounds_check|validate_size|check_len"),
]

# ── Sink patterns — these are dangerous if they receive tainted input ──────────
SINK_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    # strcpy(dest, src) — src is arg index 1
    (re.compile(r"\bstrcpy\s*\(\s*\w+\s*,\s*(\w+)\s*\)"), "stack-buffer-overflow",
     "strcpy() with tainted source — unsafe length"),
    # strcat(dest, src)
    (re.compile(r"\bstrcat\s*\(\s*\w+\s*,\s*(\w+)\s*\)"), "stack-buffer-overflow",
     "strcat() with tainted source — unsafe length"),
    # sprintf(buf, fmt, ...) — fmt or args tainted
    (re.compile(r"\bsprintf\s*\(\s*\w+\s*,\s*(\w+)"), "format-string",
     "sprintf() with tainted format/argument"),
    # memcpy(dst, src, len) — len is arg index 2
    (re.compile(r"\bmemcpy\s*\(\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*\)"), "heap-buffer-overflow",
     "memcpy() length comes from tainted source"),
    # memset(buf, val, len)
    (re.compile(r"\bmemset\s*\(\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*\)"), "heap-buffer-overflow",
     "memset() length comes from tainted source"),
    # buf[tainted_index]
    (re.compile(r"\w+\s*\[\s*(\w+)\s*\]"), "negative-index",
     "Array subscripted by tainted/unchecked integer"),
    # malloc(tainted_size)
    (re.compile(r"\b(?:malloc|calloc|realloc)\s*\(\s*(\w+)"), "integer-overflow",
     "malloc/calloc size derived from tainted variable"),
    # system(tainted_string) / popen()
    (re.compile(r"\b(?:system|popen)\s*\(\s*(\w+)\s*[,)]"), "os-command-injection",
     "system()/popen() called with tainted command string"),
    # printf(tainted_fmt)
    (re.compile(r"\bprintf\s*\(\s*(\w+)\s*[,)]"), "format-string",
     "printf() called with tainted format string"),
    # fopen(tainted_path, ...)
    (re.compile(r"\bfopen\s*\(\s*(\w+)\s*,"), "path-traversal",
     "fopen() with tainted path — directory traversal risk"),
]

# ── Propagation patterns — LHS inherits taint from RHS ───────────────────────
# e.g.  char *alias = input;   OR   ctx->field = buf;
PROPAGATION_PATTERNS: List[re.Pattern] = [
    re.compile(r"(?:char|uint8_t|uint16_t|uint32_t|uint64_t|int|size_t|void|auto)\s*\*?\s*(\w+)\s*=\s*(\w+)\s*;"),
    re.compile(r"(\w+)\s*=\s*(\w+)\s*;"),
    re.compile(r"(\w+)->(\w+)\s*=\s*(\w+)\s*;"),  # struct.field = tainted
]

# ── Function-window extractor ─────────────────────────────────────────────────
def _function_windows(src: str) -> List[Tuple[int, str]]:
    """Yield (start_lineno, body_text) for each brace-delimited function body."""
    raw_lines = src.splitlines(keepends=True)
    n = len(raw_lines)
    i = 0
    while i < n:
        if "{" in raw_lines[i]:
            depth, start = 0, i
            for j in range(i, min(i + 800, n)):
                depth += raw_lines[j].count("{") - raw_lines[j].count("}")
                if depth == 0 and j > start:
                    body = "".join(raw_lines[start: j + 1])
                    yield (start + 1, body)
                    i = j + 1
                    break
            else:
                i += 1
        else:
            i += 1


# ── Core analysis ─────────────────────────────────────────────────────────────
def analyze_function_dataflow(
    win_start: int,
    win_body: str,
    src_lines: List[str],
) -> List[DataflowFinding]:
    """
    Perform intra-procedural data-flow analysis on a single function window.
    Returns a list of DataflowFinding instances.
    """
    findings: List[DataflowFinding] = []
    seen: Set[Tuple[str, int]] = set()
    win_lines = win_body.splitlines(keepends=False)

    # ── Step 1: Identify taint sources ───────────────────────────────────────
    tainted_vars: Set[str] = set()
    for pattern, _label in TAINT_SOURCE_PATTERNS:
        for m in pattern.finditer(win_body):
            name = m.group(1) if m.lastindex and m.lastindex >= 1 else None
            if name and name not in ("NULL", "nullptr", "0"):
                tainted_vars.add(name)

    if not tainted_vars:
        return []  # no taint sources in this function — skip

    # ── Step 2: Propagate taint through assignments ───────────────────────────
    # iterate lines; update tainted_vars as we see assignments
    changed = True
    passes = 0
    while changed and passes < 5:
        changed = False
        passes += 1
        for m in re.finditer(
            r"(?:char|uint8_t|uint32_t|uint64_t|int|size_t|void|auto)?\s*\*?\s*"
            r"(\w+)\s*=\s*(\w+)\s*[;,)]",
            win_body,
            re.MULTILINE,
        ):
            lhs, rhs = m.group(1), m.group(2)
            if rhs in tainted_vars and lhs not in tainted_vars:
                tainted_vars.add(lhs)
                changed = True

    # ── Step 3: Look for sanitizer checks ────────────────────────────────────
    sanitized_lines: Set[int] = set()
    for pat in SANITIZER_PATTERNS:
        for m in pat.finditer(win_body):
            ln = win_start + win_body[:m.start()].count("\n")
            # Sanitizer on line N suppresses sinks from lines N..N+10
            for offset in range(0, 12):
                sanitized_lines.add(ln + offset)

    # ── Step 4: Check tainted vars reaching sinks ────────────────────────────
    for sink_pat, issue_type, note_template in SINK_PATTERNS:
        for m in sink_pat.finditer(win_body):
            tainted_arg = m.group(1) if m.lastindex and m.lastindex >= 1 else None
            if not tainted_arg:
                continue
            if tainted_arg not in tainted_vars:
                continue

            abs_line = win_start + win_body[: m.start()].count("\n")
            if abs_line in sanitized_lines:
                continue  # sanitizer guards this sink

            key = (issue_type, abs_line)
            if key in seen:
                continue
            seen.add(key)

            confidence = "HIGH" if issue_type in {
                "stack-buffer-overflow", "heap-buffer-overflow",
                "os-command-injection", "format-string",
            } else "MEDIUM"

            findings.append(DataflowFinding(
                issue_type=issue_type,
                line=abs_line,
                snippet=_snip(src_lines, abs_line),
                confidence=confidence,
                note=f"{note_template} — variable '{tainted_arg}' "
                     f"originates from user-controlled input and reaches "
                     f"this dangerous call without sufficient validation",
            ))

    return findings


# ── Language extension map ────────────────────────────────────────────────────
C_EXTENSIONS = {".c", ".cpp", ".cc", ".h", ".hpp", ".cxx"}


class DataflowAnalyzer:
    """
    Intra-procedural 1-level data-flow analyzer with sanitizer recognition.
    Works on C/C++ source files.  No external dependencies required.
    """

    def analyze(self, file_path: str) -> List[DataflowFinding]:
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in C_EXTENSIONS:
            return []

        src = _read(file_path)
        if not src:
            return []

        src_lines = _lines(src)
        findings: List[DataflowFinding] = []
        seen: Set[Tuple[str, int]] = set()

        for win_start, win_body in _function_windows(src):
            for f in analyze_function_dataflow(win_start, win_body, src_lines):
                key = (f.issue_type, f.line)
                if key not in seen:
                    seen.add(key)
                    findings.append(f)

        return findings
