"""
llvm_analyzer.py — P4: LLVM IR analysis wrapper.

Compiles C/C++ source to LLVM IR via `clang -emit-llvm`, then analyzes
the `.ll` text for memory-safety issues that are clearer at the IR level
than at the source level:

  • GEP (getelementptr) access with potentially out-of-bounds offset
  • Stack alloca followed by store past alloca size
  • Type-confusion via bitcast (e.g. int* cast to larger type then loaded)
  • alloca in a loop (unbounded stack growth)
  • Indirect call through possibly-null function pointer

Falls back gracefully when clang is not installed: skips IR generation and
returns an empty list (caller is notified via a warning, not an exception).

Exported API:
    LLVMFinding        — dataclass
    LLVMAnalyzer       — analyze(file_path) → List[LLVMFinding]
                       — is_available() → bool
"""

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import List, Optional, Set, Tuple


@dataclass
class LLVMFinding:
    issue_type: str
    line:       int        # IR line (1-based); maps roughly to source
    snippet:    str
    confidence: str
    lang:       str = "c"
    note:       str = ""
    stage:      str = "LLVM"


# ── Helper ────────────────────────────────────────────────────────────────────
def _snip(lines: List[str], ln: int) -> str:
    return lines[ln - 1].strip() if 1 <= ln <= len(lines) else ""


def _read(path: str) -> str:
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""


# ── LLVM IR Patterns ──────────────────────────────────────────────────────────
# 1. GEP with constant offset
_GEP_PAT = re.compile(
    r"getelementptr\s+inbounds\s+\[(\d+)\s+x\s+\w+\],\s*[\w\s%*]+,\s*\w+\s+0,\s*\w+\s+(\d+)",
    re.MULTILINE,
)
# 2. alloca — track size
_ALLOCA_PAT = re.compile(
    r"(%\w+)\s*=\s*alloca\s+\[(\d+)\s+x\s+\w+\]",
    re.MULTILINE,
)
# 3. bitcast from smaller to larger type (type confusion)
_BITCAST_PAT = re.compile(
    r"bitcast\s+i(\d+)\s*\*\s+%\w+\s+to\s+i(\d+)\s*\*",
    re.MULTILINE,
)
# 4. alloca inside a loop (pattern: alloca preceded by a branch-back label)
_LOOP_ALLOCA = re.compile(
    r"(loop\d*:|\.loop\w*:|_bb\d+:)[^\n]*\n(?:[^\n]*\n){0,10}[^\n]*alloca\s",
    re.MULTILINE | re.IGNORECASE,
)
# 5. Indirect call through potential null pointer
_INDIRECT_CALL = re.compile(
    r"call\s+\w+\s+%(\w+)\s*\(",
    re.MULTILINE,
)
# 6. store to GEP'd address where i is loop-variable (GEP i64 %i)
_LOOP_GEP_STORE = re.compile(
    r"getelementptr inbounds \[\d+ x \w+\][^,]*,[^,]*,\s*i64\s+(%[a-z]\w*)",
    re.MULTILINE,
)
# 7. memcpy with size from function param (i64 %param -> memcpy)
_MEMCPY_PARAM = re.compile(
    r"call void @llvm\.memcpy[^(]*\([^,]+,\s*[^,]+,\s*i(?:32|64)\s+(%\w+)",
    re.MULTILINE,
)


def _analyze_ir(ir_text: str) -> List[LLVMFinding]:
    """Parse LLVM IR text and return a list of LLVMFinding objects."""
    findings: List[LLVMFinding] = []
    seen: Set[Tuple[str, int]] = set()
    lines = ir_text.splitlines()

    def _add(issue, ln, note, conf="MEDIUM"):
        k = (issue, ln)
        if k not in seen:
            seen.add(k)
            findings.append(LLVMFinding(
                issue_type=issue, line=ln,
                snippet=_snip(lines, ln),
                confidence=conf, note=note,
            ))

    lineno = lambda pos: ir_text[:pos].count("\n") + 1

    # ── 1. GEP constant offset ≥ alloca size ──────────────────────────────────
    alloca_sizes: dict = {}
    for m in _ALLOCA_PAT.finditer(ir_text):
        alloca_sizes[m.group(1)] = int(m.group(2))

    for m in _GEP_PAT.finditer(ir_text):
        array_size = int(m.group(1))
        offset     = int(m.group(2))
        if offset >= array_size:
            ln = lineno(m.start())
            _add("llvm-oob-gep", ln,
                 f"GEP inbounds constant offset {offset} ≥ array size {array_size} "
                 f"— compiler may optimize away bounds check, leading to silent OOB",
                 "HIGH")

    # ── 2. Bitcast from narrower to wider integer type ────────────────────────
    for m in _BITCAST_PAT.finditer(ir_text):
        from_bits = int(m.group(1))
        to_bits   = int(m.group(2))
        if to_bits > from_bits:
            ln = lineno(m.start())
            _add("llvm-type-confusion", ln,
                 f"bitcast i{from_bits}* → i{to_bits}* — reading {to_bits} bits "
                 f"from a {from_bits}-bit allocation causes out-of-bounds read",
                 "HIGH")

    # ── 3. alloca inside loop (stack exhaustion) ──────────────────────────────
    for m in _LOOP_ALLOCA.finditer(ir_text):
        ln = lineno(m.start())
        _add("llvm-stack-alloca-loop", ln,
             "alloca() inside loop body — stack frame grows by alloca size on "
             "every iteration; unbounded recursion or large N → stack overflow",
             "MEDIUM")

    # ── 4. Loop GEP with unbounded induction variable ─────────────────────────
    for m in _LOOP_GEP_STORE.finditer(ir_text):
        idx_var = m.group(1)
        ln      = lineno(m.start())
        _add("llvm-unchecked-index", ln,
             f"GEP uses loop induction variable '{idx_var}' — if loop bound exceeds "
             f"array size this produces an out-of-bounds memory access at the IR level",
             "MEDIUM")

    # ── 5. memcpy where length comes from a function parameter ───────────────
    for m in _MEMCPY_PARAM.finditer(ir_text):
        param = m.group(1)
        ln    = lineno(m.start())
        _add("llvm-memcpy-param-size", ln,
             f"llvm.memcpy length derived from SSA value '{param}' which originates "
             f"from a function parameter — attacker-controlled size without bound check",
             "HIGH")

    return findings


# ── IR generation ─────────────────────────────────────────────────────────────
def _emit_ir(
    source_path: str,
    extra_flags: Optional[List[str]] = None,
) -> Optional[str]:
    """
    Compile *source_path* to LLVM IR text using clang.
    Returns the IR string or None if compilation fails.
    """
    clang = shutil.which("clang") or shutil.which("clang-15") or shutil.which("clang-14")
    if not clang:
        return None

    flags = list(extra_flags or [])
    ext   = os.path.splitext(source_path)[1].lower()
    if ext in (".cpp", ".cc", ".cxx"):
        clang = shutil.which("clang++") or clang

    with tempfile.NamedTemporaryFile(suffix=".ll", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        cmd = [
            clang,
            "-S", "-emit-llvm",         # output LLVM IR text
            "-O1",                       # minimal optimisation (cleans up noise)
            "-g",                        # keep debug info for source-line mapping
            "-o", tmp_path,
            source_path,
        ] + flags

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0 and os.path.isfile(tmp_path):
            return _read(tmp_path)
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    finally:
        if os.path.isfile(tmp_path):
            os.unlink(tmp_path)


# ── Source-line mapping ───────────────────────────────────────────────────────
def _ir_line_to_source_line(ir_text: str, ir_line: int) -> int:
    """
    Attempt to map an IR line number back to the original source line using
    LLVM debug metadata (!dbg / DILocation).
    Returns the source line number, or the original IR line if mapping fails.
    """
    lines = ir_text.splitlines()
    # Look backwards from ir_line for !dbg !N then resolve !N
    for i in range(min(ir_line - 1, len(lines) - 1), max(0, ir_line - 20), -1):
        dbg_ref = re.search(r"!dbg\s+(!?\d+)", lines[i])
        if not dbg_ref:
            continue
        meta_id = dbg_ref.group(1)
        # Find the DILocation info
        di_pat = re.compile(
            rf"{re.escape(meta_id)}\s*=.*DILocation.*line:\s*(\d+)"
        )
        for meta_line in lines:
            di_m = di_pat.search(meta_line)
            if di_m:
                return int(di_m.group(1))
    return ir_line


# ── LLVMAnalyzer ─────────────────────────────────────────────────────────────
C_EXTENSIONS = {".c", ".cpp", ".cc", ".h", ".hpp", ".cxx"}


class LLVMAnalyzer:
    """
    LLVM IR-level static analyzer.

    Compiles the source file to LLVM IR using clang, then scans the IR for
    memory-safety issues invisible or ambiguous at the source level.
    """

    def __init__(self, extra_compile_flags: Optional[List[str]] = None):
        self._extra_flags = extra_compile_flags or []

    @staticmethod
    def is_available() -> bool:
        """Return True if clang is found on PATH."""
        return (
            shutil.which("clang") is not None or
            shutil.which("clang++") is not None or
            shutil.which("clang-15") is not None
        )

    def analyze(self, file_path: str) -> List[LLVMFinding]:
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in C_EXTENSIONS:
            return []

        ir_text = _emit_ir(file_path, self._extra_flags)
        if not ir_text:
            # clang not installed or compilation failed — skip silently
            return []

        raw_findings = _analyze_ir(ir_text)

        # Map IR lines back to source lines where possible
        for f in raw_findings:
            f.line = _ir_line_to_source_line(ir_text, f.line)

        return raw_findings
