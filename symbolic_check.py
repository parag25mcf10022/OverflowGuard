"""
symbolic_check.py — P1: Lightweight symbolic range-propagation engine.

Uses Z3 SMT solver when available; falls back to a pure-Python interval
arithmetic engine otherwise.  Both modes share the same public API.

What it provides:
  - Track integer variable ranges through a C/C++ function body
  - Detect when a loop bound, allocation size, or array index can overflow
  - Report whether an overflow is definitively reachable, unreachable, or unknown

Exported API:
    SymbolicFinding      — dataclass
    SymbolicChecker      — analyze(file_path) → List[SymbolicFinding]
    can_overflow(alloc_expr, copy_expr) → "YES" | "NO" | "UNKNOWN"
"""

import re
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Set

# Optional Z3 import
try:
    import z3  # type: ignore
    _HAS_Z3 = True
except ImportError:
    _HAS_Z3 = False


# ── Data model ────────────────────────────────────────────────────────────────
@dataclass
class SymbolicFinding:
    issue_type: str
    line:       int
    snippet:    str
    confidence: str   # HIGH | MEDIUM | LOW
    lang:       str = "c"
    note:       str = ""
    stage:      str = "Symbolic"


# ── Helper ────────────────────────────────────────────────────────────────────
def _read(path: str) -> str:
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""


def _snip(lines: List[str], ln: int) -> str:
    return lines[ln - 1].strip() if 1 <= ln <= len(lines) else ""


# ── Integer interval (pure-Python fallback) ───────────────────────────────────
class Interval:
    """Closed integer interval [lo, hi]; hi=None means unbounded."""
    __slots__ = ("lo", "hi")

    def __init__(self, lo: int = 0, hi: Optional[int] = None):
        self.lo = lo
        self.hi = hi

    def is_bounded(self) -> bool:
        return self.hi is not None

    def __repr__(self) -> str:
        return f"[{self.lo}, {self.hi if self.hi is not None else '∞'}]"

    def join(self, other: "Interval") -> "Interval":
        lo = min(self.lo, other.lo)
        hi = (
            max(self.hi, other.hi)
            if self.hi is not None and other.hi is not None
            else None
        )
        return Interval(lo, hi)

    def can_exceed(self, limit: int) -> bool:
        """Returns True if the interval can exceed *limit*."""
        return self.hi is None or self.hi > limit


# ── Heuristic range extractor ─────────────────────────────────────────────────
# Patterns that constrain a variable's upper bound
_BOUND_PAT = re.compile(
    r"(?:"
    r"if\s*\((\w+)\s*(?:>|>=)\s*(\w+|\d+)\s*\)\s*(?:return|break|continue|throw)"
    r"|(\w+)\s*=\s*std::min\s*\((\w+),\s*(\w+|\d+)\s*\)"
    r"|(\w+)\s*(?:%=|%)\s*(\d+)"          # modulo bound
    r")",
    re.MULTILINE,
)

_DECL_PAT = re.compile(
    r"(?:int|size_t|uint\d+_t|long)\s+(\w+)\s*=\s*(\d+)\s*;",
    re.MULTILINE,
)

_LOOP_PAT = re.compile(
    r"for\s*\(\s*\w+\s+(\w+)\s*=\s*(\d+)\s*;\s*\1\s*<\s*(\w+|\d+)\s*;",
    re.MULTILINE,
)

# Pattern: buf allocated with size X, then accessed / copied with size Y
_ALLOC_PAT = re.compile(
    r"\b(?:malloc|calloc)\s*\(\s*(\w+|\d+)\s*[\),]",
    re.MULTILINE,
)
_COPY_SIZE_PAT = re.compile(
    r"\b(?:memcpy|memmove|strncpy|snprintf)\s*\([^,]+,\s*[^,]+,\s*(\w+|\d+)\s*\)",
    re.MULTILINE,
)


def _eval_const(expr: str, env: Dict[str, int]) -> Optional[int]:
    """Try to evaluate a simple expression or name to an integer constant."""
    if expr.isdigit():
        return int(expr)
    if re.match(r"0x[0-9a-fA-F]+", expr):
        return int(expr, 16)
    define_re = re.compile(
        r"#define\s+(?:BUF_SIZE|MAX_\w+|MAXLEN|\w+)\s+(\d+)"
    )
    return env.get(expr)


def _build_env(src: str) -> Dict[str, int]:
    """Collect integer constants (#define + simple variable initializers)."""
    env: Dict[str, int] = {}
    for m in re.finditer(r"#define\s+(\w+)\s+(\d+)", src):
        env[m.group(1)] = int(m.group(2))
    for m in re.finditer(r"(?:int|size_t|uint\d+_t)\s+(\w+)\s*=\s*(\d+)\s*;", src):
        env[m.group(1)] = int(m.group(2))
    return env


def _collect_bounds(src: str, env: Dict[str, int]) -> Dict[str, Interval]:
    """Return a variable → Interval map derived from guards and assignments."""
    bounds: Dict[str, Interval] = {}
    for m in _BOUND_PAT.finditer(src):
        if m.group(1):  # if (var > limit) return
            var, limit_expr = m.group(1), m.group(2)
            limit = _eval_const(limit_expr, env)
            if limit is not None:
                bounds[var] = Interval(0, limit - 1)
        if m.group(3):  # var = std::min(other, cap)
            var, cap_expr = m.group(3), m.group(5)
            cap = _eval_const(cap_expr, env)
            if cap is not None:
                bounds[var] = Interval(0, cap)
        if m.group(6):  # var %= N
            var, mod_expr = m.group(6), m.group(7)
            mod = _eval_const(mod_expr, env)
            if mod is not None:
                bounds[var] = Interval(0, mod - 1)
    return bounds


# ── Z3-based overflow check ───────────────────────────────────────────────────
def _z3_can_overflow(alloc_size_expr: str, copy_size_expr: str,
                     env: Dict[str, int]) -> str:
    """
    Uses Z3 to determine whether copy_size can exceed alloc_size.
    Returns "YES" | "NO" | "UNKNOWN"
    """
    try:
        alloc_sym = z3.Int("alloc_size")
        copy_sym  = z3.Int("copy_size")
        solver    = z3.Solver()
        solver.set("timeout", 1000)  # 1 second

        alloc_val = _eval_const(alloc_size_expr, env)
        copy_val  = _eval_const(copy_size_expr, env)

        if alloc_val is not None:
            solver.add(alloc_sym == alloc_val)
        else:
            solver.add(alloc_sym > 0, alloc_sym < 2**20)

        if copy_val is not None:
            solver.add(copy_sym == copy_val)
        else:
            solver.add(copy_sym > 0, copy_sym < 2**32)

        solver.add(copy_sym > alloc_sym)  # overflow condition
        result = solver.check()

        if result == z3.sat:
            return "YES"
        elif result == z3.unsat:
            return "NO"
        else:
            return "UNKNOWN"
    except Exception:
        return "UNKNOWN"


# ── Interval-based overflow check ─────────────────────────────────────────────
def _interval_can_overflow(alloc_expr: str, copy_expr: str,
                           bounds: Dict[str, Interval],
                           env: Dict[str, int]) -> str:
    alloc_v = _eval_const(alloc_expr, env)
    copy_v  = _eval_const(copy_expr, env)

    if alloc_v is not None and copy_v is not None:
        return "YES" if copy_v > alloc_v else "NO"

    if alloc_v is not None:
        copy_interval = bounds.get(copy_expr, Interval(0))
        if copy_interval.hi is not None:
            return "YES" if copy_interval.hi > alloc_v else "NO"
        return "UNKNOWN"

    return "UNKNOWN"


def can_overflow(alloc_expr: str, copy_expr: str,
                 env: Optional[Dict[str, int]] = None) -> str:
    """Public API: returns 'YES' | 'NO' | 'UNKNOWN'."""
    e = env or {}
    if _HAS_Z3:
        return _z3_can_overflow(alloc_expr, copy_expr, e)
    bounds = _collect_bounds("", e)
    return _interval_can_overflow(alloc_expr, copy_expr, bounds, e)


# ── Full-file analysis ────────────────────────────────────────────────────────
C_EXTENSIONS = {".c", ".cpp", ".cc", ".h", ".hpp", ".cxx"}


class SymbolicChecker:
    """
    Symbolic range-propagation analyzer.
    Detects definite and probable integer overflows / buffer overflows
    using Z3 (if installed) or a fast interval arithmetic fallback.
    """

    # Patterns: (alloc_var, copy_var)
    _BUF_ALLOC = re.compile(
        r"(?:char|uint8_t|int8_t)\s+(\w+)\s*\[\s*(\w+|\d+)\s*\]\s*;",
    )
    _HEAP_ALLOC = re.compile(
        r"(\w+)\s*=\s*(?:malloc|realloc)\s*\(\s*(\w+|\d+)[^)]*\)",
    )
    _COPY_STMT = re.compile(
        r"\b(?:memcpy|memmove|strncpy|strncat)\s*\(\s*(\w+)[^,]*,\s*[^,]+,\s*(\w+|\d+)\s*\)",
    )
    _IDX_STMT = re.compile(
        r"(\w+)\s*\[\s*(\w+)\s*\]\s*[=;]",
    )
    _LOOP_BOUND = re.compile(
        r"for\s*\([^;]*;\s*\w+\s*<(?:=?)\s*(\w+|\d+)\s*;",
    )
    _CAST_NARROW = re.compile(
        r"\(\s*(?:uint8_t|uint16_t|int8_t|int16_t|char)\s*\)\s*(\w+)",
    )

    def analyze(self, file_path: str) -> List[SymbolicFinding]:
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in C_EXTENSIONS:
            return []

        src = _read(file_path)
        if not src:
            return []

        src_lines = src.splitlines()
        env = _build_env(src)
        bounds = _collect_bounds(src, env)
        findings: List[SymbolicFinding] = []
        seen: Set[Tuple[str, int]] = set()

        def _add(issue, ln, note, conf="MEDIUM"):
            k = (issue, ln)
            if k not in seen:
                seen.add(k)
                findings.append(SymbolicFinding(
                    issue_type=issue, line=ln,
                    snippet=_snip(src_lines, ln),
                    confidence=conf, note=note,
                ))

        # ── 1. Stack buffer + copy size mismatch ─────────────────────────────
        buf_sizes: Dict[str, Tuple[int, str]] = {}  # name → (line, size_expr)
        for m in self._BUF_ALLOC.finditer(src):
            ln = src[:m.start()].count("\n") + 1
            buf_sizes[m.group(1)] = (ln, m.group(2))

        for m in self._COPY_STMT.finditer(src):
            ln   = src[:m.start()].count("\n") + 1
            dest, size_expr = m.group(1), m.group(2)
            if dest in buf_sizes:
                _, alloc_expr = buf_sizes[dest]
                result = (
                    _z3_can_overflow(alloc_expr, size_expr, env)
                    if _HAS_Z3
                    else _interval_can_overflow(alloc_expr, size_expr, bounds, env)
                )
                if result == "YES":
                    _add("stack-buffer-overflow", ln,
                         f"Symbolic check: copy size ({size_expr}) can exceed "
                         f"buffer size ({alloc_expr}) → definite overflow",
                         "HIGH")
                elif result == "UNKNOWN":
                    _add("potential-stack-overflow", ln,
                         f"Symbolic check: cannot prove copy size ({size_expr}) "
                         f"≤ buffer size ({alloc_expr}) — manual review needed",
                         "LOW")

        # ── 2. Heap alloc + copy mismatch ─────────────────────────────────────
        heap_sizes: Dict[str, Tuple[int, str]] = {}
        for m in self._HEAP_ALLOC.finditer(src):
            ln = src[:m.start()].count("\n") + 1
            heap_sizes[m.group(1)] = (ln, m.group(2))

        for m in self._COPY_STMT.finditer(src):
            ln   = src[:m.start()].count("\n") + 1
            dest, size_expr = m.group(1), m.group(2)
            if dest in heap_sizes:
                _, alloc_expr = heap_sizes[dest]
                result = (
                    _z3_can_overflow(alloc_expr, size_expr, env)
                    if _HAS_Z3
                    else _interval_can_overflow(alloc_expr, size_expr, bounds, env)
                )
                if result == "YES":
                    _add("heap-buffer-overflow", ln,
                         f"Symbolic check: copy size ({size_expr}) can exceed "
                         f"heap allocation ({alloc_expr}) → heap overflow",
                         "HIGH")

        # ── 3. Unbounded loop variable used as array index ────────────────────
        for m in self._IDX_STMT.finditer(src):
            ln      = src[:m.start()].count("\n") + 1
            arr, idx = m.group(1), m.group(2)
            if arr in buf_sizes or arr in heap_sizes:
                if idx not in bounds:
                    _add("negative-index", ln,
                         f"Array '{arr}' indexed by '{idx}' — no proven upper "
                         f"bound found for '{idx}' in this context",
                         "LOW")

        # ── 4. Narrow (truncating) cast of large integer ─────────────────────
        for m in self._CAST_NARROW.finditer(src):
            ln  = src[:m.start()].count("\n") + 1
            var = m.group(1)
            interval = bounds.get(var, Interval(0))
            if interval.can_exceed(255):
                _add("integer-truncation", ln,
                     f"Narrow cast of '{var}' which may exceed 255 — "
                     f"truncation could produce unexpected small / negative value",
                     "MEDIUM")

        return findings
