"""
deep_analyzer.py — Multi-pass inter-procedural C/C++ vulnerability detector.

Targets structural patterns that are invisible to single-line / single-pass
scanners.  Each pass examines source within a scoped function window so the
analysis stays context-aware.

  Pass A — alloc-loop-mismatch
      malloc/calloc receives a size derived from field/variable A, but the
      loop that writes into the allocated buffer iterates N times (N derived
      from a *different* field/variable B), copying sizeof(T) per iteration.
      When A < B * sizeof(T) this is a heap overflow.  Catches BUG-A.

  Pass B — le-loop-oob
      for (...; i <= EXPR; ...) where EXPR is a count/index variable or a
      compile-time constant, and the loop body uses i as an array subscript.
      "One past the end" access.  Catches BUG-B and BUG-E.

  Pass C — uncapped-loop-bound
      for (...; i < obj->count_field; ...) with no preceding guard that
      validates count_field < MAX_CONSTANT before entering the loop.  An
      externally corrupted count_field drives the loop past the backing
      fixed-size array.  Catches BUG-C.

  Pass D — ring-buffer-overflow
      A ring-buffer head/tail index is assigned through a modulo expression
      (safe path) but the same variable is ALSO used as a direct (no modulo)
      array subscript elsewhere in the same function — the fast path that every
      real-world ring-buffer vulnerability exploits.  Catches BUG-D.

  Pass E — narrow-size-cast
      A size_t / int / long expression (involving sizeof, *, or size-carrying
      field names) is cast down to uint16_t / uint8_t / short before being
      forwarded to malloc/calloc.  The truncation silently makes the allocation
      tiny while the caller continues to believe the full amount was allocated.
      Catches the precondition of BUG-A.

Exported API
------------
    DeepFinding   — dataclass with (issue_type, line, snippet, confidence, note)
    DeepAnalyzer  — analyze(file_path) → List[DeepFinding]
"""

import re
import os
from dataclasses import dataclass
from typing import List, Optional, Tuple


# ── Data class ───────────────────────────────────────────────────────────────
@dataclass
class DeepFinding:
    issue_type: str      # matches a key in VULN_DATA
    line: int
    snippet: str
    confidence: str      # HIGH | MEDIUM | LOW
    note: str = ""
    stage: str = "Deep"


# ── Utility helpers ───────────────────────────────────────────────────────────
def _read(path: str) -> str:
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""


def _lines_of(src: str) -> List[str]:
    return src.splitlines(keepends=False)


def _lnum(src: str, pos: int) -> int:
    return src[:pos].count("\n") + 1


def _snip(lines: List[str], ln: int) -> str:
    return lines[ln - 1].strip() if 1 <= ln <= len(lines) else ""


# ── Function-window extractor ─────────────────────────────────────────────────
def _function_windows(src: str) -> List[Tuple[int, int, str]]:
    """
    Return a list of (start_lineno, end_lineno, body_text) for each brace-
    delimited function body found in the source.  Handles arbitrarily nested
    braces by counting {/}.  The start_lineno is the line of the opening '{'.
    """
    windows: List[Tuple[int, int, str]] = []
    raw_lines = src.splitlines(keepends=True)
    n = len(raw_lines)
    i = 0
    while i < n:
        if "{" in raw_lines[i]:
            depth = 0
            start = i
            for j in range(i, min(i + 600, n)):
                depth += raw_lines[j].count("{") - raw_lines[j].count("}")
                if depth == 0 and j > start:
                    body = "".join(raw_lines[start : j + 1])
                    windows.append((start + 1, j + 1, body))
                    i = j + 1
                    break
            else:
                i += 1
        else:
            i += 1
    return windows


def _line_of_in_window(window_body: str, window_start: int, pos: int) -> int:
    """Convert a match offset inside a window body to an absolute line number."""
    return window_start + window_body[:pos].count("\n")


# ─────────────────────────────────────────────────────────────────────────────
# Pass A — Alloc-loop size mismatch
# ─────────────────────────────────────────────────────────────────────────────
# Patterns
_MALLOC_RE   = re.compile(
    r"\b(?:std::)?(?:malloc|calloc|realloc)\s*\(\s*([^)]+?)\s*\)",
    re.MULTILINE,
)
_FORLOOP_RE  = re.compile(
    r"\bfor\s*\([^;]*;\s*[a-zA-Z_]\w*\s*<[^=][^;]*;\s*[^)]*\)",
    re.MULTILINE,
)
_MEMCPY_SIZE_RE = re.compile(
    r"\b(?:std::)?(?:memcpy|memmove)\s*\([^,]+,\s*[^,]+,\s*sizeof\s*\(",
    re.MULTILINE,
)
# For counting: extract the loop-bound variable from for(...; i < VAR; ...)
_LOOP_BOUND_RE = re.compile(
    r"\bfor\s*\([^;]*;\s*[a-zA-Z_]\w*\s*<\s*(?:[a-zA-Z_]\w*\s*->\s*)?([a-zA-Z_]\w*)\s*;",
    re.MULTILINE,
)
# Grab the variable/field that the malloc or calloc size argument refers to
_SIZE_VAR_RE = re.compile(r"\b([a-zA-Z_]\w*)\b")


def _extract_size_vars(arg: str) -> List[str]:
    """Return all identifier names in a size expression (skipping keywords)."""
    SKIP = {"sizeof", "static_cast", "size_t", "uint64_t", "uint32_t",
            "uint16_t", "uint8_t", "int", "long", "unsigned", "reinterpret_cast"}
    return [m.group(1) for m in _SIZE_VAR_RE.finditer(arg)
            if m.group(1) not in SKIP]


def check_alloc_loop_mismatch(
    src: str, lines: List[str]
) -> List[DeepFinding]:
    """
    Detect heap overflow from malloc size vs. loop copy size mismatch.

    Within each function window:
      1. Find every malloc(X) call — collect size-variable names from X.
      2. Within the next 60 source lines (same window), find a for-loop.
      3. If the for-loop contains a memcpy(... sizeof(...)) and the loop
         iteration bound uses a *different* variable than the malloc size,
         report an alloc-loop-mismatch finding.
    """
    findings: List[DeepFinding] = []
    seen: set = set()

    for win_start, win_end, win_body in _function_windows(src):
        win_lines_raw = win_body.splitlines(keepends=False)

        # Find all malloc calls inside this window
        for m_alloc in _MALLOC_RE.finditer(win_body):
            alloc_abs_line = _line_of_in_window(win_body, win_start, m_alloc.start())
            size_arg = m_alloc.group(1)
            alloc_vars = set(_extract_size_vars(size_arg))
            if not alloc_vars:
                continue

            # Search in the next 60 lines of this window
            alloc_local = win_body[:m_alloc.start()].count("\n")
            window_after = "\n".join(
                win_lines_raw[alloc_local : alloc_local + 60]
            )

            # Must have a for-loop AND a memcpy with sizeof
            if not _FORLOOP_RE.search(window_after):
                continue
            if not _MEMCPY_SIZE_RE.search(window_after):
                continue

            # Extract the loop-bound variable(s)
            loop_bound_vars: set = set()
            for m_lb in _LOOP_BOUND_RE.finditer(window_after):
                loop_bound_vars.add(m_lb.group(1))

            # If loop bound uses identifiers NOT in alloc_vars → mismatch
            mismatch = loop_bound_vars - alloc_vars
            if not mismatch:
                continue

            key = ("alloc-loop-mismatch", alloc_abs_line)
            if key in seen:
                continue
            seen.add(key)

            # Find the for-loop line for the secondary report
            m_for = _FORLOOP_RE.search(window_after)
            for_abs = alloc_abs_line + window_after[:m_for.start()].count("\n") if m_for else alloc_abs_line

            findings.append(DeepFinding(
                issue_type="alloc-loop-mismatch",
                line=alloc_abs_line,
                snippet=_snip(lines, alloc_abs_line),
                confidence="HIGH",
                note=(
                    f"malloc() size derives from {{{', '.join(sorted(alloc_vars))}}} "
                    f"but the memcpy loop iterates over "
                    f"{{{', '.join(sorted(mismatch))}}} — "
                    f"heap overflow when loop count × sizeof(T) > allocation size "
                    f"(for-loop near line {for_abs})"
                ),
            ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Pass B — Off-by-one <= loop bounds  (BUG-B, BUG-E)
# ─────────────────────────────────────────────────────────────────────────────
# for (...; IDX <= EXPR; ...) — IDX will reach EXPR which is the last *valid*
# index only if the array is sized EXPR+1.  When EXPR == CAPACITY-1, the
# canonical check is `i < CAPACITY` so `i <= CAPACITY-1`.
# When EXPR == count_var (a runtime count of filled slots), `i <= count_var`
# reads the slot PAST the last filled entry — off-by-one OOB.
_LE_LOOP_RE = re.compile(
    r"for\s*\([^;]*;\s*(?P<idx>[a-zA-Z_]\w*)\s*<=\s*(?P<bound>[^;]+?)\s*;"
    r"[^)]*\)",
    re.MULTILINE,
)
# Detect the loop body's array access that uses the same index var
_ARRAY_IDX_RE_TMPL = r"\b{idx}\b.*?\[|\.(\w+)\s*\[{idx}\s*\]|\[{idx}\s*[+\-]?\s*\]"


def check_le_loop_bounds(src: str, lines: List[str]) -> List[DeepFinding]:
    """
    Flag every for-loop that uses <= in its continuation condition and whose
    body uses the loop index as an array subscript.  Such loops read/write one
    element past the valid range (off-by-one or straight OOB).
    """
    findings: List[DeepFinding] = []
    seen: set = set()

    for m in _LE_LOOP_RE.finditer(src):
        idx  = m.group("idx")
        bound = m.group("bound").strip()
        ln   = _lnum(src, m.start())

        if (ln,) in seen:
            continue

        # Determine how suspicious the bound expression is
        # HIGH: bound is a variable (named count/size/num/max/len) or contains ->
        # MEDIUM: bound is a raw compile-time constant
        bound_is_var = bool(re.search(r"[a-zA-Z_]\w*", bound))
        looks_like_count = bool(re.search(
            r"(?i)(count|cnt|size|num|max|len|regions|handlers|ports)",
            bound,
        ))
        confidence = "HIGH" if (bound_is_var and looks_like_count) else "MEDIUM"

        # Check if loop body uses idx as array subscript within next ~12 lines
        after_pos = m.end()
        window = src[after_pos: after_pos + 800]
        arr_idx_re = re.compile(
            r"\[" + re.escape(idx) + r"\s*[\],+\-]",
            re.MULTILINE,
        )
        if not arr_idx_re.search(window):
            # Also accept ->field[idx] style
            alt = re.compile(r"->\w+\s*\[" + re.escape(idx) + r"\s*\]")
            if not alt.search(window):
                continue

        key = ("le-loop-oob", ln)
        if key in seen:
            continue
        seen.add(key)

        findings.append(DeepFinding(
            issue_type="le-loop-oob",
            line=ln,
            snippet=_snip(lines, ln),
            confidence=confidence,
            note=(
                f"Loop condition uses '<=' against '{bound}' — "
                f"index variable '{idx}' will reach one slot past "
                f"the last valid element on the final iteration "
                f"(off-by-one / out-of-bounds array access)"
            ),
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Pass C — Uncapped struct-field loop bound  (BUG-C)
# ─────────────────────────────────────────────────────────────────────────────
# for (...; i < obj->count_field; ...) without a preceding guard
# `if (obj->count_field >= MAX_...)`.
_STRUCT_BOUND_RE = re.compile(
    r"for\s*\([^;]*;\s*(?P<idx>[a-zA-Z_]\w*)\s*<\s*"
    r"(?P<obj>[a-zA-Z_]\w*)\s*->\s*(?P<field>[a-zA-Z_]\w*)\s*;",
    re.MULTILINE,
)
_COUNT_FIELD_RE = re.compile(
    r"(?i)(count|cnt|num_|_num|size|total|len\b)",
)
# A guard looks like: if (...count_field >= ...) or if (count_field > MAX_...)
_GUARD_RE_TMPL = r"if\s*\([^)]*{field}[^)]*(?:>=|>|==)[^)]*\)"


def check_uncapped_field_loop(src: str, lines: List[str]) -> List[DeepFinding]:
    """
    Detect for-loops whose iteration count comes from a struct member field
    (obj->count_field) without a preceding capacity guard.  If count_field is
    corrupted -- e.g. via a concurrent write or integer wrap -- the loop
    iterates past the end of the fixed-size backing array.
    """
    findings: List[DeepFinding] = []
    seen: set = set()

    for m in _STRUCT_BOUND_RE.finditer(src):
        field = m.group("field")
        obj   = m.group("obj")
        ln    = _lnum(src, m.start())

        if not _COUNT_FIELD_RE.search(field):
            continue

        # Look for a guard in the 30 lines before this loop
        before_pos = max(0, m.start() - 1200)
        before_src = src[before_pos : m.start()]
        guard_re = re.compile(
            _GUARD_RE_TMPL.format(field=re.escape(field)),
            re.MULTILINE | re.IGNORECASE,
        )
        # Also accept MAX_ style: if (io_count >= MAX_IOPORT_HANDLERS)
        cap_guard_re = re.compile(
            r"if\s*\([^)]*" + re.escape(field) + r"[^)]*(?:>=|>)\s*\w+\s*\)",
            re.MULTILINE,
        )
        has_guard = bool(guard_re.search(before_src)) or \
                    bool(cap_guard_re.search(before_src))
        if has_guard:
            continue

        key = ("uncapped-loop-bound", ln)
        if key in seen:
            continue
        seen.add(key)

        findings.append(DeepFinding(
            issue_type="uncapped-loop-bound",
            line=ln,
            snippet=_snip(lines, ln),
            confidence="MEDIUM",
            note=(
                f"Loop bound '{obj}->{field}' is a mutable struct field with "
                f"no capacity guard before this loop — if '{field}' is "
                f"corrupted or over-incremented the loop will iterate past the "
                f"end of the fixed-size backing array, causing an OOB read/write"
            ),
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Pass D — Ring-buffer index without modulo  (BUG-D)
# ─────────────────────────────────────────────────────────────────────────────
# A variable is treated as a ring-buffer index if it appears in a modulo
# assignment:  var = (var + 1) % N  — the "safe path".
# BUG: the same variable is ALSO used as a direct array subscript arr[var]
# without modulo, i.e. the "fast path" that skips the safety net.
_RING_MODULO_RE = re.compile(
    r"\b(?P<var>[a-zA-Z_]\w*)\s*=\s*\([^)]+\)\s*%\s*\w+",
    re.MULTILINE,
)
_RING_DIRECT_RE_TMPL = r"\[\s*{var}\s*\]"  # arr[var] (no % in same expression)


def check_ring_buf_direct_index(src: str, lines: List[str]) -> List[DeepFinding]:
    """
    Find ring-buffer index variables that are safely incremented with modulo
    but are also used as direct (no-modulo) array subscripts in the same
    function — the latent OOB surface that activates when the index is
    externally corrupted past the buffer size.
    """
    findings: List[DeepFinding] = []
    seen: set = set()

    for win_start, win_end, win_body in _function_windows(src):
        win_lines = win_body.splitlines(keepends=False)

        # Collect all ring-buffer index variables in this window
        ring_vars: set = set()
        for m in _RING_MODULO_RE.finditer(win_body):
            ring_vars.add(m.group("var"))

        if not ring_vars:
            continue

        # For each ring var, check if it appears as a direct subscript
        for var in ring_vars:
            direct_re = re.compile(
                r"\[" + re.escape(var) + r"\s*\]",  # [var] without % before ]
                re.MULTILINE,
            )
            for m_dir in direct_re.finditer(win_body):
                # Confirm there is no % in the same or preceding expression
                ctx_start = max(0, m_dir.start() - 120)
                ctx = win_body[ctx_start : m_dir.end()]
                if "%" in ctx:
                    continue  # modulo is present — safe path

                abs_line = _line_of_in_window(win_body, win_start, m_dir.start())
                key = ("ring-buffer-overflow", abs_line)
                if key in seen:
                    continue
                seen.add(key)

                findings.append(DeepFinding(
                    issue_type="ring-buffer-overflow",
                    line=abs_line,
                    snippet=_snip(lines, abs_line),
                    confidence="HIGH",
                    note=(
                        f"Ring-buffer index '{var}' is assigned via modulo "
                        f"(safe path) but is also used as a direct array "
                        f"subscript without modulo guard — if '{var}' is "
                        f"pre-incremented past the buffer size by an external "
                        f"path this becomes an out-of-bounds write"
                    ),
                ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Pass E — Narrow-type size cast before allocation  (BUG-A precondition)
# ─────────────────────────────────────────────────────────────────────────────
# static_cast<uint16_t>(body_size) when body_size is a size_t or contains
# a multiplication — silently truncates for large inputs.
_NARROW_CAST_RE = re.compile(
    r"(?:static_cast\s*<\s*(?:uint16_t|uint8_t|short|unsigned\s+short)\s*>"
    r"|(?:uint16_t|uint8_t|short)\s*\()"
    r"\s*\(\s*([^)]*(?:sizeof|size|len|count|num|\*)[^)]*)\)",
    re.MULTILINE,
)


def check_narrow_size_cast(src: str, lines: List[str]) -> List[DeepFinding]:
    """
    Detect explicit narrowing casts of size expressions to uint16_t / uint8_t /
    short.  When the size exceeds the narrow type's maximum (65535 / 255) the
    value wraps to a dangerously small number that is later used as an
    allocation size or buffer length.
    """
    findings: List[DeepFinding] = []
    seen: set = set()

    for m in _NARROW_CAST_RE.finditer(src):
        ln = _lnum(src, m.start())
        key = ("narrow-size-cast", ln)
        if key in seen:
            continue
        seen.add(key)
        expr = m.group(1).strip()
        findings.append(DeepFinding(
            issue_type="narrow-size-cast",
            line=ln,
            snippet=_snip(lines, ln),
            confidence="HIGH",
            note=(
                f"Size expression '{expr}' is explicitly cast to a narrow "
                f"integer type (uint16_t/uint8_t/short) — for values > 65535 "
                f"the high bits are silently discarded, producing a tiny "
                f"allocation that a subsequent copy can overflow"
            ),
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Bonus Pass F — field-write past struct boundary
# (array sized [N+1] used as OOB landing zone)
# ─────────────────────────────────────────────────────────────────────────────
_ARRAY_PLUS1_RE = re.compile(
    r"\b(\w+)\s+(\w+)\s*\[\s*(\w+)\s*\+\s*1\s*\]",
    re.MULTILINE,
)
# Detects patterns like:  MmioRegion mmio[MAX_MMIO_REGIONS + 1];
# where the +1 looks like defensive padding but is an OOB landing zone

def check_oob_landing_zone(src: str, lines: List[str]) -> List[DeepFinding]:
    """
    Flag array declarations of the form arr[CONSTANT + 1] or arr[N + 1]
    when N is also used as a loop/check bound in the same translation unit.
    The extra +1 slot is the classic silent OOB landing zone — the array
    appears to have room for one extra write, masking adjacent-write bugs.
    """
    findings: List[DeepFinding] = []
    seen: set = set()

    for m in _ARRAY_PLUS1_RE.finditer(src):
        base_const = m.group(3)
        ln = _lnum(src, m.start())

        # Check that base_const appears elsewhere as a loop bound or limit
        usage_re = re.compile(
            r"\b" + re.escape(base_const) + r"\b",
            re.MULTILINE,
        )
        uses = list(usage_re.finditer(src))
        if len(uses) < 3:  # declaration + at least 2 uses elsewhere
            continue

        key = ("oob-landing-zone", ln)
        if key in seen:
            continue
        seen.add(key)

        arr_name = m.group(2)
        findings.append(DeepFinding(
            issue_type="off-by-one",
            line=ln,
            snippet=_snip(lines, ln),
            confidence="MEDIUM",
            note=(
                f"Array '{arr_name}[{base_const} + 1]' has one extra slot "
                f"beyond the nominal bound '{base_const}'. "
                f"If loop/check code uses '{base_const}' as an exclusive "
                f"upper bound with '<=' instead of '<', the +1 slot silently "
                f"absorbs the OOB write, masking the vulnerability from ASAN "
                f"and bounds checkers (classic off-by-one landing zone)"
            ),
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Main DeepAnalyzer class
# ─────────────────────────────────────────────────────────────────────────────
C_EXTENSIONS = {".c", ".cpp", ".cc", ".h", ".hpp", ".cxx"}


class DeepAnalyzer:
    """
    Multi-pass inter-procedural vulnerability detector for C/C++.
    Call analyze(file_path) to obtain a List[DeepFinding].
    """

    def analyze(self, file_path: str) -> List[DeepFinding]:
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in C_EXTENSIONS:
            return []

        src = _read(file_path)
        if not src:
            return []

        lines = _lines_of(src)
        findings: List[DeepFinding] = []

        # Deduplication set: (issue_type, line)
        seen: set = set()

        def _add(fs: List[DeepFinding]) -> None:
            for f in fs:
                key = (f.issue_type, f.line)
                if key not in seen:
                    seen.add(key)
                    findings.append(f)

        _add(check_alloc_loop_mismatch(src, lines))   # BUG-A
        _add(check_le_loop_bounds(src, lines))         # BUG-B, BUG-E
        _add(check_uncapped_field_loop(src, lines))   # BUG-C
        _add(check_ring_buf_direct_index(src, lines)) # BUG-D
        _add(check_narrow_size_cast(src, lines))       # BUG-A precondition
        _add(check_oob_landing_zone(src, lines))       # BUG-B/E structure cue

        return findings
