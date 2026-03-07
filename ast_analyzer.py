"""
ast_analyzer.py — Lightweight C/C++ AST-based sink/source tracker.

Uses libclang (clang.cindex) when available; falls back to regex-only analysis
so the tool always works even if libclang is not installed.
"""

import re
import os
from dataclasses import dataclass, field
from typing import Optional, List

# --- libclang availability ---
try:
    import clang.cindex as cindex
    CLANG_AVAILABLE = True
except ImportError:
    CLANG_AVAILABLE = False

# ---------------------------------------------------------------------------
# Dangerous sink functions → vulnerability type
# ---------------------------------------------------------------------------
SINK_FUNCTIONS = {
    "strcpy":    "stack-buffer-overflow",
    "strcat":    "stack-buffer-overflow",
    "sprintf":   "stack-buffer-overflow",
    "vsprintf":  "stack-buffer-overflow",
    "gets":      "stack-buffer-overflow",
    "scanf":     "stack-buffer-overflow",
    "memcpy":    "buffer-overflow",
    "memmove":   "buffer-overflow",
}

HEAP_ALLOC_FUNCTIONS = {"malloc", "calloc", "realloc"}
FREE_FUNCTIONS       = {"free"}

# ---------------------------------------------------------------------------
# Data class for a single finding
# ---------------------------------------------------------------------------
@dataclass
class ASTFinding:
    issue_type: str
    line: int
    col: int
    snippet: str
    confidence: str   # "HIGH" | "MEDIUM" | "LOW"
    note: str = ""
    stage: str = "AST"

    def __repr__(self):
        return (f"ASTFinding({self.issue_type!r}, "
                f"line={self.line}, confidence={self.confidence!r})")


# ---------------------------------------------------------------------------
# Main analyzer class
# ---------------------------------------------------------------------------
class ASTAnalyzer:
    def __init__(self, file_path: str):
        self.file_path = os.path.abspath(file_path)
        self.findings: List[ASTFinding] = []
        self._lines: List[str] = []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _read_lines(self):
        try:
            with open(self.file_path, "r", errors="ignore") as f:
                self._lines = f.readlines()
        except OSError:
            self._lines = []

    def _snippet(self, line_num: int) -> str:
        if self._lines and 1 <= line_num <= len(self._lines):
            return self._lines[line_num - 1].strip()
        return ""

    def _add(self, issue: str, line: int, col: int,
             confidence: str, note: str):
        self.findings.append(
            ASTFinding(issue_type=issue, line=line, col=col,
                       snippet=self._snippet(line),
                       confidence=confidence, note=note))

    # ------------------------------------------------------------------
    # libclang-based walk
    # ------------------------------------------------------------------
    def _walk(self, node, heap_vars: set, freed_vars: set):
        """Recursively walk the translation unit cursor."""
        if node.kind == cindex.CursorKind.VAR_DECL:
            # Track variables initialised with malloc/calloc/realloc
            for child in node.get_children():
                if (child.kind == cindex.CursorKind.CALL_EXPR and
                        child.spelling in HEAP_ALLOC_FUNCTIONS):
                    heap_vars.add(node.spelling)

        if node.kind == cindex.CursorKind.CALL_EXPR:
            fn = node.spelling or ""
            args = list(node.get_arguments())
            ln = node.location.line

            # ---- Dangerous string / buffer sinks ----
            if fn in SINK_FUNCTIONS:
                issue = SINK_FUNCTIONS[fn]
                # Refine: if dest or a local context pointer is from heap
                if args:
                    dest_tok = list(args[0].get_tokens())
                    dest_name = dest_tok[0].spelling if dest_tok else ""
                    if dest_name in heap_vars:
                        issue = "heap-buffer-overflow"
                self._add(issue, ln, node.location.column,
                          "HIGH", f"Dangerous call to {fn}()")

            # ---- scanf with unbounded %s ----
            elif fn == "scanf":
                if args:
                    fmt_toks = list(args[0].get_tokens())
                    fmt = fmt_toks[0].spelling if fmt_toks else ""
                    # %s without explicit width is a sink
                    if re.search(r'%[0-9]*s', fmt):
                        self._add("stack-buffer-overflow", ln,
                                  node.location.column, "HIGH",
                                  "scanf() with unbounded %s format")

            # ---- printf with variable format string ----
            elif fn == "printf":
                if args:
                    first = args[0]
                    toks = list(first.get_tokens())
                    is_literal = (
                        first.kind == cindex.CursorKind.STRING_LITERAL or
                        (toks and toks[0].spelling.startswith('"')))
                    if not is_literal:
                        self._add("format-string", ln,
                                  node.location.column, "HIGH",
                                  "printf() format arg is a variable, not a literal")

            # ---- free() → record pointer name ----
            elif fn in FREE_FUNCTIONS:
                if args:
                    toks = list(args[0].get_tokens())
                    if toks:
                        freed_vars.add(toks[0].spelling)

        # ---- Use of a freed pointer ----
        if node.kind in (cindex.CursorKind.DECL_REF_EXPR,
                         cindex.CursorKind.MEMBER_REF_EXPR,
                         cindex.CursorKind.ARRAY_SUBSCRIPT_EXPR):
            if node.spelling in freed_vars:
                self._add("use-after-free", node.location.line,
                          node.location.column, "HIGH",
                          f"Pointer '{node.spelling}' used after free()")

        for child in node.get_children():
            self._walk(child, heap_vars, freed_vars)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    def analyze(self) -> List[ASTFinding]:
        """Return a deduplicated list of ASTFinding objects."""
        self._read_lines()

        if CLANG_AVAILABLE:
            try:
                idx = cindex.Index.create()
                tu = idx.parse(
                    self.file_path,
                    args=["-std=c11", "-fsyntax-only",
                          "-I/usr/include", "-I/usr/local/include"],
                    options=(cindex.TranslationUnit
                             .PARSE_DETAILED_PROCESSING_RECORD))
                heap_vars: set = set()
                freed_vars: set = set()
                self._walk(tu.cursor, heap_vars, freed_vars)
            except Exception:
                # libclang parse error (missing headers, etc.) → fallback
                self.findings.clear()
                return self._regex_fallback()
        else:
            return self._regex_fallback()

        return self._dedup(self.findings)

    # ------------------------------------------------------------------
    # Regex-only fallback
    # ------------------------------------------------------------------
    def _regex_fallback(self) -> List[ASTFinding]:
        src = "".join(self._lines)
        findings: List[ASTFinding] = []

        has_malloc = bool(re.search(
            r"\b(malloc|calloc|realloc)\s*\(", src))

        # Dangerous calls
        for pattern, base_issue in [
            (r"\bstrcpy\s*\(",  "stack-buffer-overflow"),
            (r"\bstrcat\s*\(",  "stack-buffer-overflow"),
            (r"\bsprintf\s*\(", "stack-buffer-overflow"),
            (r"\bvsprintf\s*\(","stack-buffer-overflow"),
            (r"\bgets\s*\(",    "stack-buffer-overflow"),
        ]:
            for m in re.finditer(pattern, src):
                ln = src[:m.start()].count("\n") + 1
                # Look 8 lines back for a heap alloc
                context_start = max(0, m.start() - 300)
                ctx = src[context_start:m.start()]
                issue = ("heap-buffer-overflow"
                         if has_malloc and re.search(
                             r"\b(malloc|calloc|realloc)\s*\(", ctx)
                         else base_issue)
                findings.append(ASTFinding(
                    issue_type=issue, line=ln, col=0,
                    snippet=self._snippet(ln), confidence="MEDIUM",
                    note="Regex: dangerous call to "
                         + re.search(r"\b\w+", pattern).group() + "()"))

        # scanf with unbounded %s
        for m in re.finditer(r"\bscanf\s*\(", src):
            call_text = src[m.start():m.start() + 120]
            if re.search(r'%[0-9]*s', call_text):
                ln = src[:m.start()].count("\n") + 1
                findings.append(ASTFinding(
                    issue_type="stack-buffer-overflow", line=ln, col=0,
                    snippet=self._snippet(ln), confidence="MEDIUM",
                    note="Regex: scanf() with unbounded %s"))

        # printf with variable format string
        for m in re.finditer(
                r"\bprintf\s*\(\s*([a-zA-Z_]\w*)\s*[,)]", src):
            ln = src[:m.start()].count("\n") + 1
            findings.append(ASTFinding(
                issue_type="format-string", line=ln, col=0,
                snippet=self._snippet(ln), confidence="MEDIUM",
                note="Regex: printf() variable format string"))

        # Use-after-free: free(ptr) … use of ptr
        for m in re.finditer(r"\bfree\s*\(\s*([a-zA-Z_]\w*)\s*\)", src):
            ptr = m.group(1)
            free_line = src[:m.start()].count("\n") + 1
            rest = src[m.end():]
            use_m = re.search(r'\b' + re.escape(ptr) + r'\b', rest)
            if use_m:
                use_line = free_line + rest[:use_m.start()].count("\n")
                findings.append(ASTFinding(
                    issue_type="use-after-free", line=use_line, col=0,
                    snippet=self._snippet(use_line), confidence="HIGH",
                    note=f"Regex: '{ptr}' used after free()"))

        return self._dedup(findings)

    @staticmethod
    def _dedup(findings: List[ASTFinding]) -> List[ASTFinding]:
        seen: set = set()
        out: List[ASTFinding] = []
        for f in findings:
            key = (f.issue_type, f.line)
            if key not in seen:
                seen.add(key)
                out.append(f)
        return out
