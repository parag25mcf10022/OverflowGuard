"""
interprocedural_taint.py — P1: Inter-procedural call-graph + taint propagation.

Builds a lightweight call graph from C/C++ source files and propagates
taint across function boundaries using a fixpoint iteration.

What it catches that intra-procedural analysis cannot:
    void process(char *data) {
        char buf[64];
        strcpy(buf, data);   // <- not flagged intra-proc (data is a param)
    }
    int main(int argc, char **argv) {
        process(argv[1]);    // <- inter-proc: argv[1] reaches strcpy via data
    }

Exported API:
    InterproceduralFinding    — dataclass
    InterproceduralAnalyzer   — analyze_project(directory) → List[...]
                              — analyze_file(path) → List[...]
"""

import re
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class InterproceduralFinding:
    issue_type: str
    line:       int
    snippet:    str
    confidence: str
    lang:       str = "c"
    note:       str = ""
    stage:      str = "Interprocedural"


# ── Helpers ───────────────────────────────────────────────────────────────────
def _read(p: str) -> str:
    try:
        with open(p, "r", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""


def _snip(lines: List[str], ln: int) -> str:
    return lines[ln - 1].strip() if 1 <= ln <= len(lines) else ""


# ── Taint sources (user-controlled data entering the program) ─────────────────
_TAINT_SOURCES = {
    "argv", "getenv", "gets", "fgets", "recv", "recvfrom",
    "read", "scanf", "fscanf", "sscanf", "getline",
}

# ── Dangerous sinks (reaching these with tainted data is a bug) ───────────────
_DANGEROUS_SINKS: Dict[str, str] = {
    "strcpy":  "stack-buffer-overflow",
    "strcat":  "stack-buffer-overflow",
    "sprintf": "format-string",
    "memcpy":  "heap-buffer-overflow",
    "memset":  "heap-buffer-overflow",
    "system":  "os-command-injection",
    "popen":   "os-command-injection",
    "execve":  "os-command-injection",
    "execvp":  "os-command-injection",
    "printf":  "format-string",
    "fprintf": "format-string",
}

# ── Patterns ──────────────────────────────────────────────────────────────────
# function definition: return_type func_name(params...)
_FUNC_DEF = re.compile(
    r"(?:^|\n)(?:static\s+|inline\s+|virtual\s+|extern\s+)*"
    r"[\w:*&<>\[\]]+\s+(\w+)\s*\(([^)]*)\)\s*(?:const\s*)?(?:noexcept\s*)?\{",
    re.MULTILINE,
)
# function call: func_name(args...)
_FUNC_CALL = re.compile(
    r"\b(\w+)\s*\(([^;{]*?)\)",
    re.MULTILINE,
)
_ARG_SPLIT = re.compile(r",\s*")


def _parse_params(param_str: str) -> List[str]:
    """Return list of parameter NAMES from a function signature string."""
    names = []
    for part in _ARG_SPLIT.split(param_str):
        part = part.strip()
        if not part or part in ("void", "..."):
            continue
        # strip type, keep last token (name)
        # handles: const char *name, size_t len, etc.
        tokens = re.split(r"[\s*&]+", part.rstrip())
        tokens = [t for t in tokens if t and re.match(r"^\w+$", t)]
        if tokens:
            names.append(tokens[-1])
    return names


def _parse_args(arg_str: str) -> List[str]:
    """Return list of actual argument expressions from a call."""
    args = []
    depth = 0
    current = []
    for ch in arg_str:
        if ch in "([{":
            depth += 1
            current.append(ch)
        elif ch in ")]}":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        args.append("".join(current).strip())
    return args


# ── Call Graph ────────────────────────────────────────────────────────────────
@dataclass
class FuncInfo:
    name:   str
    start:  int              # line number (1-based)
    params: List[str]        # parameter names in order
    body:   str              # raw function body text
    tainted_params: Set[int] = field(default_factory=set)  # indices
    tainted_locals: Set[str] = field(default_factory=set)
    calls:  List[Tuple[str, List[str], int]] = field(default_factory=list)
    # (callee_name, [arg_expressions], call_line)


def _build_call_graph(src: str) -> Dict[str, FuncInfo]:
    """Extract all function definitions and the calls they make."""
    funcs: Dict[str, FuncInfo] = {}
    src_lines = src.splitlines()

    for m in _FUNC_DEF.finditer(src):
        name       = m.group(1)
        param_str  = m.group(2)
        start_line = src[:m.start()].count("\n") + 1
        params     = _parse_params(param_str)

        # Extract function body (balanced braces)
        brace_start = m.end() - 1  # points to '{'
        depth, i    = 0, brace_start
        while i < len(src):
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = src[brace_start: i + 1]

        fi = FuncInfo(name=name, start=start_line, params=params, body=body)

        # Collect calls within this body
        for cm in _FUNC_CALL.finditer(body):
            callee   = cm.group(1)
            arg_str  = cm.group(2)
            call_ln  = start_line + body[:cm.start()].count("\n")
            fi.calls.append((callee, _parse_args(arg_str), call_ln))

        funcs[name] = fi

    return funcs


def _seed_taint(funcs: Dict[str, FuncInfo]) -> None:
    """Mark parameters tainted if they come from external taint sources in main/callers."""
    for fi in funcs.values():
        # Any call to a taint source that captures result into a local
        for callee, args, _ in fi.calls:
            if callee in _TAINT_SOURCES:
                # Mark ALL receiving locals as tainted
                for arg in args:
                    arg = arg.strip().lstrip("&")
                    if re.match(r"^\w+$", arg):
                        fi.tainted_locals.add(arg)

        # argv is a taint source by existence — mark first params of main
        if fi.name == "main" or fi.name == "wmain":
            for idx, p in enumerate(fi.params):
                if p in ("argv", "argc"):
                    fi.tainted_params.add(idx)
                    fi.tainted_locals.add(p)


def _propagate_fixpoint(funcs: Dict[str, FuncInfo]) -> None:
    """
    Fixpoint: if a function passes a tainted arg to callee param,
    mark that callee param as tainted and re-iterate.
    """
    changed = True
    iterations = 0
    while changed and iterations < 20:
        changed = False
        iterations += 1
        for fi in funcs.values():
            for callee_name, call_args, call_line in fi.calls:
                callee = funcs.get(callee_name)
                if callee is None:
                    continue
                for arg_idx, arg_expr in enumerate(call_args):
                    arg_expr = arg_expr.strip().lstrip("&")
                    # Check if this arg expression is a tainted var in caller
                    tokens = re.split(r"\W+", arg_expr)
                    is_tainted = any(
                        tok in fi.tainted_locals or
                        (tok in fi.params and fi.params.index(tok) in fi.tainted_params)
                        for tok in tokens if tok
                    )
                    if is_tainted and arg_idx < len(callee.params):
                        if arg_idx not in callee.tainted_params:
                            callee.tainted_params.add(arg_idx)
                            callee.tainted_locals.add(callee.params[arg_idx])
                            changed = True


def _find_sink_violations(
    funcs: Dict[str, FuncInfo],
    src_lines: List[str],
) -> List[InterproceduralFinding]:
    """Find calls to dangerous sinks with tainted arguments."""
    findings: List[InterproceduralFinding] = []
    seen: Set[Tuple[str, int]] = set()

    for fi in funcs.values():
        for callee_name, call_args, call_line in fi.calls:
            if callee_name not in _DANGEROUS_SINKS:
                continue

            # Check whether any call arg is tainted
            for arg_expr in call_args:
                arg_expr_stripped = arg_expr.strip().lstrip("&")
                tokens = re.split(r"\W+", arg_expr_stripped)
                tainted = any(
                    tok in fi.tainted_locals or
                    (tok in fi.params and fi.params.index(tok) in fi.tainted_params)
                    for tok in tokens if tok
                )
                if not tainted:
                    continue

                issue = _DANGEROUS_SINKS[callee_name]
                key = (issue, call_line)
                if key in seen:
                    continue
                seen.add(key)

                findings.append(InterproceduralFinding(
                    issue_type=issue,
                    line=call_line,
                    snippet=_snip(src_lines, call_line),
                    confidence="HIGH",
                    note=(
                        f"Inter-procedural taint: '{callee_name}()' in function "
                        f"'{fi.name}' receives tainted data that ultimately originates "
                        f"from an external source — no sanitization seen across call chain"
                    ),
                ))

    return findings


# ── Public API ────────────────────────────────────────────────────────────────
C_EXTENSIONS = {".c", ".cpp", ".cc", ".h", ".hpp", ".cxx"}


class InterproceduralAnalyzer:
    """
    Inter-procedural call-graph taint analyzer.
    Supports single-file and whole-directory (project) analysis.
    """

    def analyze_file(self, file_path: str) -> List[InterproceduralFinding]:
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in C_EXTENSIONS:
            return []
        src = _read(file_path)
        if not src:
            return []
        return self._run(src)

    def analyze_project(self, directory: str) -> List[InterproceduralFinding]:
        """Analyze all C/C++ files in *directory* as a single compilation unit."""
        combined_src_parts: List[str] = []
        for root, _dirs, files in os.walk(directory):
            for fname in files:
                if os.path.splitext(fname)[1].lower() in C_EXTENSIONS:
                    fpath = os.path.join(root, fname)
                    combined_src_parts.append(_read(fpath))
        if not combined_src_parts:
            return []
        combined = "\n".join(combined_src_parts)
        return self._run(combined)

    def _run(self, src: str) -> List[InterproceduralFinding]:
        src_lines = src.splitlines()
        funcs = _build_call_graph(src)
        _seed_taint(funcs)
        _propagate_fixpoint(funcs)
        return _find_sink_violations(funcs, src_lines)
