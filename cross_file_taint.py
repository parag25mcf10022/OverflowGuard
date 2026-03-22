"""
cross_file_taint.py — Cross-file taint analysis for OverflowGuard v11.0

Builds a file-level call graph from imports/includes, then propagates taint
findings across file boundaries to detect multi-hop injection paths.

Supports: C/C++ (#include), Python (import/from), Java (import), Go (import),
          Rust (use/mod), JavaScript/TypeScript (import/require).

Copyright 2026 Parag Bagade — MIT Licence
"""

from __future__ import annotations
import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from collections import defaultdict

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CrossFileFinding:
    """A taint finding that spans multiple files."""
    source_file: str
    source_line: int
    source_function: str
    sink_file: str
    sink_line: int
    sink_function: str
    issue_type: str
    severity: str
    description: str
    taint_chain: List[str]            # list of "file:function" hops
    risk_score: float = 0.0
    cwe: str = ""


@dataclass
class FunctionExport:
    """A function exported (defined) by a file."""
    name: str
    file_path: str
    line: int
    params: List[str] = field(default_factory=list)
    returns_tainted: bool = False     # does this function return user input?
    tainted_params: List[int] = field(default_factory=list)  # 0-indexed param positions that flow to sinks


@dataclass
class ImportEdge:
    """An import/include edge from one file to another."""
    from_file: str
    to_file: str       # resolved absolute path (or best guess)
    to_module: str     # raw module name as written
    symbols: List[str] = field(default_factory=list)  # specific imported names


# ---------------------------------------------------------------------------
# Language-specific import extractors
# ---------------------------------------------------------------------------

# Taint sources — functions that introduce external input
_CROSS_FILE_SOURCES: Dict[str, List[str]] = {
    "c":      ["recv", "read", "fgets", "fread", "gets", "scanf", "fscanf",
               "getenv", "getline", "recvfrom", "recvmsg"],
    "cpp":    ["recv", "read", "fgets", "cin", "getline", "getenv", "scanf"],
    "python": ["input", "request.args", "request.form", "request.json",
               "request.data", "request.get_json", "sys.stdin", "os.environ",
               "flask.request", "django.request"],
    "java":   ["getParameter", "getHeader", "getInputStream", "getReader",
               "readLine", "Scanner.next", "BufferedReader.readLine"],
    "go":     ["http.Request", "r.FormValue", "r.URL.Query", "bufio.Scanner",
               "os.Stdin", "ioutil.ReadAll"],
    "rust":   ["std::io::stdin", "std::io::Read", "std::env::args",
               "std::env::var", "hyper::Request"],
    "js":     ["req.body", "req.query", "req.params", "process.env",
               "readline", "fs.readFileSync"],
}

# Taint sinks — dangerous functions
_CROSS_FILE_SINKS: Dict[str, List[str]] = {
    "c":      ["system", "exec", "popen", "strcpy", "memcpy", "sprintf",
               "strcat", "gets", "printf"],
    "cpp":    ["system", "exec", "popen", "strcpy", "memcpy", "sprintf"],
    "python": ["eval", "exec", "os.system", "subprocess.call", "subprocess.run",
               "subprocess.Popen", "cursor.execute", "render_template_string"],
    "java":   ["Runtime.exec", "ProcessBuilder", "Statement.execute",
               "PreparedStatement.execute", "ObjectInputStream"],
    "go":     ["exec.Command", "os.Exec", "sql.Query", "fmt.Fprintf",
               "template.HTML"],
    "rust":   ["std::process::Command", "std::ptr::write", "libc::system"],
    "js":     ["eval", "child_process.exec", "child_process.spawn",
               "db.query", "res.send", "innerHTML"],
}


def _detect_lang(file_path: str) -> Optional[str]:
    ext = os.path.splitext(file_path)[1].lower()
    return {
        ".c": "c", ".h": "c",
        ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
        ".py": "python",
        ".java": "java",
        ".go": "go",
        ".rs": "rust",
        ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js",
        ".ts": "js", ".tsx": "js",
    }.get(ext)


def _extract_imports_c(content: str, file_path: str) -> List[ImportEdge]:
    edges = []
    for m in re.finditer(r'#include\s*"([^"]+)"', content):
        inc = m.group(1)
        # Try to resolve relative to file
        resolved = os.path.normpath(os.path.join(os.path.dirname(file_path), inc))
        edges.append(ImportEdge(from_file=file_path, to_file=resolved, to_module=inc))
    return edges


def _extract_imports_python(content: str, file_path: str) -> List[ImportEdge]:
    edges = []
    base_dir = os.path.dirname(file_path)
    for m in re.finditer(r'^(?:from\s+([\w.]+)\s+import\s+([\w, ]+)|import\s+([\w.]+))', content, re.MULTILINE):
        if m.group(1):
            mod = m.group(1)
            symbols = [s.strip() for s in m.group(2).split(",")]
        else:
            mod = m.group(3)
            symbols = []
        # Try to resolve
        mod_path = os.path.join(base_dir, mod.replace(".", os.sep) + ".py")
        edges.append(ImportEdge(from_file=file_path, to_file=mod_path, to_module=mod, symbols=symbols))
    return edges


def _extract_imports_java(content: str, file_path: str) -> List[ImportEdge]:
    edges = []
    base_dir = os.path.dirname(file_path)
    for m in re.finditer(r'^import\s+([\w.]+)(?:\.\*)?;', content, re.MULTILINE):
        mod = m.group(1)
        parts = mod.split(".")
        cls_name = parts[-1]
        # Java — try to find the file in same directory structure
        java_path = os.path.join(base_dir, *parts[:-1], cls_name + ".java")
        edges.append(ImportEdge(from_file=file_path, to_file=java_path, to_module=mod, symbols=[cls_name]))
    return edges


def _extract_imports_go(content: str, file_path: str) -> List[ImportEdge]:
    edges = []
    for m in re.finditer(r'"([^"]+)"', content):
        mod = m.group(1)
        if mod.startswith(".") or "/" in mod:
            # Relative or project import
            resolved = os.path.normpath(os.path.join(os.path.dirname(file_path), mod))
            edges.append(ImportEdge(from_file=file_path, to_file=resolved, to_module=mod))
    return edges


def _extract_imports_js(content: str, file_path: str) -> List[ImportEdge]:
    edges = []
    base_dir = os.path.dirname(file_path)
    # import ... from '...'
    for m in re.finditer(r'(?:import\s+.*?\s+from\s+|require\s*\(\s*)["\']([^"\']+)["\']', content):
        mod = m.group(1)
        if mod.startswith("."):
            for ext in ("", ".js", ".ts", ".jsx", ".tsx", "/index.js", "/index.ts"):
                resolved = os.path.normpath(os.path.join(base_dir, mod + ext))
                if os.path.isfile(resolved):
                    edges.append(ImportEdge(from_file=file_path, to_file=resolved, to_module=mod))
                    break
            else:
                edges.append(ImportEdge(from_file=file_path, to_file=mod, to_module=mod))
    return edges


def _extract_imports_rust(content: str, file_path: str) -> List[ImportEdge]:
    edges = []
    base_dir = os.path.dirname(file_path)
    for m in re.finditer(r'^(?:use|mod)\s+([\w:]+)', content, re.MULTILINE):
        mod = m.group(1).replace("::", os.sep)
        resolved = os.path.join(base_dir, mod + ".rs")
        edges.append(ImportEdge(from_file=file_path, to_file=resolved, to_module=m.group(1)))
    return edges


_IMPORT_EXTRACTORS = {
    "c": _extract_imports_c,
    "cpp": _extract_imports_c,
    "python": _extract_imports_python,
    "java": _extract_imports_java,
    "go": _extract_imports_go,
    "js": _extract_imports_js,
    "rust": _extract_imports_rust,
}


# ---------------------------------------------------------------------------
# Function definition extractor
# ---------------------------------------------------------------------------

_FUNC_PATTERNS: Dict[str, str] = {
    "c":      r'(?:int|void|char|long|size_t|unsigned|static|inline)\s+\*?\s*(\w+)\s*\(([^)]*)\)\s*\{',
    "cpp":    r'(?:int|void|char|long|size_t|unsigned|auto|static|inline|virtual)\s+\*?\s*(\w+)\s*\(([^)]*)\)\s*(?:const\s*)?\{',
    "python": r'def\s+(\w+)\s*\(([^)]*)\)\s*(?:->.*?)?:',
    "java":   r'(?:public|private|protected|static|final|abstract|synchronized)?\s*\w+\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+\w+(?:,\s*\w+)*)?\s*\{',
    "go":     r'func\s+(?:\([^)]+\)\s+)?(\w+)\s*\(([^)]*)\)',
    "rust":   r'(?:pub\s+)?fn\s+(\w+)\s*\(([^)]*)\)',
    "js":     r'(?:function\s+(\w+)\s*\(([^)]*)\)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(?([^)]*)\)?\s*=>)',
}


def _extract_functions(content: str, file_path: str, lang: str) -> List[FunctionExport]:
    """Extract function definitions from source code."""
    pattern = _FUNC_PATTERNS.get(lang)
    if not pattern:
        return []

    functions = []
    lines = content.splitlines()
    for m in re.finditer(pattern, content, re.MULTILINE):
        name = m.group(1) or (m.group(3) if m.lastindex >= 3 else None)
        params_str = m.group(2) or (m.group(4) if m.lastindex >= 4 else "")
        if not name:
            continue

        line_no = content[:m.start()].count("\n") + 1
        params = [p.strip().split()[-1].strip("*&") for p in params_str.split(",") if p.strip()] if params_str else []

        # Check if function body returns tainted data
        # Get function body (approximate: find matching brace or next function)
        func_start = m.end()
        func_body = content[func_start:func_start + 2000]  # reasonable window

        sources = _CROSS_FILE_SOURCES.get(lang, [])
        returns_tainted = any(src in func_body for src in sources) and "return" in func_body

        # Check which params flow to sinks
        sinks = _CROSS_FILE_SINKS.get(lang, [])
        tainted_params = []
        for i, param in enumerate(params):
            if param and any(f"{param}" in func_body and sink in func_body for sink in sinks):
                tainted_params.append(i)

        functions.append(FunctionExport(
            name=name,
            file_path=file_path,
            line=line_no,
            params=params,
            returns_tainted=returns_tainted,
            tainted_params=tainted_params,
        ))

    return functions


# ---------------------------------------------------------------------------
# Cross-file taint analyzer
# ---------------------------------------------------------------------------

class CrossFileTaintAnalyzer:
    """Builds a cross-file call graph and propagates taint across boundaries."""

    def __init__(self):
        self._file_cache: Dict[str, str] = {}            # path → content
        self._import_graph: Dict[str, List[ImportEdge]] = defaultdict(list)
        self._functions: Dict[str, List[FunctionExport]] = defaultdict(list)  # path → functions
        self._func_index: Dict[str, FunctionExport] = {}  # name → export (first wins)

    def analyze_directory(self, root_path: str, scan_exts: Optional[Set[str]] = None) -> List[CrossFileFinding]:
        """Analyze all source files under root_path for cross-file taint flows."""
        SKIP_DIRS = {
            ".git", ".hg", ".svn", "node_modules", "__pycache__",
            ".venv", "venv", ".tox", "target", "build", "dist",
        }

        if scan_exts is None:
            scan_exts = {".c", ".cpp", ".cc", ".h", ".hpp",
                         ".py", ".java", ".go", ".rs",
                         ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}

        # Phase 1: Collect all files and build indices
        all_files: List[str] = []
        for dirpath, dirs, files in os.walk(root_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext in scan_exts:
                    all_files.append(os.path.join(dirpath, fname))

        for fpath in all_files:
            self._index_file(fpath)

        # Phase 2: Detect cross-file taint flows
        return self._find_cross_file_flows(root_path)

    def analyze_files(self, file_paths: List[str], root_path: str = "") -> List[CrossFileFinding]:
        """Analyze specific files for cross-file taint flows."""
        for fpath in file_paths:
            self._index_file(fpath)
        return self._find_cross_file_flows(root_path or os.path.commonpath(file_paths))

    def _index_file(self, file_path: str) -> None:
        """Parse a file and add to indices."""
        try:
            with open(file_path, "r", errors="ignore") as fh:
                content = fh.read()
        except (OSError, UnicodeDecodeError):
            return

        self._file_cache[file_path] = content
        lang = _detect_lang(file_path)
        if not lang:
            return

        # Extract imports
        extractor = _IMPORT_EXTRACTORS.get(lang)
        if extractor:
            edges = extractor(content, file_path)
            self._import_graph[file_path] = edges

        # Extract function definitions
        funcs = _extract_functions(content, file_path, lang)
        self._functions[file_path] = funcs
        for func in funcs:
            if func.name not in self._func_index:
                self._func_index[func.name] = func

    def _find_cross_file_flows(self, root_path: str) -> List[CrossFileFinding]:
        """Detect taint flows that cross file boundaries."""
        findings: List[CrossFileFinding] = []

        # For each file, find calls to functions defined in other files
        for file_path, content in self._file_cache.items():
            lang = _detect_lang(file_path)
            if not lang:
                continue

            sources = _CROSS_FILE_SOURCES.get(lang, [])
            sinks = _CROSS_FILE_SINKS.get(lang, [])
            lines = content.splitlines()

            # Find taint sources in this file
            source_lines: List[Tuple[int, str]] = []
            for i, line in enumerate(lines, 1):
                for src in sources:
                    if src in line:
                        source_lines.append((i, src))
                        break

            if not source_lines:
                continue

            # Find calls to imported functions
            import_edges = self._import_graph.get(file_path, [])
            imported_files = {e.to_file for e in import_edges if os.path.isfile(e.to_file)}

            if lang in ("c", "cpp"):
                # GLib & Wireshark callbacks often lack explicit #include and aren't syntactic calls
                for fpath_other, funcs_other in self._functions.items():
                    if fpath_other != file_path:
                        for fn in funcs_other:
                            if fn.name in content:
                                imported_files.add(fpath_other)
                                break

            # Check if tainted data flows to functions in other files
            for imp_file in imported_files:
                imp_funcs = self._functions.get(imp_file, [])
                for func in imp_funcs:
                    # Check if this function is called in the current file (or used as callback)
                    if lang in ("c", "cpp"):
                        call_pattern = re.compile(rf'\b{re.escape(func.name)}\b')
                    else:
                        call_pattern = re.compile(rf'\b{re.escape(func.name)}\s*\(')
                    for m in call_pattern.finditer(content):
                        call_line = content[:m.start()].count("\n") + 1
                        call_text = lines[call_line - 1] if call_line <= len(lines) else ""

                        # Check if any source data might flow into the call
                        # Simple heuristic: source and call are in same function scope
                        for src_line, src_name in source_lines:
                            if abs(call_line - src_line) < 50:  # within 50 lines
                                # Check if the called function has sinks or tainted params
                                imp_lang = _detect_lang(imp_file)
                                imp_content = self._file_cache.get(imp_file, "")
                                imp_sinks = _CROSS_FILE_SINKS.get(imp_lang or lang, [])

                                has_sink = any(sink in imp_content for sink in imp_sinks)
                                if has_sink or func.tainted_params:
                                    chain = [
                                        f"{os.path.relpath(file_path, root_path)}:{src_name}(line {src_line})",
                                        f"{os.path.relpath(file_path, root_path)}:{func.name}()(line {call_line})",
                                        f"{os.path.relpath(imp_file, root_path)}:{func.name}(body)",
                                    ]

                                    findings.append(CrossFileFinding(
                                        source_file=file_path,
                                        source_line=src_line,
                                        source_function=src_name,
                                        sink_file=imp_file,
                                        sink_line=func.line,
                                        sink_function=func.name,
                                        issue_type="cross-file-taint-flow",
                                        severity="HIGH",
                                        description=(
                                            f"Tainted data from {src_name} (line {src_line}) flows "
                                            f"to {func.name}() in {os.path.basename(imp_file)} which "
                                            f"contains dangerous sinks."
                                        ),
                                        taint_chain=chain,
                                        risk_score=7.5,
                                        cwe="CWE-20",
                                    ))

            # Also check reverse: this file exports functions called by others that have sinks
            my_funcs = self._functions.get(file_path, [])
            for func in my_funcs:
                if not func.tainted_params and not func.returns_tainted:
                    continue
                # Find callers in other files
                for other_file, other_content in self._file_cache.items():
                    if other_file == file_path:
                        continue
                    if func.name in other_content:
                        other_lang = _detect_lang(other_file)
                        other_sinks = _CROSS_FILE_SINKS.get(other_lang or lang, [])
                        # Does the caller pass the return value to a sink?
                        if func.returns_tainted and any(sink in other_content for sink in other_sinks):
                            findings.append(CrossFileFinding(
                                source_file=file_path,
                                source_line=func.line,
                                source_function=func.name,
                                sink_file=other_file,
                                sink_line=0,
                                sink_function="(caller)",
                                issue_type="cross-file-taint-return",
                                severity="HIGH",
                                description=(
                                    f"{func.name}() in {os.path.basename(file_path)} returns "
                                    f"tainted data that may flow to sinks in "
                                    f"{os.path.basename(other_file)}."
                                ),
                                taint_chain=[
                                    f"{os.path.relpath(file_path, root_path)}:{func.name}(returns taint)",
                                    f"{os.path.relpath(other_file, root_path)}:(uses return value)",
                                ],
                                risk_score=6.5,
                                cwe="CWE-20",
                            ))

        # Deduplicate
        seen: Set[str] = set()
        unique: List[CrossFileFinding] = []
        for f in findings:
            key = f"{f.source_file}:{f.source_line}:{f.sink_file}:{f.sink_function}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def run_cross_file_taint(root_path: str, verbose: bool = False) -> List[CrossFileFinding]:
    """Run cross-file taint analysis on a directory."""
    analyzer = CrossFileTaintAnalyzer()
    findings = analyzer.analyze_directory(root_path)
    if verbose:
        for f in findings:
            print(f"  [{f.severity}] {f.issue_type}: {f.description[:100]}")
            print(f"    Chain: {' → '.join(f.taint_chain)}")
    return findings
