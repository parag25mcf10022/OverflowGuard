"""
tree_sitter_engine.py — Multi‑language AST parsing engine for OverflowGuard v9.0

Provides **real** AST parsing for 12 + languages using tree‑sitter, replacing
the regex‑based pattern matching that powered earlier versions.

Supported languages (when the corresponding grammar is installed):
  C, C++, Python, Java, Go, Rust, JavaScript, TypeScript, PHP, Ruby, C#,
  Kotlin, Swift, Scala

Fall‑back hierarchy:
  1. ``tree_sitter_languages`` (bundles 80 + grammars in one pip package)
  2. Individual ``tree‑sitter‑<lang>`` wheels  (>= 0.22 API)
  3. Graceful degradation — ``TS_AVAILABLE`` is ``False`` and callers can
     decide whether to proceed with a regex fallback.
"""

from __future__ import annotations

import os
import importlib
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Dict,
    Generator,
    List,
    Optional,
    Set,
    Tuple,
)

# ---------------------------------------------------------------------------
# tree‑sitter availability detection
# ---------------------------------------------------------------------------

TS_AVAILABLE: bool = False
_TS_MODE: str = "none"  # "bundled" | "individual" | "none"

# Mapping from our language key → pip module name (individual wheels)
_INDIVIDUAL_LANG_MODULES: Dict[str, str] = {
    "c":          "tree_sitter_c",
    "cpp":        "tree_sitter_cpp",
    "python":     "tree_sitter_python",
    "java":       "tree_sitter_java",
    "go":         "tree_sitter_go",
    "rust":       "tree_sitter_rust",
    "javascript": "tree_sitter_javascript",
    "typescript": "tree_sitter_typescript",
    "php":        "tree_sitter_php",
    "ruby":       "tree_sitter_ruby",
    "c_sharp":    "tree_sitter_c_sharp",
    "kotlin":     "tree_sitter_kotlin",
    "swift":      "tree_sitter_swift",
    "scala":      "tree_sitter_scala",
}

# Loaded individual modules cache
_loaded_lang_mods: Dict[str, Any] = {}

# ---------- try bundled first ---------
try:
    from tree_sitter_languages import get_language as _bundled_get_language  # type: ignore
    from tree_sitter_languages import get_parser as _bundled_get_parser     # type: ignore

    TS_AVAILABLE = True
    _TS_MODE = "bundled"
except ImportError:
    pass

# ---------- try individual wheels ---------
if not TS_AVAILABLE:
    try:
        from tree_sitter import Language as _TSLanguage, Parser as _TSParser  # type: ignore

        for lang_key, mod_name in _INDIVIDUAL_LANG_MODULES.items():
            try:
                _loaded_lang_mods[lang_key] = importlib.import_module(mod_name)
            except ImportError:
                pass
        if _loaded_lang_mods:
            TS_AVAILABLE = True
            _TS_MODE = "individual"
    except ImportError:
        pass

# ---------------------------------------------------------------------------
# Extension → language key mapping
# ---------------------------------------------------------------------------

EXT_LANG_MAP: Dict[str, str] = {
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".py": "python", ".pyw": "python",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".php": "php",
    ".rb": "ruby",
    ".cs": "c_sharp",
    ".kt": "kotlin", ".kts": "kotlin",
    ".swift": "swift",
    ".scala": "scala", ".sc": "scala",
}


def supported_extensions() -> Set[str]:
    """Return the set of file extensions for which we can build an AST."""
    if not TS_AVAILABLE:
        return set()
    if _TS_MODE == "bundled":
        return set(EXT_LANG_MAP.keys())
    # individual mode — only exts whose language module is loaded
    avail_langs = set(_loaded_lang_mods.keys())
    return {ext for ext, lang in EXT_LANG_MAP.items() if lang in avail_langs}


def language_for_file(file_path: str) -> Optional[str]:
    """Return the tree‑sitter language key for *file_path*, or ``None``."""
    ext = os.path.splitext(file_path)[1].lower()
    return EXT_LANG_MAP.get(ext)


# ---------------------------------------------------------------------------
# Lightweight AST node wrapper
# ---------------------------------------------------------------------------

@dataclass
class TSNode:
    """Thin wrapper around a tree‑sitter node exposing the fields we need."""

    type: str
    text: str
    start_line: int        # 1‑based
    end_line: int          # 1‑based
    start_col: int         # 0‑based
    end_col: int           # 0‑based
    children: List["TSNode"] = field(default_factory=list, repr=False)
    named_children: List["TSNode"] = field(default_factory=list, repr=False)
    field_map: Dict[str, "TSNode"] = field(default_factory=dict, repr=False)
    _raw: Any = field(default=None, repr=False)

    # -- convenience helpers ------------------------------------------------

    def child_by_field(self, name: str) -> Optional["TSNode"]:
        return self.field_map.get(name)

    def walk(self) -> Generator["TSNode", None, None]:
        """Pre‑order depth‑first traversal."""
        yield self
        for c in self.children:
            yield from c.walk()

    def walk_named(self) -> Generator["TSNode", None, None]:
        """Like *walk* but only yields *named* children (skips punctuation)."""
        yield self
        for c in self.named_children:
            yield from c.walk_named()

    def find_all(self, node_type: str) -> List["TSNode"]:
        return [n for n in self.walk() if n.type == node_type]

    def find_first(self, node_type: str) -> Optional["TSNode"]:
        for n in self.walk():
            if n.type == node_type:
                return n
        return None

    def ancestors(self) -> List["TSNode"]:
        """Return the chain of types from root down to (but not including) self."""
        # We store parent link during _wrap.
        chain: List["TSNode"] = []
        cur = getattr(self, "_parent", None)
        while cur is not None:
            chain.append(cur)
            cur = getattr(cur, "_parent", None)
        chain.reverse()
        return chain


# ---------------------------------------------------------------------------
# Parser factory
# ---------------------------------------------------------------------------

class TreeSitterParser:
    """Parse source code into a :class:`TSNode` tree for a given language."""

    def __init__(self, language: str):
        if not TS_AVAILABLE:
            raise RuntimeError(
                "tree‑sitter is not installed.  "
                "Install via:  pip install tree-sitter-languages"
            )
        self.language = language
        self._parser = self._make_parser(language)

    # ---- internal ---------------------------------------------------------

    @staticmethod
    def _make_parser(lang: str) -> Any:
        if _TS_MODE == "bundled":
            return _bundled_get_parser(lang)
        elif _TS_MODE == "individual":
            mod = _loaded_lang_mods.get(lang)
            if mod is None:
                raise RuntimeError(
                    f"No tree‑sitter grammar for '{lang}'.  "
                    f"Install:  pip install tree-sitter-{lang.replace('_', '-')}"
                )
            lang_obj = _TSLanguage(mod.language())
            return _TSParser(lang_obj)
        raise RuntimeError("tree‑sitter not available")

    @staticmethod
    def _wrap(raw_node: Any, parent: Optional[TSNode] = None) -> TSNode:
        """Recursively wrap a raw tree‑sitter node into :class:`TSNode`."""
        children = [
            TreeSitterParser._wrap(c)
            for c in raw_node.children
        ]
        named = [c for c in children if not c.type.startswith("(") and c.type not in (
            ",", ";", "(", ")", "{", "}", "[", "]", ":", ".", "->", "::", "=>",
            "//", "/*", "*/", "#", "\"", "'",
        )]

        # Build field map — tree‑sitter exposes field names on child nodes.
        fm: Dict[str, TSNode] = {}
        for i, c in enumerate(raw_node.children):
            fn = raw_node.field_name_for_child(i)
            if fn:
                fm[fn] = children[i] if i < len(children) else None  # type: ignore

        node = TSNode(
            type=raw_node.type,
            text=raw_node.text.decode("utf-8", errors="replace")
                 if isinstance(raw_node.text, bytes) else str(raw_node.text),
            start_line=raw_node.start_point[0] + 1,
            end_line=raw_node.end_point[0] + 1,
            start_col=raw_node.start_point[1],
            end_col=raw_node.end_point[1],
            children=children,
            named_children=named,
            field_map=fm,
            _raw=raw_node,
        )

        # Set parent back‑links
        for c in children:
            c._parent = node  # type: ignore[attr-defined]

        return node

    # ---- public API -------------------------------------------------------

    def parse(self, source: str) -> TSNode:
        """Parse *source* (str) and return the root :class:`TSNode`."""
        raw_tree = self._parser.parse(bytes(source, "utf-8"))
        return self._wrap(raw_tree.root_node)

    def parse_file(self, file_path: str) -> TSNode:
        """Read *file_path* and return the parsed AST root."""
        with open(file_path, "r", errors="replace") as fh:
            source = fh.read()
        return self.parse(source)


# ---------------------------------------------------------------------------
# High‑level AST query utilities
# ---------------------------------------------------------------------------

class ASTQueries:
    """
    Language‑aware convenience queries on a :class:`TSNode` tree.

    These methods abstract over node‑type differences between grammars
    (e.g. ``call_expression`` in C vs ``call`` in Python).
    """

    # -- node‑type synonyms per category -----------------------------------

    _FUNC_DEF_TYPES: Dict[str, Set[str]] = {
        "c":          {"function_definition"},
        "cpp":        {"function_definition", "template_declaration"},
        "python":     {"function_definition"},
        "java":       {"method_declaration", "constructor_declaration"},
        "go":         {"function_declaration", "method_declaration"},
        "rust":       {"function_item"},
        "javascript": {"function_declaration", "arrow_function", "method_definition"},
        "typescript": {"function_declaration", "arrow_function", "method_definition"},
        "php":        {"function_definition", "method_declaration"},
        "ruby":       {"method", "singleton_method"},
        "c_sharp":    {"method_declaration", "constructor_declaration"},
        "kotlin":     {"function_declaration"},
        "swift":      {"function_declaration"},
        "scala":      {"function_definition"},
    }

    _CALL_TYPES: Dict[str, Set[str]] = {
        "c":          {"call_expression"},
        "cpp":        {"call_expression"},
        "python":     {"call"},
        "java":       {"method_invocation", "object_creation_expression"},
        "go":         {"call_expression"},
        "rust":       {"call_expression", "macro_invocation"},
        "javascript": {"call_expression", "new_expression"},
        "typescript": {"call_expression", "new_expression"},
        "php":        {"function_call_expression", "member_call_expression",
                       "scoped_call_expression"},
        "ruby":       {"call", "method_call"},
        "c_sharp":    {"invocation_expression", "object_creation_expression"},
        "kotlin":     {"call_expression"},
        "swift":      {"call_expression"},
        "scala":      {"call_expression"},
    }

    _ASSIGN_TYPES: Dict[str, Set[str]] = {
        "c":          {"assignment_expression", "init_declarator"},
        "cpp":        {"assignment_expression", "init_declarator"},
        "python":     {"assignment", "augmented_assignment"},
        "java":       {"assignment_expression", "local_variable_declaration"},
        "go":         {"short_var_declaration", "assignment_statement"},
        "rust":       {"let_declaration", "assignment_expression"},
        "javascript": {"assignment_expression", "variable_declarator"},
        "typescript": {"assignment_expression", "variable_declarator"},
        "php":        {"assignment_expression"},
        "ruby":       {"assignment"},
        "c_sharp":    {"assignment_expression", "variable_declarator"},
        "kotlin":     {"property_declaration", "assignment"},
        "swift":      {"value_binding_pattern"},
        "scala":      {"val_definition", "var_definition"},
    }

    _IF_TYPES: Dict[str, Set[str]] = {
        "c":  {"if_statement"}, "cpp": {"if_statement"},
        "python": {"if_statement"}, "java": {"if_statement"},
        "go": {"if_statement"}, "rust": {"if_expression"},
        "javascript": {"if_statement"}, "typescript": {"if_statement"},
        "php": {"if_statement"}, "ruby": {"if", "unless"},
        "c_sharp": {"if_statement"}, "kotlin": {"if_expression"},
        "swift": {"if_statement"}, "scala": {"if_expression"},
    }

    _LOOP_TYPES: Dict[str, Set[str]] = {
        "c":  {"for_statement", "while_statement", "do_statement"},
        "cpp": {"for_statement", "while_statement", "do_statement", "for_range_loop"},
        "python": {"for_statement", "while_statement"},
        "java": {"for_statement", "enhanced_for_statement", "while_statement",
                 "do_statement"},
        "go": {"for_statement"},
        "rust": {"for_expression", "while_expression", "loop_expression"},
        "javascript": {"for_statement", "for_in_statement", "while_statement",
                       "do_statement"},
        "typescript": {"for_statement", "for_in_statement", "while_statement",
                       "do_statement"},
        "php": {"for_statement", "foreach_statement", "while_statement"},
        "ruby": {"for", "while", "until"},
        "c_sharp": {"for_statement", "foreach_statement", "while_statement",
                    "do_statement"},
        "kotlin": {"for_statement", "while_statement", "do_while_statement"},
        "swift": {"for_in_statement", "while_statement", "repeat_while_statement"},
        "scala": {"for_expression", "while_expression"},
    }

    _RETURN_TYPES: Set[str] = {"return_statement", "return_expression"}

    _ARRAY_ACCESS_TYPES: Dict[str, Set[str]] = {
        "c": {"subscript_expression"}, "cpp": {"subscript_expression"},
        "python": {"subscript"}, "java": {"array_access"},
        "go": {"index_expression"}, "rust": {"index_expression"},
        "javascript": {"subscript_expression"}, "typescript": {"subscript_expression"},
        "php": {"subscript_expression"}, "ruby": {"element_reference"},
        "c_sharp": {"element_access_expression"},
        "kotlin": {"indexing_expression"}, "swift": {"subscript_expression"},
        "scala": {"call_expression"},  # Scala uses apply() for indexing
    }

    # ---- dangerous‑function databases -----------------------------------

    # Sink functions per language that indicate potential vulnerabilities
    SINKS: Dict[str, Dict[str, str]] = {
        "c": {
            "strcpy": "buffer-overflow", "strcat": "buffer-overflow",
            "sprintf": "buffer-overflow", "gets": "buffer-overflow",
            "scanf": "buffer-overflow", "vsprintf": "buffer-overflow",
            "memcpy": "buffer-overflow", "memmove": "buffer-overflow",
            "strncpy": "buffer-overflow",  # still risky if n > dest
            "printf": "format-string", "fprintf": "format-string",
            "syslog": "format-string", "snprintf": "format-string",
            "system": "os-command-injection", "popen": "os-command-injection",
            "execve": "os-command-injection", "execvp": "os-command-injection",
            "free": "double-free",
        },
        "cpp": {
            "strcpy": "buffer-overflow", "strcat": "buffer-overflow",
            "sprintf": "buffer-overflow", "gets": "buffer-overflow",
            "scanf": "buffer-overflow", "system": "os-command-injection",
            "popen": "os-command-injection", "printf": "format-string",
            "free": "double-free", "delete": "double-free",
            "memcpy": "buffer-overflow", "memmove": "buffer-overflow",
        },
        "python": {
            "eval": "insecure-eval", "exec": "insecure-eval",
            "compile": "insecure-eval",
            "os.system": "os-command-injection",
            "os.popen": "os-command-injection",
            "subprocess.call": "os-command-injection",
            "subprocess.run": "os-command-injection",
            "subprocess.Popen": "os-command-injection",
            "pickle.loads": "insecure-deserialization",
            "pickle.load": "insecure-deserialization",
            "yaml.load": "insecure-deserialization",
            "marshal.loads": "insecure-deserialization",
            "__import__": "insecure-eval",
        },
        "java": {
            "Runtime.exec": "os-command-injection",
            "ProcessBuilder": "os-command-injection",
            "ObjectInputStream": "insecure-deserialization",
            "readObject": "insecure-deserialization",
            "ScriptEngine.eval": "insecure-eval",
            "Statement.execute": "sql-injection",
            "Statement.executeQuery": "sql-injection",
            "Statement.executeUpdate": "sql-injection",
        },
        "go": {
            "exec.Command": "os-command-injection",
            "sql.Query": "sql-injection", "sql.Exec": "sql-injection",
            "template.HTML": "xss",
            "http.ListenAndServe": "insecure-config",
        },
        "rust": {
            "Command::new": "os-command-injection",
            "mem::transmute": "unsafe-block",
            "from_raw_parts": "buffer-overflow",
            "slice::from_raw_parts": "buffer-overflow",
        },
        "javascript": {
            "eval": "insecure-eval",
            "Function": "insecure-eval",
            "setTimeout": "insecure-eval",  # when string arg
            "setInterval": "insecure-eval",
            "child_process.exec": "os-command-injection",
            "child_process.execSync": "os-command-injection",
            "innerHTML": "xss",
            "document.write": "xss",
        },
        "typescript": {
            "eval": "insecure-eval",
            "Function": "insecure-eval",
            "child_process.exec": "os-command-injection",
            "innerHTML": "xss", "document.write": "xss",
        },
        "php": {
            "eval": "insecure-eval", "assert": "insecure-eval",
            "system": "os-command-injection", "exec": "os-command-injection",
            "shell_exec": "os-command-injection", "passthru": "os-command-injection",
            "popen": "os-command-injection", "proc_open": "os-command-injection",
            "unserialize": "insecure-deserialization",
            "mysqli_query": "sql-injection", "mysql_query": "sql-injection",
            "include": "path-traversal", "require": "path-traversal",
            "file_get_contents": "ssrf",
        },
        "ruby": {
            "eval": "insecure-eval", "send": "insecure-eval",
            "system": "os-command-injection",
            "exec": "os-command-injection", "`": "os-command-injection",
            "Marshal.load": "insecure-deserialization",
            "YAML.load": "insecure-deserialization",
        },
        "c_sharp": {
            "Process.Start": "os-command-injection",
            "SqlCommand": "sql-injection",
            "BinaryFormatter.Deserialize": "insecure-deserialization",
            "XmlSerializer": "xml-injection",
        },
        "kotlin": {
            "Runtime.exec": "os-command-injection",
            "ProcessBuilder": "os-command-injection",
            "ObjectInputStream": "insecure-deserialization",
        },
        "swift": {
            "Process": "os-command-injection",
            "NSTask": "os-command-injection",
            "NSKeyedUnarchiver": "insecure-deserialization",
        },
        "scala": {
            "Runtime.exec": "os-command-injection",
            "Process": "os-command-injection",
            "ObjectInputStream": "insecure-deserialization",
        },
    }

    # Taint sources — functions that return user‑controllable data
    SOURCES: Dict[str, Set[str]] = {
        "c":          {"gets", "scanf", "fscanf", "fgets", "read", "recv",
                       "getenv", "fread", "getchar", "getline", "readlink"},
        "cpp":        {"cin", "getline", "scanf", "gets", "read", "recv"},
        "python":     {"input", "raw_input", "sys.stdin.read", "sys.stdin.readline",
                       "request.args.get", "request.form.get", "request.data",
                       "os.environ.get", "os.getenv"},
        "java":       {"Scanner.next", "Scanner.nextLine", "BufferedReader.readLine",
                       "request.getParameter", "request.getHeader",
                       "System.getenv", "System.getProperty"},
        "go":         {"fmt.Scan", "fmt.Scanf", "bufio.Scanner.Text",
                       "http.Request.FormValue", "http.Request.URL.Query",
                       "os.Getenv", "ioutil.ReadAll"},
        "rust":       {"stdin().read_line", "std::env::var", "std::env::args"},
        "javascript": {"prompt", "process.argv", "req.query", "req.body",
                       "req.params", "document.cookie", "location.search",
                       "localStorage.getItem", "window.name"},
        "typescript": {"prompt", "process.argv", "req.query", "req.body",
                       "req.params"},
        "php":        {"$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER",
                       "$_FILES", "file_get_contents", "fgets", "fread"},
        "ruby":       {"gets", "ARGV", "params", "ENV", "STDIN.gets",
                       "request.params"},
        "c_sharp":    {"Console.ReadLine", "Request.QueryString",
                       "Request.Form", "Environment.GetEnvironmentVariable"},
        "kotlin":     {"readLine", "Scanner.next", "request.getParameter"},
        "swift":      {"readLine", "CommandLine.arguments",
                       "ProcessInfo.processInfo.environment"},
        "scala":      {"scala.io.StdIn.readLine", "System.getenv",
                       "request.getParameter"},
    }

    # Sanitizer / guard function names per language
    SANITIZERS: Dict[str, Set[str]] = {
        "c":          {"strlcpy", "strlcat", "snprintf", "strnlen", "sizeof",
                       "bounds_check", "safe_copy"},
        "cpp":        {"strlcpy", "strlcat", "snprintf", "std::clamp",
                       "gsl::narrow", "safe_cast"},
        "python":     {"escape", "quote", "sanitize", "bleach.clean",
                       "html.escape", "shlex.quote", "markupsafe.escape",
                       "parameterized", "prepared"},
        "java":       {"PreparedStatement", "setString", "ESAPI.encoder",
                       "StringEscapeUtils", "HtmlUtils.htmlEscape",
                       "Jsoup.clean", "Pattern.matches"},
        "go":         {"template.HTMLEscapeString", "url.QueryEscape",
                       "html.EscapeString", "sanitize", "strconv.Atoi"},
        "rust":       {"sanitize", "escape", "checked_add", "checked_mul",
                       "saturating_add"},
        "javascript": {"encodeURIComponent", "encodeURI", "DOMPurify.sanitize",
                       "escapeHtml", "validator.escape", "xss"},
        "typescript": {"encodeURIComponent", "DOMPurify.sanitize",
                       "escapeHtml", "validator.escape"},
        "php":        {"htmlspecialchars", "htmlentities", "addslashes",
                       "mysqli_real_escape_string", "PDO::prepare",
                       "filter_input", "filter_var", "intval"},
        "ruby":       {"sanitize", "escape", "html_escape", "h",
                       "ActiveRecord::Base.sanitize"},
        "c_sharp":    {"HtmlEncode", "UrlEncode", "SqlParameter",
                       "AntiXss", "Sanitize"},
        "kotlin":     {"PreparedStatement", "setString", "sanitize", "escape"},
        "swift":      {"addingPercentEncoding", "sanitize", "NSRegularExpression"},
        "scala":      {"PreparedStatement", "setString", "sanitize"},
    }

    def __init__(self, language: str):
        self.language = language

    # ---- generic finders -------------------------------------------------

    def find_functions(self, root: TSNode) -> List[TSNode]:
        """Return all function / method definition nodes."""
        types = self._FUNC_DEF_TYPES.get(self.language, set())
        return [n for n in root.walk() if n.type in types]

    def find_calls(self, root: TSNode) -> List[TSNode]:
        """Return all call‑expression nodes."""
        types = self._CALL_TYPES.get(self.language, set())
        return [n for n in root.walk() if n.type in types]

    def find_assignments(self, root: TSNode) -> List[TSNode]:
        """Return all assignment / declaration‑with‑init nodes."""
        types = self._ASSIGN_TYPES.get(self.language, set())
        return [n for n in root.walk() if n.type in types]

    def find_ifs(self, root: TSNode) -> List[TSNode]:
        types = self._IF_TYPES.get(self.language, set())
        return [n for n in root.walk() if n.type in types]

    def find_loops(self, root: TSNode) -> List[TSNode]:
        types = self._LOOP_TYPES.get(self.language, set())
        return [n for n in root.walk() if n.type in types]

    def find_returns(self, root: TSNode) -> List[TSNode]:
        return [n for n in root.walk() if n.type in self._RETURN_TYPES]

    def find_array_accesses(self, root: TSNode) -> List[TSNode]:
        types = self._ARRAY_ACCESS_TYPES.get(self.language, set())
        return [n for n in root.walk() if n.type in types]

    # ---- call‑name extraction -------------------------------------------

    def call_name(self, call_node: TSNode) -> str:
        """
        Extract the callee name from a call node.

        Handles:  ``foo()``,  ``obj.method()``,  ``pkg::func()``,
                  ``Foo::bar()``,  ``a.b.c()``
        """
        func = call_node.child_by_field("function") or call_node.child_by_field("name")
        if func is None:
            # Python ``call`` node: first named child is the function
            for c in call_node.named_children:
                if c.type in ("identifier", "attribute", "member_expression",
                              "scoped_identifier", "field_expression",
                              "selector_expression"):
                    func = c
                    break
        if func is None:
            return call_node.text.split("(")[0].strip() if "(" in call_node.text else call_node.text

        # Flatten dotted / scoped names
        return func.text.strip()

    # ---- higher‑level helpers -------------------------------------------

    def function_name(self, func_node: TSNode) -> str:
        """Extract the name identifier from a function definition node."""
        name_node = func_node.child_by_field("name") or func_node.child_by_field("declarator")
        if name_node is not None:
            # For C/C++ the declarator might be a ``function_declarator``; drill down
            inner = name_node.find_first("identifier")
            return inner.text if inner else name_node.text
        # Fallback — find first identifier child
        for c in func_node.named_children:
            if c.type == "identifier":
                return c.text
        return "<anonymous>"

    def function_params(self, func_node: TSNode) -> List[Tuple[str, str]]:
        """Return [(param_name, param_type)] for a function definition."""
        params_node = func_node.child_by_field("parameters") or func_node.find_first(
            "parameter_list"
        ) or func_node.find_first("formal_parameters")
        if params_node is None:
            return []
        result: List[Tuple[str, str]] = []
        for p in params_node.named_children:
            name = ""
            ptype = ""
            name_n = p.child_by_field("name") or p.find_first("identifier")
            type_n = p.child_by_field("type") or p.find_first("type_identifier") or p.find_first("primitive_type")
            if name_n:
                name = name_n.text
            if type_n:
                ptype = type_n.text
            if name or ptype:
                result.append((name, ptype))
        return result

    def is_sink_call(self, call_node: TSNode) -> Optional[str]:
        """If *call_node* calls a known sink, return the vuln type, else None."""
        cname = self.call_name(call_node)
        sinks = self.SINKS.get(self.language, {})
        # Exact match
        if cname in sinks:
            return sinks[cname]
        # Dotted suffix match (e.g., "os.system" matches "system")
        for sink_name, vuln_type in sinks.items():
            if "." in sink_name:
                if cname.endswith(sink_name) or cname == sink_name.split(".")[-1]:
                    return vuln_type
            elif cname.endswith("." + sink_name) or cname == sink_name:
                return vuln_type
        return None

    def is_source_call(self, call_node: TSNode) -> bool:
        """Return True if *call_node* calls a known taint source."""
        cname = self.call_name(call_node)
        sources = self.SOURCES.get(self.language, set())
        if cname in sources:
            return True
        for s in sources:
            if "." in s:
                if cname.endswith(s) or cname == s.split(".")[-1]:
                    return True
            elif cname.endswith("." + s) or cname == s:
                return True
        return False

    def is_sanitizer_call(self, call_node: TSNode) -> bool:
        """Return True if *call_node* calls a known sanitizer."""
        cname = self.call_name(call_node)
        sanitizers = self.SANITIZERS.get(self.language, set())
        if cname in sanitizers:
            return True
        for s in sanitizers:
            if cname.endswith(s) or s in cname:
                return True
        return False

    def get_identifiers_in(self, node: TSNode) -> Set[str]:
        """Return all identifier names referenced within *node*."""
        return {n.text for n in node.walk() if n.type == "identifier"}

    def extract_lhs_rhs(self, assign_node: TSNode) -> Tuple[Optional[str], Optional[TSNode]]:
        """
        For an assignment node, return (lhs_name, rhs_node).
        Returns (None, None) if the structure is not recognised.
        """
        left = assign_node.child_by_field("left") or assign_node.child_by_field("name")
        right = assign_node.child_by_field("right") or assign_node.child_by_field("value")
        if left is None and len(assign_node.named_children) >= 2:
            left = assign_node.named_children[0]
            right = assign_node.named_children[1]
        lhs_name: Optional[str] = None
        if left is not None:
            id_node = left.find_first("identifier") if left.type != "identifier" else left
            lhs_name = id_node.text if id_node else left.text
        return lhs_name, right


# ---------------------------------------------------------------------------
# Convenience: one‑shot parse + queries
# ---------------------------------------------------------------------------

def parse_file(file_path: str) -> Tuple[Optional[TSNode], Optional[ASTQueries]]:
    """
    Parse *file_path* and return ``(root_node, queries)`` or ``(None, None)``
    if tree‑sitter is unavailable or the language is not supported.
    """
    lang = language_for_file(file_path)
    if lang is None or not TS_AVAILABLE:
        return None, None
    try:
        parser = TreeSitterParser(lang)
        root = parser.parse_file(file_path)
        queries = ASTQueries(lang)
        return root, queries
    except Exception:
        return None, None


def parse_source(source: str, language: str) -> Tuple[Optional[TSNode], Optional[ASTQueries]]:
    """Parse a source string for the given language key."""
    if not TS_AVAILABLE:
        return None, None
    try:
        parser = TreeSitterParser(language)
        root = parser.parse(source)
        queries = ASTQueries(language)
        return root, queries
    except Exception:
        return None, None
