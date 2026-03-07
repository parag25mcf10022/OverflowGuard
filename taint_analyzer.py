"""
taint_analyzer.py — Multi-language dataflow / taint-tracking engine.

For each supported language we track:
  • Taint SOURCES  : functions / APIs that introduce user-controlled data
  • Taint SINKS    : functions / APIs that are dangerous if fed tainted data
  • Sanitizers     : functions that cleanse taint (reduces false-positives)

The analysis is purely regex + heuristic; it intentionally trades completeness
for zero external dependencies.  When libclang is available the main
ast_analyzer.py provides deeper C/C++ coverage; this module handles
cross-language patterns and additional C/C++ categories that the AST walker
does not yet cover.

Exported API:
    TaintFinding   — dataclass with (issue_type, line, snippet, confidence, lang, note)
    TaintAnalyzer  — analyze(file_path) → List[TaintFinding]
"""

import re
import os
from dataclasses import dataclass
from typing import List, Optional

# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------
@dataclass
class TaintFinding:
    issue_type: str
    line: int
    snippet: str
    confidence: str    # HIGH | MEDIUM | LOW
    lang: str          # c | python | java | go | rust | generic
    note: str = ""
    stage: str = "Taint"


# ---------------------------------------------------------------------------
# Language-agnostic helpers
# ---------------------------------------------------------------------------
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


def _snippet_at(lines: List[str], ln: int) -> str:
    if 1 <= ln <= len(lines):
        return lines[ln - 1].strip()
    return ""


# ---------------------------------------------------------------------------
# C / C++ taint rules
# ---------------------------------------------------------------------------

# Sources: return values of these functions are attacker-controlled
C_SOURCES = [
    re.compile(r"\bgetchar\s*\("),
    re.compile(r"\bgets\s*\("),
    re.compile(r"\bfgets\s*\("),
    re.compile(r"\bfgetc\s*\("),
    re.compile(r"\bread\s*\("),
    re.compile(r"\brecv\s*\("),
    re.compile(r"\brecvfrom\s*\("),
    re.compile(r"\bgetenv\s*\("),
    re.compile(r"\bscanf\s*\("),
    re.compile(r"\bsscanf\s*\("),
    re.compile(r"\bfscanf\s*\("),
    re.compile(r"argv\s*\["),
]

# Dangerous sinks in C / C++
C_SINK_RULES = [
    # integer overflow in size expression fed to alloc
    (re.compile(r"\b(malloc|calloc|realloc)\s*\(\s*([^)]*?\*[^)]*?)\)"),
     "integer-overflow",
     "HIGH",
     "alloc size uses multiplication — possible integer overflow feeding heap allocation"),

    # double-free pattern: free called on pointer in same scope twice
    (re.compile(r"\bfree\s*\(\s*([a-zA-Z_]\w*)\s*\)"),
     "double-free",
     "HIGH",
     "multiple free() calls on same pointer"),

    # off-by-one: loop condition using <= with buffer-size constant
    (re.compile(r"for\s*\([^;]*;\s*[a-zA-Z_]\w*\s*<=\s*(?:sizeof\s*\([^)]+\)|[0-9]+)\s*;"),
     "off-by-one",
     "MEDIUM",
     "loop uses <= against buffer size/constant — potential off-by-one"),

    # integer truncation: assigning int/long result to char/short
    (re.compile(r"\b(unsigned\s+char|char|short)\s+[a-zA-Z_]\w*\s*=\s*[a-zA-Z_]\w*\s*\+\s*[a-zA-Z_0-9]+"),
     "integer-truncation",
     "MEDIUM",
     "Narrowing assignment — integer value truncated to smaller type"),

    # NULL dereference: pointer returned from malloc not checked
    (re.compile(r"\b(malloc|calloc|realloc)\s*\([^)]+\)\s*;"),
     "null-pointer",
     "MEDIUM",
     "Return value of allocation function not checked for NULL"),

    # strncat/strncpy partial-copy: size arg is dest size not remaining space
    (re.compile(r"\bstrncat\s*\("),
     "stack-buffer-overflow",
     "HIGH",
     "strncat() — size arg should be remaining space, not dest size"),

    # memcpy / memmove with user-supplied length
    (re.compile(r"\b(memcpy|memmove)\s*\([^,]+,\s*[^,]+,\s*([a-zA-Z_]\w*)\s*\)"),
     "buffer-overflow",
     "MEDIUM",
     "memcpy/memmove length comes from a variable — validate bounds"),

    # Dangerous system/popen with taintable strings
    (re.compile(r"\b(system|popen)\s*\("),
     "os-command-injection",
     "HIGH",
     "system()/popen() call — command string may be attacker-controlled"),

    # Path traversal via relative paths in fopen
    (re.compile(r'\bfopen\s*\(\s*(?!["\"])'),
     "path-traversal",
     "MEDIUM",
     "fopen() with non-literal path — risk of directory traversal"),

    # Unsafe temp file
    (re.compile(r"\b(tmpnam|tempnam|mktemp)\s*\("),
     "insecure-temp-file",
     "MEDIUM",
     "Unsafe temporary file API — use mkstemp() instead"),

    # Unsafe random
    (re.compile(r"\brand\s*\(\s*\)|\bsrand\s*\("),
     "weak-rng",
     "LOW",
     "rand()/srand() is predictable — use /dev/urandom or getrandom()"),

    # Signed integer used as array index
    (re.compile(r"\bint\s+[a-zA-Z_]\w*\s*=[^;]*;\s*\n[^;]*\[[a-zA-Z_]\w*\]"),
     "negative-index",
     "MEDIUM",
     "Signed integer used as array index — negative value causes OOB read/write"),

    # Off-by-one: <= used as loop bound against a count/size/max variable
    (re.compile(
        r"for\s*\([^;]*;\s*[a-zA-Z_]\w*\s*<="
        r"\s*(?:[a-zA-Z_]\w*->|[a-zA-Z_]\w*\.)?[a-zA-Z_]\w*"
        r"(?:_count|_cnt|_size|_num|_max|_len|_regions|_handlers|_ports)\s*;",
    ),
     "off-by-one",
     "HIGH",
     "Loop uses '<= count_field' — final iteration accesses index[count_field] "
     "which is one past the last valid element (off-by-one / OOB)"),

    # Off-by-one: <= used against a plain compile-time constant in array loops
    (re.compile(
        r"for\s*\([^;]*;\s*[a-zA-Z_]\w*\s*<=\s*[A-Z_][A-Z0-9_]+\s*;"
    ),
     "off-by-one",
     "MEDIUM",
     "Loop uses '<= CONSTANT' — check whether CONSTANT is the last valid index "
     "or the array size (off-by-one if array size == CONSTANT)"),

    # Narrow-type cast of size expression — silent truncation
    (re.compile(
        r"static_cast\s*<\s*(?:uint16_t|uint8_t|short|unsigned short)\s*>"
        r"\s*\([^)]*(?:sizeof|size|len|count|num|\*)[^)]*\)"
    ),
     "integer-truncation",
     "HIGH",
     "Explicit cast of size expression to uint16_t/uint8_t — silently truncates "
     "values > 65535, turning a large allocation or length into a tiny one"),

    # Allocation immediately followed by unchecked copy into it
    (re.compile(
        r"\b(?:std::)?malloc\s*\([^)]+\)[^;]*;\s*\n"
        r"(?:[^\n]*\n){0,5}[^\n]*memcpy\s*\("
    ),
     "heap-buffer-overflow",
     "MEDIUM",
     "malloc() result used in memcpy within a few lines — verify the copy "
     "length cannot exceed the allocated size"),

    # Ring-buffer: index variable used directly as array subscript (no modulo)
    (re.compile(
        r"\b(?:irq_(?:head|tail)|head_idx|tail_idx|buf_head|buf_tail|wr_ptr|rd_ptr)\s*\]"
    ),
     "ring-buffer-overflow",
     "HIGH",
     "Ring-buffer head/tail index used as direct array subscript without modulo "
     "guard — if the index exceeds the buffer capacity this is an OOB write"),

    # Struct field used as for-loop bound without MAX guard (generic form)
    (re.compile(
        r"for\s*\([^;]*;\s*[a-zA-Z_]\w*\s*<\s*"
        r"[a-zA-Z_]\w*->(?:io|mmio|port|handler|slot)[_a-z]*count\s*;"
    ),
     "uncapped-loop-bound",
     "MEDIUM",
     "for-loop bounded by obj->*_count struct field without a MAX capacity guard — "
     "a corrupted or over-incremented field drives the loop past the array end"),
]

# Sanitizer patterns for C (reduce false positives)
C_SANITIZERS = [
    re.compile(r"\bstrlen\s*\([^)]+\)\s*[<>]=?\s*sizeof"),
    re.compile(r"\bif\s*\([^)]*!=\s*NULL\)"),
    re.compile(r"\bif\s*\([^)]*\s+==\s*NULL\)"),
    re.compile(r"-D_FORTIFY_SOURCE"),
]


def _analyze_c(src: str, lines: List[str]) -> List[TaintFinding]:
    findings: List[TaintFinding] = []
    seen: set = set()

    # ---- double-free detection: collect free(ptr) lines per pointer ----
    free_calls: dict = {}
    for m in re.finditer(r"\bfree\s*\(\s*([a-zA-Z_]\w*)\s*\)", src):
        ptr = m.group(1)
        ln = _lnum(src, m.start())
        free_calls.setdefault(ptr, []).append(ln)
    for ptr, call_lines in free_calls.items():
        if len(call_lines) >= 2:
            for ln in call_lines[1:]:
                key = ("double-free", ln)
                if key not in seen:
                    seen.add(key)
                    findings.append(TaintFinding(
                        issue_type="double-free",
                        line=ln,
                        snippet=_snippet_at(lines, ln),
                        confidence="HIGH",
                        lang="c",
                        note=f"free() called on '{ptr}' more than once — double-free"))

    # ---- all other sink rules ----
    for pattern, issue, confidence, note in C_SINK_RULES:
        if issue == "double-free":
            continue  # handled above
        for m in re.finditer(pattern, src):
            ln = _lnum(src, m.start())
            key = (issue, ln)
            if key in seen:
                continue
            seen.add(key)
            findings.append(TaintFinding(
                issue_type=issue,
                line=ln,
                snippet=_snippet_at(lines, ln),
                confidence=confidence,
                lang="c",
                note=note))

    return findings


# ---------------------------------------------------------------------------
# Python taint rules
# ---------------------------------------------------------------------------
PY_SINK_RULES = [
    # SQL injection via string formatting in execute()
    (re.compile(r'\.execute\s*\(\s*["\'].*%[sd].*["\']|\.execute\s*\(\s*[^)]*\.format\(|\.execute\s*\(\s*f["\']'),
     "sql-injection", "HIGH",
     "SQL execute() with string interpolation — use parameterised queries"),

    # Command injection
    (re.compile(r'\bos\.system\s*\(|\bsubprocess\.(call|Popen|run)\s*\([^)]*shell=True'),
     "os-command-injection", "HIGH",
     "shell=True or os.system() — may execute attacker-controlled commands"),

    # Eval/exec of dynamic input
    (re.compile(r'\beval\s*\(|\bexec\s*\('),
     "insecure-eval", "CRITICAL",
     "eval()/exec() of user input enables arbitrary code execution"),

    # Unsafe deserialization
    (re.compile(r'\bpickle\.loads?\s*\(|\bpickle\.load\s*\(|\byaml\.load\s*\([^)]+\)(?!\s*,\s*Loader)'),
     "insecure-deserialization", "CRITICAL",
     "pickle/yaml.load() deserializes arbitrary objects — use safe_load()"),

    # XML eXternal Entity
    (re.compile(r'\blxml\.etree|xml\.etree\.ElementTree|xml\.dom\.minidom'),
     "xxe-injection", "MEDIUM",
     "Python XML parser: disable external entity resolution (defusedxml)"),

    # Hardcoded secrets
    (re.compile(r'(?i)(password|secret|api_key|token)\s*=\s*["\'][^"\']{4,}["\']'),
     "hardcoded-password", "HIGH",
     "Hardcoded credential found — use environment variables or a secrets manager"),

    # Path traversal via user input in open()
    (re.compile(r'\bopen\s*\(\s*(?:request\.|input\(|os\.path\.join)[^)]*\)'),
     "path-traversal", "HIGH",
     "open() with user-influenced path — validate and sanitize with os.path.realpath()"),

    # SSRF via requests with user input
    (re.compile(r'\brequests\.(get|post|put|delete)\s*\(\s*(?!["\'](http|https))'),
     "ssrf", "HIGH",
     "requests.get/post with dynamic URL — validate scheme/host against allowlist"),

    # Weak hashing
    (re.compile(r'\bhashlib\.(md5|sha1)\s*\('),
     "weak-crypto", "MEDIUM",
     "MD5/SHA-1 is cryptographically broken — use SHA-256 or higher"),

    # Flask debug mode
    (re.compile(r'\.run\s*\([^)]*debug\s*=\s*True'),
     "insecure-config", "HIGH",
     "Flask debug=True enables the Werkzeug debugger — never enable in production"),

    # Template injection (Jinja2 / str.format with user input)
    (re.compile(r'render_template_string\s*\(|Template\s*\(\s*(?!["\'f])'),
     "template-injection", "HIGH",
     "Jinja2 render_template_string with variable template — risk of SSTI"),

    # Insecure random used for security
    (re.compile(r'\brandom\.(?:random|randint|choice|shuffle)\s*\('),
     "weak-rng", "LOW",
     "random module is not cryptographically secure — use secrets module"),

    # JWT none algorithm
    (re.compile(r'algorithms\s*=\s*\[\s*["\']none["\']'),
     "jwt-none-alg", "CRITICAL",
     "JWT 'none' algorithm accepted — attacker can forge tokens"),

    # Directory listing / debug routes
    (re.compile(r'\bapp\.add_url_rule\s*\(.*\.\*\*'),
     "insecure-config", "MEDIUM",
     "Wildcard route registration may expose unintended endpoints"),

    # XML bomb / billion laughs
    (re.compile(r'<!ENTITY\s+\w+\s+SYSTEM'),
     "xxe-injection", "HIGH",
     "XXE pattern in template — use defusedxml to parse XML"),
]


def _analyze_python(src: str, lines: List[str]) -> List[TaintFinding]:
    findings: List[TaintFinding] = []
    seen: set = set()
    for pattern, issue, confidence, note in PY_SINK_RULES:
        for m in re.finditer(pattern, src):
            ln = _lnum(src, m.start())
            key = (issue, ln)
            if key in seen:
                continue
            seen.add(key)
            findings.append(TaintFinding(
                issue_type=issue,
                line=ln,
                snippet=_snippet_at(lines, ln),
                confidence=confidence,
                lang="python",
                note=note))
    return findings


# ---------------------------------------------------------------------------
# Java taint rules
# ---------------------------------------------------------------------------
JAVA_SINK_RULES = [
    # SQL injection
    (re.compile(r'Statement\s*\.\s*(execute|executeQuery|executeUpdate)\s*\(\s*[^)]*\+'),
     "sql-injection", "HIGH",
     "JDBC Statement with string concatenation — use PreparedStatement"),

    # Prepared statement not used
    (re.compile(r'createStatement\s*\(\s*\)'),
     "sql-injection", "MEDIUM",
     "createStatement() used — prefer PreparedStatement for parameterised queries"),

    # Command injection via Runtime.exec
    (re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\('),
     "os-command-injection", "HIGH",
     "Runtime.exec() with dynamic arguments — command injection risk"),

    # Unsafe deserialization
    (re.compile(r'ObjectInputStream\s*\(|\.readObject\s*\('),
     "insecure-deserialization", "CRITICAL",
     "Java deserialization via ObjectInputStream — use safer formats (JSON/XML with schema)"),

    # Path traversal
    (re.compile(r'new\s+File\s*\(\s*(?!["\'"])'),
     "path-traversal", "MEDIUM",
     "new File() with dynamic path — validate with getCanonicalPath()"),

    # XXE
    (re.compile(r'DocumentBuilderFactory\.newInstance\(\)|SAXParserFactory\.newInstance\(\)'),
     "xxe-injection", "HIGH",
     "XML parser without disabling external entities — XXE risk"),

    # Weak crypto
    (re.compile(r'getInstance\s*\(\s*["\'](?:MD5|SHA1|DES|RC4)["\']'),
     "weak-crypto", "HIGH",
     "Weak cryptographic algorithm — use AES-256-GCM or SHA-256+"),

    # Hardcoded secrets
    (re.compile(r'(?i)(password|secret|apikey|token)\s*=\s*["\'][^"\']{4,}["\']'),
     "hardcoded-password", "HIGH",
     "Hardcoded credential in Java source — use environment variables or a vault"),

    # LDAP injection
    (re.compile(r'new\s+InitialDirContext|DirContext\s*\.\s*search\s*\('),
     "ldap-injection", "HIGH",
     "LDAP search with dynamic filter — sanitize with RFC 4515 escaping"),

    # Spring SpEL injection
    (re.compile(r'ExpressionParser|StandardEvaluationContext'),
     "template-injection", "HIGH",
     "Spring SpEL with user input may allow RCE — use SimpleEvaluationContext"),

    # Open redirect
    (re.compile(r'response\.sendRedirect\s*\(\s*request\.getParameter'),
     "open-redirect", "MEDIUM",
     "sendRedirect with request parameter — validate against allowlist"),

    # Insecure random
    (re.compile(r'\bnew\s+Random\s*\('),
     "weak-rng", "LOW",
     "java.util.Random is not cryptographically secure — use SecureRandom"),

    # Trust boundary violation
    (re.compile(r'request\.getParameter\s*\([^)]+\)\s*(?:;|\n)'),
     "input-validation", "LOW",
     "Request parameter used without validation — consider input sanitization"),
]


def _analyze_java(src: str, lines: List[str]) -> List[TaintFinding]:
    findings: List[TaintFinding] = []
    seen: set = set()
    for pattern, issue, confidence, note in JAVA_SINK_RULES:
        for m in re.finditer(pattern, src):
            ln = _lnum(src, m.start())
            key = (issue, ln)
            if key in seen:
                continue
            seen.add(key)
            findings.append(TaintFinding(
                issue_type=issue,
                line=ln,
                snippet=_snippet_at(lines, ln),
                confidence=confidence,
                lang="java",
                note=note))
    return findings


# ---------------------------------------------------------------------------
# Go taint rules
# ---------------------------------------------------------------------------
GO_SINK_RULES = [
    # SQL injection
    (re.compile(r'\.Query\s*\(\s*(?:fmt\.Sprintf|[a-zA-Z_]\w*\s*\+)'),
     "sql-injection", "HIGH",
     "database/sql Query with fmt.Sprintf or concatenation — use parameterised ($1, ?)"),

    # Command injection
    (re.compile(r'exec\.Command\s*\([^)]*\+'),
     "os-command-injection", "HIGH",
     "exec.Command with concatenated argument — command injection risk"),

    # Path traversal
    (re.compile(r'os\.Open\s*\(|ioutil\.ReadFile\s*\(|http\.ServeFile\s*\('),
     "path-traversal", "MEDIUM",
     "File open with dynamic path — validate with filepath.Clean()"),

    # Insecure TLS
    (re.compile(r'InsecureSkipVerify\s*:\s*true'),
     "insecure-tls", "HIGH",
     "TLS certificate verification disabled — MITM risk"),

    # Weak crypto
    (re.compile(r'md5\.New\(\)|sha1\.New\(\)'),
     "weak-crypto", "MEDIUM",
     "MD5/SHA-1 is cryptographically broken — use crypto/sha256"),

    # Hardcoded secrets
    (re.compile(r'(?i)(password|secret|apiKey|token)\s*:?=\s*"[^"]{4,}"'),
     "hardcoded-password", "HIGH",
     "Hardcoded credential in Go source — use environment variables"),

    # Race condition: goroutine accessing shared variable without sync
    (re.compile(r'go\s+func\s*\('),
     "race-condition", "MEDIUM",
     "Goroutine launched — ensure shared state is protected with sync primitives"),

    # HTTP redirect without validation
    (re.compile(r'http\.Redirect\s*\([^,]+,\s*[^,]+,\s*r\.(?:FormValue|URL\.Query)'),
     "open-redirect", "MEDIUM",
     "http.Redirect with user-controlled URL — validate against allowlist"),

    # SSRF via http.Get with variable
    (re.compile(r'http\.(?:Get|Post)\s*\(\s*(?!["\'])'),
     "ssrf", "HIGH",
     "http.Get/Post with dynamic URL — validate scheme and host against allowlist"),

    # Goroutine leak via unbuffered channel
    (re.compile(r'make\s*\(\s*chan\s+'),
     "resource-leak", "LOW",
     "Unbuffered channel — potential goroutine leak if consumer terminates"),

    # Integer overflow in slice index
    (re.compile(r'int\s*\([^)]*\)\s*\*\s*int\s*\('),
     "integer-overflow", "MEDIUM",
     "Multiplication of int-cast values may overflow before use as slice index"),
]


def _analyze_go(src: str, lines: List[str]) -> List[TaintFinding]:
    findings: List[TaintFinding] = []
    seen: set = set()
    for pattern, issue, confidence, note in GO_SINK_RULES:
        for m in re.finditer(pattern, src):
            ln = _lnum(src, m.start())
            key = (issue, ln)
            if key in seen:
                continue
            seen.add(key)
            findings.append(TaintFinding(
                issue_type=issue,
                line=ln,
                snippet=_snippet_at(lines, ln),
                confidence=confidence,
                lang="go",
                note=note))
    return findings


# ---------------------------------------------------------------------------
# Rust taint rules
# ---------------------------------------------------------------------------
RUST_SINK_RULES = [
    # unsafe block
    (re.compile(r'\bunsafe\s*\{'),
     "unsafe-block", "HIGH",
     "unsafe block — manual memory operations bypass Rust's safety guarantees"),

    # Raw pointer dereference
    (re.compile(r'\*\s*(?:mut|const)\s+[a-zA-Z_]\w*|\bas\s+\*(?:mut|const)'),
     "unsafe-block", "HIGH",
     "Raw pointer dereference — potential memory safety violation"),

    # panics on unwrap/expect without error handling
    (re.compile(r'\.unwrap\(\)|\.expect\('),
     "panic-unwrap", "LOW",
     ".unwrap()/.expect() will panic on None/Err — use match or ? operator"),

    # Use of transmute
    (re.compile(r'\bstd::mem::transmute\b|\bmem::transmute\b'),
     "unsafe-block", "CRITICAL",
     "mem::transmute reinterprets bits without any safety checks — avoid if possible"),

    # Weak crypto via deprecated crates
    (re.compile(r'extern\s+crate\s+(?:md5|sha1)\b'),
     "weak-crypto", "MEDIUM",
     "Deprecated weak crypto crate — use ring or RustCrypto sha2/sha3"),

    # Hardcoded secrets
    (re.compile(r'(?i)(password|secret|api_key|token)\s*:\s*&str\s*=\s*"[^"]{4,}"'),
     "hardcoded-password", "HIGH",
     "Hardcoded credential in Rust source — use environment variables"),

    # Command injection via std::process::Command with string format
    (re.compile(r'Command::new\s*\(\s*format!'),
     "os-command-injection", "HIGH",
     "process::Command with format! argument — command injection risk"),
]


def _analyze_rust(src: str, lines: List[str]) -> List[TaintFinding]:
    findings: List[TaintFinding] = []
    seen: set = set()
    for pattern, issue, confidence, note in RUST_SINK_RULES:
        for m in re.finditer(pattern, src):
            ln = _lnum(src, m.start())
            key = (issue, ln)
            if key in seen:
                continue
            seen.add(key)
            findings.append(TaintFinding(
                issue_type=issue,
                line=ln,
                snippet=_snippet_at(lines, ln),
                confidence=confidence,
                lang="rust",
                note=note))
    return findings


# ---------------------------------------------------------------------------
# Main analyzer class
# ---------------------------------------------------------------------------
EXT_LANG_MAP = {
    ".c":    "c",
    ".cpp":  "c",
    ".cc":   "c",
    ".h":    "c",
    ".hpp":  "c",
    ".py":   "python",
    ".java": "java",
    ".go":   "go",
    ".rs":   "rust",
}


class TaintAnalyzer:
    """Language-aware taint tracker.  Call analyze(file_path) to get findings."""

    def analyze(self, file_path: str) -> List[TaintFinding]:
        ext = os.path.splitext(file_path)[1].lower()
        lang = EXT_LANG_MAP.get(ext)
        if lang is None:
            return []

        src = _read(file_path)
        if not src:
            return []

        lines = _lines_of(src)

        dispatch = {
            "c":      _analyze_c,
            "python": _analyze_python,
            "java":   _analyze_java,
            "go":     _analyze_go,
            "rust":   _analyze_rust,
        }
        return dispatch[lang](src, lines)
