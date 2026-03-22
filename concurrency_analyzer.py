"""
concurrency_analyzer.py — P3: Multi-language concurrency bug detector.

Detects race conditions, missing lock/unlock pairing, atomic misuse, and
other threading bugs across C/C++, Java, Go, and Python source files using
regex-based pattern analysis (no AST required).

Exported API:
    ConcurrencyFinding   — dataclass
    ConcurrencyAnalyzer  — analyze(file_path) → List[ConcurrencyFinding]
"""

import re
import os
from dataclasses import dataclass
from typing import List, Set, Tuple, Dict


@dataclass
class ConcurrencyFinding:
    issue_type: str
    line:       int
    snippet:    str
    confidence: str   # HIGH | MEDIUM | LOW
    lang:       str
    note:       str = ""
    stage:      str = "Concurrency"


# ── Helpers ───────────────────────────────────────────────────────────────────
def _read(p: str) -> str:
    try:
        with open(p, "r", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""


def _snip(lines: List[str], ln: int) -> str:
    return lines[ln - 1].strip() if 1 <= ln <= len(lines) else ""


def _lineno(src: str, pos: int) -> int:
    return src[:pos].count("\n") + 1


# ═══════════════════════════════════════════════════════════════════════════════
# C / C++
# ═══════════════════════════════════════════════════════════════════════════════
def _analyze_c(src: str, src_lines: List[str]) -> List[ConcurrencyFinding]:
    findings: List[ConcurrencyFinding] = []
    seen: Set[Tuple[str, int]] = set()

    def _add(issue, ln, note, conf="MEDIUM"):
        k = (issue, ln)
        if k not in seen:
            seen.add(k)
            findings.append(ConcurrencyFinding(
                issue_type=issue, line=ln,
                snippet=_snip(src_lines, ln),
                confidence=conf, lang="c", note=note,
            ))

    # ── 1. pthread_create without corresponding lock in function ──────────────
    for m in re.finditer(r"\bpthread_create\s*\(", src):
        ln = _lineno(src, m.start())
        # Check if any mutex_lock appears nearby (heuristic window ±50 lines)
        window_start = max(0, m.start() - 1500)
        window_end = min(len(src), m.end() + 1500)
        window = src[window_start:window_end]
        if "pthread_mutex_lock" not in window and "std::mutex" not in window:
            _add("race-condition", ln,
                 "pthread_create() called but no pthread_mutex_lock/std::mutex "
                 "detected nearby — shared data may be unprotected",
                 "MEDIUM")

    # ── 2. Global/shared write inside thread function without lock ─────────────
    for m in re.finditer(
        r"\b(?:volatile\s+)?(?:int|long|char|double|float|uint\d+_t)\s+(\w+)\s*=", src
    ):
        # Is this a file-scope (global) declaration?  Heuristic: line is not indented
        ln    = _lineno(src, m.start())
        line_text = src_lines[ln - 1] if ln <= len(src_lines) else ""
        if not line_text.startswith((" ", "\t")) and not line_text.lstrip().startswith(("//", "/*", "#", "*")):  # top-level
            varname = m.group(1)
            # Find writes to this var inside threaded functions
            write_pat = re.compile(rf"\b{re.escape(varname)}\s*(?:\+\+|--|[\+\-\*\/\|&\^]?=)")
            for wm in write_pat.finditer(src):
                wln = _lineno(src, wm.start())
                w_text = src_lines[wln - 1] if wln <= len(src_lines) else ""
                if w_text.startswith(("    ", "\t")) and wln != ln:
                    context_start = max(0, wm.start() - 2000)
                    ctx = src[context_start:wm.start()]
                    if "pthread_mutex_lock" not in ctx[-1500:] and "atomic" not in ctx[-500:]:
                        _add("data-race", wln,
                             f"Write to global '{varname}' inside nested scope "
                             f"without mutex or std::atomic — potential data race",
                             "LOW")

    # ── 3. volatile misuse as synchronization ─────────────────────────────────
    for m in re.finditer(r"\bvolatile\s+(?:int|long|bool)\s+(\w+)", src):
        ln    = _lineno(src, m.start())
        name  = m.group(1)
        # Is it used as a loop-termination flag? That's the classic misuse
        loop_pat = re.compile(rf"while\s*\(\s*!?\s*{re.escape(name)}\s*\)")
        if loop_pat.search(src):
            _add("volatile-misuse", ln,
                 f"'volatile {name}' used as thread-synchronization flag — "
                 f"volatile does NOT guarantee visibility on modern CPUs; "
                 f"use std::atomic<bool> or a mutex instead",
                 "HIGH")

    # ── 4. Missing std::atomic on shared counter ──────────────────────────────
    for m in re.finditer(
        r"(?:static\s+|extern\s+)?(?:int|long|unsigned)\s+(\w*count\w*|"
        r"\w*counter\w*|\w*total\w*|\w*refcount\w*)\s*=\s*0\s*;",
        src, re.IGNORECASE,
    ):
        ln   = _lineno(src, m.start())
        name = m.group(1)
        line_text = src_lines[ln - 1] if ln <= len(src_lines) else ""
        if not line_text.startswith((" ", "\t")):
            # Global counter without atomic
            incr_pat = re.compile(rf"\b{re.escape(name)}\s*(?:\+\+|--|\+=|-=)")
            if incr_pat.search(src):
                _add("missing-atomic", ln,
                     f"Global counter '{name}' incremented/decremented without "
                     f"std::atomic or mutex — non-atomic RMW introduces race",
                     "MEDIUM")

    # ── 5. Double-checked locking without volatile / atomic ───────────────────
    dcl = re.compile(
        r"if\s*\(\s*(\w+)\s*==\s*(?:nullptr|NULL|0)\s*\)\s*\{[^}]*"
        r"(?:lock|mutex)[^}]*\1\s*=[^}]*if\s*\(\s*\1\s*==\s*(?:nullptr|NULL|0)\s*\)",
        re.DOTALL,
    )
    for m in dcl.finditer(src):
        ln = _lineno(src, m.start())
        _add("double-checked-locking", ln,
             "Double-checked locking without std::atomic — broken on some architectures; "
             "use std::call_once or atomic<T*>",
             "HIGH")

    # ── 6. Thread creation in destructor / signal handler ─────────────────────
    for m in re.finditer(r"\~\s*\w+\s*\([^)]*\)\s*\{[^}]*pthread_create", src, re.DOTALL):
        ln = _lineno(src, m.start())
        _add("thread-in-destructor", ln,
             "pthread_create() inside destructor — may cause use-after-free or "
             "double-free when object lifetime ends before thread completes",
             "HIGH")

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Java
# ═══════════════════════════════════════════════════════════════════════════════
def _analyze_java(src: str, src_lines: List[str]) -> List[ConcurrencyFinding]:
    findings: List[ConcurrencyFinding] = []
    seen: Set[Tuple[str, int]] = set()

    def _add(issue, ln, note, conf="MEDIUM"):
        k = (issue, ln)
        if k not in seen:
            seen.add(k)
            findings.append(ConcurrencyFinding(
                issue_type=issue, line=ln,
                snippet=_snip(src_lines, ln),
                confidence=conf, lang="java", note=note,
            ))

    # ── 1. Thread subclass without synchronized method ────────────────────────
    thread_class = re.compile(
        r"class\s+(\w+)\s+extends\s+Thread\s*\{(.*?)(?=\nclass|\Z)", re.DOTALL
    )
    for m in thread_class.finditer(src):
        body = m.group(2)
        ln   = _lineno(src, m.start())
        if "synchronized" not in body and "volatile" not in body:
            # Look for field writes that might be races
            if re.search(r"(?:private|protected|public)\s+(?:int|long|boolean|String)\s+\w+", body):
                _add("unsynchronized-thread", ln,
                     f"Class '{m.group(1)}' extends Thread and has instance fields "
                     f"but no synchronized methods or volatile fields — data race risk",
                     "MEDIUM")

    # ── 2. Collections.synchronizedList / synchronizedMap used unsafely ───────
    for m in re.finditer(
        r"Collections\.synchronized(?:List|Map|Set)\s*\(", src
    ):
        ln = _lineno(src, m.start())
        # Check if iterator used without sync block
        window = src[m.end():min(len(src), m.end() + 3000)]
        if re.search(r"\.iterator\(\)|for\s*\(.*?:", window):
            if "synchronized" not in window[:500]:
                _add("unsafe-iteration", ln,
                     "Collections.synchronizedXxx() requires external synchronization "
                     "during iteration — missing synchronized block around iterator",
                     "HIGH")

    # ── 3. Double-checked locking pattern (classic Java broken DCL) ───────────
    for m in re.finditer(
        r"if\s*\(\s*(\w+)\s*==\s*null\s*\)\s*\{[^}]*synchronized[^}]*"
        r"if\s*\(\s*\1\s*==\s*null\s*\)",
        src, re.DOTALL,
    ):
        ln   = _lineno(src, m.start())
        name = m.group(1)
        if "volatile" not in src[max(0, m.start() - 500):m.start()]:
            _add("double-checked-locking", ln,
                 f"Double-checked locking on '{name}' without volatile — "
                 f"broken before Java 5 memory model; add 'volatile' keyword",
                 "HIGH")

    # ── 4. Shared HashMap accessed without synchronization ───────────────────
    for m in re.finditer(r"new\s+HashMap\s*<", src):
        ln   = _lineno(src, m.start())
        line = src_lines[ln - 1] if ln <= len(src_lines) else ""
        if not line.strip().startswith(("//", "*")):
            # Is this field used in multiple threads?
            if "new Thread" in src or "implements Runnable" in src:
                _add("unsynchronized-hashmap", ln,
                     "HashMap accessed in multi-threaded context — use ConcurrentHashMap "
                     "or synchronize all access; HashMap is NOT thread-safe",
                     "LOW")

    # ── 5. wait()/notify() called outside synchronized block ──────────────────
    for m in re.finditer(r"\.\s*(?:wait|notify|notifyAll)\s*\(", src):
        ln      = _lineno(src, m.start())
        context = src[max(0, m.start() - 500):m.start()]
        if "synchronized" not in context:
            _add("wait-outside-sync", ln,
                 "wait()/notify()/notifyAll() must be called from within a "
                 "synchronized block — IllegalMonitorStateException at runtime",
                 "HIGH")

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Go
# ═══════════════════════════════════════════════════════════════════════════════
def _analyze_go(src: str, src_lines: List[str]) -> List[ConcurrencyFinding]:
    findings: List[ConcurrencyFinding] = []
    seen: Set[Tuple[str, int]] = set()

    def _add(issue, ln, note, conf="MEDIUM"):
        k = (issue, ln)
        if k not in seen:
            seen.add(k)
            findings.append(ConcurrencyFinding(
                issue_type=issue, line=ln,
                snippet=_snip(src_lines, ln),
                confidence=conf, lang="go", note=note,
            ))

    # ── 1. Goroutine closes over loop variable ────────────────────────────────
    for m in re.finditer(
        r"for\s+(?:\w+\s*,\s*)?(\w+)\s*:=\s*range\s+\w+[^{]*\{[^}]*go\s+func\s*\(",
        src, re.DOTALL,
    ):
        loop_var = m.group(1)
        body     = src[m.start():min(len(src), m.end() + 300)]
        if loop_var in body and "(" + loop_var + ")" not in body:
            ln = _lineno(src, m.start())
            _add("goroutine-loop-closure", ln,
                 f"Goroutine captures loop variable '{loop_var}' by reference — "
                 f"all goroutines will see the final value; pass as argument: "
                 f"go func({loop_var} TYPE) {{ ... }}({loop_var})",
                 "HIGH")

    # ── 2. Map written in multiple goroutines without mutex ───────────────────
    if "go func" in src or "go " in src:
        for m in re.finditer(r"\bmap\[", src):
            ln = _lineno(src, m.start())
            # Check if map is written inside goroutine
            context = src[m.end():min(len(src), m.end() + 2000)]
            if re.search(r"\bgo\s+func", context):
                nearby = src[max(0, m.start() - 200):m.start() + 200]
                if "sync.Mutex" not in nearby and "sync.RWMutex" not in nearby:
                    _add("concurrent-map-write", ln,
                         "Map may be written inside a goroutine without mutex — "
                         "concurrent map writes cause panic at runtime; use "
                         "sync.Mutex or sync.Map",
                         "MEDIUM")

    # ── 3. WaitGroup.Add() inside goroutine instead of before go ─────────────
    for m in re.finditer(r"go\s+func\s*\([^)]*\)\s*\{[^}]*\.Add\s*\(", src, re.DOTALL):
        ln = _lineno(src, m.start())
        _add("waitgroup-add-in-goroutine", ln,
             "sync.WaitGroup.Add() called INSIDE goroutine — race: goroutine may "
             "complete before Add() is called; call wg.Add(1) BEFORE 'go func'",
             "HIGH")

    # ── 4. Channel send/receive without select for timeout ───────────────────
    for m in re.finditer(r"\bch\s*<-\s*|<-\s*\bch\b", src):
        ln = _lineno(src, m.start())
        context = src[max(0, m.start() - 200):m.start() + 200]
        if "select" not in context and "time.After" not in context:
            # Check if inside goroutine
            goroutine_ctx = src[max(0, m.start() - 1000):m.start()]
            if "go func" in goroutine_ctx or "func(" in goroutine_ctx:
                _add("unbuffered-channel-block", ln,
                     "Channel operation without select/timeout — goroutine may "
                     "block indefinitely if no sender/receiver is ready; consider "
                     "select { case: ... case <-time.After(...): }",
                     "LOW")

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Python
# ═══════════════════════════════════════════════════════════════════════════════
def _analyze_python(src: str, src_lines: List[str]) -> List[ConcurrencyFinding]:
    findings: List[ConcurrencyFinding] = []
    seen: Set[Tuple[str, int]] = set()

    def _add(issue, ln, note, conf="MEDIUM"):
        k = (issue, ln)
        if k not in seen:
            seen.add(k)
            findings.append(ConcurrencyFinding(
                issue_type=issue, line=ln,
                snippet=_snip(src_lines, ln),
                confidence=conf, lang="python", note=note,
            ))

    # ── 1. threading.Thread with shared mutable state ────────────────────────
    if "threading.Thread" in src or "Thread(target=" in src:
        # Look for list/dict mutations without lock
        for m in re.finditer(r"(?:\.append\(|\.extend\(|\.update\(|\[.*?\]\s*=)", src):
            ln = _lineno(src, m.start())
            context = src[max(0, m.start() - 1000):m.start()]
            if ("threading.Thread" in context or "Thread(target=" in context):
                if "threading.Lock" not in context and "with lock" not in context:
                    _add("thread-unsafe-mutation", ln,
                         "Mutable shared state modified in threading.Thread context "
                         "without threading.Lock — dict/list operations are NOT "
                         "atomically safe in multi-threaded Python",
                         "MEDIUM")

    # ── 2. asyncio: missing await ─────────────────────────────────────────────
    if "async def" in src or "asyncio" in src:
        for m in re.finditer(r"\basync\s+def\s+\w+", src):
            func_start = m.end()
            # Find the function body (next 40 lines)
            body_end = src.find("\nasync def", func_start) or len(src)
            body = src[func_start:min(len(src), func_start + 2000)]
            for cm in re.finditer(r"\b(\w+_async|async_\w+|aio\w+)\s*\(", body):
                inner_ln = _lineno(src, func_start + cm.start())
                line_txt = src_lines[inner_ln - 1] if inner_ln <= len(src_lines) else ""
                if "await" not in line_txt and "#" not in line_txt.split("await")[0]:
                    _add("missing-await", inner_ln,
                         f"Coroutine '{cm.group(1)}()' called without 'await' inside "
                         f"async function — coroutine object created but never executed",
                         "HIGH")

    # ── 3. multiprocessing shared state without Manager/Lock ─────────────────
    if "multiprocessing" in src:
        for m in re.finditer(r"multiprocessing\.Process\s*\(", src):
            ln = _lineno(src, m.start())
            context = src[max(0, m.start() - 500):m.start() + 500]
            if "Manager()" not in context and "multiprocessing.Lock" not in context:
                _add("multiprocess-unshared", ln,
                     "multiprocessing.Process launched without Manager() or "
                     "multiprocessing.Lock — plain Python objects are NOT shared "
                     "between processes; use multiprocessing.Queue/Pipe/Manager",
                     "LOW")

    # ── 4. threading without daemon=True for long-lived programs ─────────────
    for m in re.finditer(r"Thread\s*\([^)]*\)", src):
        ln = _lineno(src, m.start())
        if "daemon" not in m.group(0) and "daemon=True" not in m.group(0):
            _add("non-daemon-thread", ln,
                 "Thread created without daemon=True — program will not exit "
                 "until this thread finishes; set daemon=True for background workers",
                 "LOW")

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Language dispatch
# ═══════════════════════════════════════════════════════════════════════════════
_LANG_MAP: Dict[str, str] = {
    ".c": "c", ".cpp": "c", ".cc": "c", ".cxx": "c", ".h": "c", ".hpp": "c",
    ".java": "java",
    ".go": "go",
    ".py": "python",
}


class ConcurrencyAnalyzer:
    """
    Multi-language concurrency bug detector.
    Supports C/C++, Java, Go, and Python.
    """

    def analyze(self, file_path: str) -> List[ConcurrencyFinding]:
        ext  = os.path.splitext(file_path)[1].lower()
        lang = _LANG_MAP.get(ext)
        if lang is None:
            return []

        src = _read(file_path)
        if not src:
            return []
        lines = src.splitlines()

        if lang == "c":
            return _analyze_c(src, lines)
        if lang == "java":
            return _analyze_java(src, lines)
        if lang == "go":
            return _analyze_go(src, lines)
        if lang == "python":
            return _analyze_python(src, lines)
        return []
