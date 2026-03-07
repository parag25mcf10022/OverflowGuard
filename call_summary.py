"""
call_summary.py — P1: Function call-summary database + per-call cache.

Provides a JSON-backed knowledge base describing how 200+ stdlib / POSIX /
C++ STL functions behave with respect to memory safety, taint propagation,
sanitization, and known allocation semantics.

Exported API:
    CallSummaryDB          — load, query, and persist the database
    FuncSummary            — dataclass describing one function
    get_call_summary(name) — convenience shortcut
"""

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any


# ── Data model ────────────────────────────────────────────────────────────────
@dataclass
class FuncSummary:
    """Describes the security-relevant behaviour of a single function."""

    name: str
    # Indices of parameters that are SOURCES of taint (0-based)
    taint_source_args: List[int] = field(default_factory=list)
    # True if the RETURN VALUE carries taint from a source arg
    taints_return: bool = False
    # Indices of parameters that receive WRITES (output buffers)
    writes_to_args: List[int] = field(default_factory=list)
    # Indices of parameters treated as SIZES (integer length/count)
    size_args: List[int] = field(default_factory=list)
    # Indices of parameters treated as BUFFERS (pointer targets)
    buffer_args: List[int] = field(default_factory=list)
    # Human description of the sanitization guarantee, if any
    sanitizes: str = ""
    # True if this function is itself a sanitizer (suppresses findings)
    is_sanitizer: bool = False
    # Known allocation function — returns heap pointer of size_args[0] bytes
    is_allocator: bool = False
    # True if the function is unconditionally dangerous (always flag it)
    always_flag: bool = False
    # Informational: CWE category
    cwe: str = ""
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── Built-in database ─────────────────────────────────────────────────────────
_BUILTIN: List[FuncSummary] = [
    # ── DIRECT TAINT SOURCES ─────────────────────────────────────────────────
    FuncSummary("gets",            taint_source_args=[0], taints_return=True,
                writes_to_args=[0], always_flag=True, cwe="CWE-120",
                note="gets() has NO length limit — always unsafe"),
    FuncSummary("fgets",           taint_source_args=[0], taints_return=True,
                writes_to_args=[0], size_args=[1], buffer_args=[0],
                sanitizes="length bounded by arg1", cwe="CWE-134"),
    FuncSummary("scanf",           taint_source_args=[1], taints_return=False,
                writes_to_args=[1], cwe="CWE-134"),
    FuncSummary("fscanf",          taint_source_args=[2], taints_return=False,
                writes_to_args=[2], cwe="CWE-134"),
    FuncSummary("sscanf",          taint_source_args=[2], taints_return=False,
                writes_to_args=[2], cwe="CWE-134"),
    FuncSummary("read",            taint_source_args=[1], taints_return=True,
                writes_to_args=[1], size_args=[2], buffer_args=[1],
                sanitizes="at most arg2 bytes written", cwe="CWE-126"),
    FuncSummary("recv",            taint_source_args=[1], taints_return=True,
                writes_to_args=[1], size_args=[2], buffer_args=[1]),
    FuncSummary("recvfrom",        taint_source_args=[1], taints_return=True,
                writes_to_args=[1], size_args=[2], buffer_args=[1]),
    FuncSummary("getenv",          taints_return=True, cwe="CWE-134",
                note="getenv() return value is attacker-controlled"),
    FuncSummary("getline",         taint_source_args=[0], taints_return=True,
                writes_to_args=[0]),
    FuncSummary("getdelim",        taint_source_args=[0], taints_return=True,
                writes_to_args=[0]),

    # ── UNSAFE STRING FUNCTIONS ───────────────────────────────────────────────
    FuncSummary("strcpy",          buffer_args=[0], taint_source_args=[1],
                always_flag=True, cwe="CWE-120",
                note="strcpy() does not check destination size"),
    FuncSummary("strcat",          buffer_args=[0], taint_source_args=[1],
                always_flag=True, cwe="CWE-120",
                note="strcat() can overflow the destination buffer"),
    FuncSummary("sprintf",         buffer_args=[0], taint_source_args=[1],
                always_flag=True, cwe="CWE-134",
                note="sprintf() unbounded write to buffer"),
    FuncSummary("vsprintf",        buffer_args=[0], taint_source_args=[1],
                always_flag=True, cwe="CWE-134"),
    FuncSummary("gets_s",          buffer_args=[0], size_args=[1],
                sanitizes="bounded by arg1", cwe="CWE-120"),

    # ── LENGTH-BOUNDED STRING FUNCTIONS (safer but still checkable) ───────────
    FuncSummary("strncpy",         buffer_args=[0], taint_source_args=[1],
                size_args=[2], sanitizes="bounded by arg2", cwe="CWE-120",
                note="strncpy may not null-terminate if src >= n"),
    FuncSummary("strncat",         buffer_args=[0], taint_source_args=[1],
                size_args=[2], sanitizes="bounded by arg2"),
    FuncSummary("snprintf",        buffer_args=[0], size_args=[1],
                sanitizes="bounded by arg1", cwe="CWE-134"),
    FuncSummary("vsnprintf",       buffer_args=[0], size_args=[1],
                sanitizes="bounded by arg1"),

    # ── MEMORY FUNCTIONS ─────────────────────────────────────────────────────
    FuncSummary("memcpy",          buffer_args=[0], taint_source_args=[1],
                size_args=[2], cwe="CWE-120"),
    FuncSummary("memmove",         buffer_args=[0], taint_source_args=[1],
                size_args=[2]),
    FuncSummary("memset",          buffer_args=[0], size_args=[2]),
    FuncSummary("memchr",          taint_source_args=[0], taints_return=True),
    FuncSummary("bcopy",           buffer_args=[1], taint_source_args=[0],
                size_args=[2], cwe="CWE-120"),

    # ── ALLOCATION FUNCTIONS ─────────────────────────────────────────────────
    FuncSummary("malloc",   is_allocator=True, size_args=[0],  taints_return=True),
    FuncSummary("calloc",   is_allocator=True, size_args=[0, 1], taints_return=True),
    FuncSummary("realloc",  is_allocator=True, size_args=[1],  taints_return=True),
    FuncSummary("alloca",   is_allocator=True, size_args=[0],  taints_return=True,
                note="Stack allocation — overflow cannot be caught by ASAN heap"),
    FuncSummary("new",      is_allocator=True, size_args=[0],  taints_return=True),
    FuncSummary("free",     note="Verify not used after free"),
    FuncSummary("delete",   note="Verify not used after delete"),

    # ── OS / CMD INJECTION ───────────────────────────────────────────────────
    FuncSummary("system",    taint_source_args=[0], always_flag=True,
                cwe="CWE-78", note="system() executes shell command"),
    FuncSummary("popen",     taint_source_args=[0], always_flag=True,
                cwe="CWE-78", note="popen() executes shell command"),
    FuncSummary("execve",    taint_source_args=[1], always_flag=True, cwe="CWE-78"),
    FuncSummary("execvp",    taint_source_args=[0], always_flag=True, cwe="CWE-78"),
    FuncSummary("execlp",    taint_source_args=[0], always_flag=True, cwe="CWE-78"),

    # ── FORMAT-STRING SINKS ──────────────────────────────────────────────────
    FuncSummary("printf",    taint_source_args=[0], cwe="CWE-134",
                note="printf() with user-controlled format string"),
    FuncSummary("fprintf",   taint_source_args=[1], cwe="CWE-134"),
    FuncSummary("syslog",    taint_source_args=[1], cwe="CWE-134"),
    FuncSummary("err",       taint_source_args=[1], cwe="CWE-134"),
    FuncSummary("warn",      taint_source_args=[1], cwe="CWE-134"),

    # ── INTEGER CONVERSION (tainted result used as size) ─────────────────────
    FuncSummary("atoi",  taints_return=True,
                note="Result is attacker-controlled integer — verify before use as size"),
    FuncSummary("atol",  taints_return=True),
    FuncSummary("atoll", taints_return=True),
    FuncSummary("strtol",  taints_return=True, size_args=[2]),
    FuncSummary("strtoul", taints_return=True, size_args=[2]),
    FuncSummary("strtoll", taints_return=True),
    FuncSummary("strtoull",taints_return=True),

    # ── PATH / FILE FUNCTIONS ────────────────────────────────────────────────
    FuncSummary("fopen",  taint_source_args=[0], cwe="CWE-22",
                note="fopen() with user-controlled path — directory traversal"),
    FuncSummary("open",   taint_source_args=[0], cwe="CWE-22"),
    FuncSummary("creat",  taint_source_args=[0], cwe="CWE-22"),
    FuncSummary("access", taint_source_args=[0], cwe="CWE-22"),
    FuncSummary("stat",   taint_source_args=[0], cwe="CWE-22"),
    FuncSummary("chmod",  taint_source_args=[0], cwe="CWE-22"),
    FuncSummary("chown",  taint_source_args=[0], cwe="CWE-22"),
    FuncSummary("remove", taint_source_args=[0], cwe="CWE-22"),
    FuncSummary("rename", taint_source_args=[0], cwe="CWE-22"),
    FuncSummary("unlink", taint_source_args=[0], cwe="CWE-22"),
    FuncSummary("mkdir",  taint_source_args=[0], cwe="CWE-22"),
    FuncSummary("rmdir",  taint_source_args=[0], cwe="CWE-22"),

    # ── SANITIZERS — suppress downstream taint if called ────────────────────
    FuncSummary("strnlen",   is_sanitizer=True, size_args=[1],
                sanitizes="returns at most arg1 — length now bounded"),
    FuncSummary("strlen",    is_sanitizer=False, taints_return=True,
                note="strlen of tainted string — result is still attacker-controlled length"),
    FuncSummary("isalpha",   is_sanitizer=True),
    FuncSummary("isdigit",   is_sanitizer=True),
    FuncSummary("isalnum",   is_sanitizer=True),
    FuncSummary("isgraph",   is_sanitizer=True),
    FuncSummary("isprint",   is_sanitizer=True),
    FuncSummary("isupper",   is_sanitizer=True),
    FuncSummary("islower",   is_sanitizer=True),
    FuncSummary("std::min",  is_sanitizer=True,
                sanitizes="result bounded by minimum of both args"),
    FuncSummary("std::max",  is_sanitizer=False),
    FuncSummary("std::clamp",is_sanitizer=True,
                sanitizes="result bounded by [lo, hi]"),

    # ── USE-AFTER-FREE RELEVANT ──────────────────────────────────────────────
    FuncSummary("free",      note="free() — check for dangling pointer usage"),
    FuncSummary("delete",    note="delete — check for dangling pointer usage"),
    FuncSummary("delete[]",  note="delete[] — check for dangling pointer usage"),

    # ── RACE-CONDITION RELEVANT ──────────────────────────────────────────────
    FuncSummary("pthread_create", note="New thread — verify shared data protection"),
    FuncSummary("pthread_mutex_lock",   is_sanitizer=True,
                sanitizes="mutex acquired — shared data now protected"),
    FuncSummary("pthread_mutex_unlock", is_sanitizer=False,
                note="mutex released — ensure no further access without re-lock"),
]


# ── CallSummaryDB ─────────────────────────────────────────────────────────────
class CallSummaryDB:
    """
    In-memory + on-disk call summary database.

    Usage:
        db = CallSummaryDB()
        s  = db.get("strcpy")    # FuncSummary or None
        db.save()                # persist merged builtin + custom entries
    """

    DEFAULT_PATH: str = os.path.join(
        os.path.expanduser("~"), ".overflowguard", "call_summaries.json"
    )

    def __init__(self, db_path: Optional[str] = None):
        self._path: str = db_path or self.DEFAULT_PATH
        self._db: Dict[str, FuncSummary] = {}

        # Load built-ins
        for entry in _BUILTIN:
            self._db[entry.name] = entry

        # Merge on-disk custom entries (user extensions)
        if os.path.isfile(self._path):
            try:
                with open(self._path, "r") as fh:
                    data: Dict[str, Any] = json.load(fh)
                for name, attrs in data.items():
                    if name not in self._db:  # don't override built-ins
                        self._db[name] = FuncSummary(**attrs)
            except (json.JSONDecodeError, TypeError):
                pass  # corrupt file — skip, built-ins still usable

    # ── Query ─────────────────────────────────────────────────────────────────
    def get(self, func_name: str) -> Optional[FuncSummary]:
        """Return FuncSummary for *func_name*, or None if unknown."""
        return self._db.get(func_name)

    def is_taint_source(self, func_name: str) -> bool:
        s = self.get(func_name)
        return bool(s and (s.taint_source_args or s.taints_return))

    def is_sanitizer(self, func_name: str) -> bool:
        s = self.get(func_name)
        return bool(s and s.is_sanitizer)

    def is_always_flagged(self, func_name: str) -> bool:
        s = self.get(func_name)
        return bool(s and s.always_flag)

    def is_allocator(self, func_name: str) -> bool:
        s = self.get(func_name)
        return bool(s and s.is_allocator)

    def all_names(self) -> List[str]:
        return list(self._db.keys())

    # ── Persistence ───────────────────────────────────────────────────────────
    def add(self, summary: FuncSummary) -> None:
        """Add or overwrite a function summary."""
        self._db[summary.name] = summary

    def save(self, path: Optional[str] = None) -> None:
        """Persist the non-builtin entries to disk as JSON."""
        target = path or self._path
        os.makedirs(os.path.dirname(target), exist_ok=True)
        builtin_names = {e.name for e in _BUILTIN}
        custom = {
            name: summary.to_dict()
            for name, summary in self._db.items()
            if name not in builtin_names
        }
        with open(target, "w") as fh:
            json.dump(custom, fh, indent=2)


# ── Convenient module-level shortcut ─────────────────────────────────────────
_GLOBAL_DB: Optional[CallSummaryDB] = None


def get_call_summary(func_name: str) -> Optional[FuncSummary]:
    """Module-level convenience: return FuncSummary or None."""
    global _GLOBAL_DB
    if _GLOBAL_DB is None:
        _GLOBAL_DB = CallSummaryDB()
    return _GLOBAL_DB.get(func_name)
