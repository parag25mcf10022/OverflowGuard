"""
concolic_fuzzer.py — P4: Concolic / hybrid fuzzing engine.

Combines concrete execution (fuzzing) with symbolic constraint solving
to automatically generate inputs that trigger overflow conditions.

Three operational tiers — used in order of availability:
  Tier 1 (best):  angr symbolic execution — generates proven trigger inputs
  Tier 2:         AFL++ / libFuzzer wrapper — coverage-guided fuzzing
  Tier 3:         Heuristic seed mutation   — pure-Python fallback, always available

All three share the same public API so callers are agnostic to the backend.

Exported API:
    ConcolicFinding     — dataclass
    ConcolicFuzzer      — fuzz(file_path) → List[ConcolicFinding]
                        — is_angr_available() → bool
                        — is_afl_available() → bool
"""

import os
import re
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import angr  # type: ignore
    import claripy  # type: ignore
    _HAS_ANGR = True
except ImportError:
    _HAS_ANGR = False


@dataclass
class ConcolicFinding:
    issue_type:    str
    line:          int
    snippet:       str
    confidence:    str
    trigger_input: str = ""    # concrete input bytes (hex or human-readable)
    lang:          str = "c"
    note:          str = ""
    stage:         str = "Concolic"


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


# ── Tier 1: angr symbolic execution ──────────────────────────────────────────
def _fuzz_with_angr(binary_path: str) -> List[ConcolicFinding]:
    """
    Load the compiled binary into angr, mark stdin bytes as symbolic,
    and explore paths to find states that trigger a crash or OOB condition.
    """
    findings: List[ConcolicFinding] = []
    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
        stdin_sym = claripy.BVS("stdin", 8 * 256)  # 256-byte symbolic stdin

        state = proj.factory.full_init_state(
            stdin=angr.SimFileStream(name="stdin", content=stdin_sym, has_end=False),
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            },
        )

        simgr = proj.factory.simulation_manager(state)
        simgr.explore(find=lambda s: "overflow" in s.posix.dumps(2).decode("utf-8", errors="replace"),
                      avoid=[],
                      timeout=15)

        if simgr.found:
            for s in simgr.found[:3]:
                trigger_bytes = s.solver.eval(stdin_sym, cast_to=bytes)
                trigger_hex   = trigger_bytes.hex()
                findings.append(ConcolicFinding(
                    issue_type="symbolic-trigger",
                    line=0,
                    snippet="(angr symbolic execution path)",
                    confidence="HIGH",
                    trigger_input=trigger_hex,
                    note=(
                        f"angr found a path where stdin=0x{trigger_hex[:32]}... "
                        f"triggers an overflow / crash condition"
                    ),
                    stage="Concolic",
                ))
    except Exception as e:
        # angr exploration can fail for many benign reasons; swallow and continue
        findings.append(ConcolicFinding(
            issue_type="symbolic-analysis-error",
            line=0,
            snippet="",
            confidence="LOW",
            note=f"angr analysis failed: {e}",
            stage="Concolic",
        ))
    return findings


# ── Tier 2: AFL++ / libFuzzer wrapper ────────────────────────────────────────
def _fuzz_with_afl(
    source_path: str,
    timeout_sec: int = 20,
) -> List[ConcolicFinding]:
    """
    Compile the file with AFL++ instrumentation and run afl-fuzz briefly.
    Reports any crash-inducing inputs found in the output corpus.
    """
    findings: List[ConcolicFinding] = []
    afl_fuzz = shutil.which("afl-fuzz")
    afl_cc   = shutil.which("afl-clang-fast") or shutil.which("afl-cc")
    if not afl_fuzz or not afl_cc:
        return []

    with tempfile.TemporaryDirectory(prefix="og_afl_") as tmpdir:
        binary   = os.path.join(tmpdir, "target")
        seed_dir = os.path.join(tmpdir, "seeds")
        out_dir  = os.path.join(tmpdir, "out")
        os.makedirs(seed_dir)
        os.makedirs(out_dir)

        # Write a minimal initial seed
        with open(os.path.join(seed_dir, "seed1"), "wb") as fh:
            fh.write(b"A" * 64)
        with open(os.path.join(seed_dir, "seed2"), "wb") as fh:
            fh.write(b"\x00" * 64)

        # Compile with AFL instrumentation
        compile_result = subprocess.run(
            [afl_cc, "-g", "-fsanitize=address", "-o", binary, source_path],
            capture_output=True, text=True, timeout=30,
        )
        if compile_result.returncode != 0:
            return []

        # Run afl-fuzz (short run)
        env = os.environ.copy()
        env["AFL_NO_UI"] = "1"
        env["AFL_SKIP_CPUFREQ"] = "1"
        try:
            subprocess.run(
                [afl_fuzz, "-i", seed_dir, "-o", out_dir,
                 "-t", "1000", "--",  # 1 second per test-case
                 binary, "@@"],
                timeout=timeout_sec, capture_output=True, env=env,
            )
        except subprocess.TimeoutExpired:
            pass  # expected — collect results anyway

        # Check for crashes
        crash_dir = os.path.join(out_dir, "default", "crashes")
        if os.path.isdir(crash_dir):
            for crash_file in os.listdir(crash_dir):
                if crash_file.startswith("id:"):
                    crash_path = os.path.join(crash_dir, crash_file)
                    try:
                        with open(crash_path, "rb") as fh:
                            data = fh.read(256)
                        findings.append(ConcolicFinding(
                            issue_type="afl-crash",
                            line=0,
                            snippet="(AFL++ coverage-guided fuzzing)",
                            confidence="HIGH",
                            trigger_input=data.hex(),
                            note=(
                                f"AFL++ found a crash-inducing input: "
                                f"0x{data.hex()[:32]}... ({len(data)} bytes)"
                            ),
                            stage="Concolic",
                        ))
                    except OSError:
                        pass

    return findings


# ── Tier 3: Heuristic seed mutation ──────────────────────────────────────────
# Identify C-level functions that take user input and generate boundary-value
# seeds to run the binary with (if compilable) and check for crashes.
_SINK_PATTERN = re.compile(
    r"\b(?:strcpy|strcat|gets|sprintf|memcpy|scanf|recv|fgets)\s*\(",
    re.MULTILINE,
)
_BOUNDARY_SEEDS: List[bytes] = [
    b"A" * 64,
    b"A" * 128,
    b"A" * 256,
    b"A" * 512,
    b"A" * 1024,
    b"\xff" * 64,
    b"\x00" * 64,
    b"%s%s%s%s%s%s%s",
    b"%n%n%n%n",
    b"../../etc/passwd\x00",
    struct.pack("<I", 0xFFFFFFFF) * 16,
    struct.pack("<I", 0x80000000) * 16,
    b"-1\x00",
    b"99999999999999999999\x00",
]


def _compile_target(source_path: str, output_path: str) -> bool:
    """Compile source to a binary with ASAN.  Returns True on success."""
    ext    = os.path.splitext(source_path)[1].lower()
    cc     = "g++" if ext in (".cpp", ".cc", ".cxx") else "gcc"
    result = subprocess.run(
        [cc, "-g", "-fsanitize=address,undefined",
         "-fno-omit-frame-pointer",
         source_path, "-o", output_path],
        capture_output=True, text=True, timeout=30,
    )
    return result.returncode == 0


def _run_with_seed(binary: str, seed: bytes, timeout: float = 2.0) -> Optional[str]:
    """
    Run *binary* with *seed* on stdin.
    Returns stderr output if the process crashes (non-zero exit or signal), else None.
    """
    try:
        result = subprocess.run(
            [binary],
            input=seed,
            capture_output=True,
            timeout=timeout,
        )
        if result.returncode != 0 or b"AddressSanitizer" in result.stderr:
            # Detect ASAN/UBSAN reports
            stderr_text = result.stderr.decode("utf-8", errors="replace")
            if any(kw in stderr_text for kw in
                   ("overflow", "heap-buffer-overflow", "stack-buffer-overflow",
                    "SEGV", "undefined", "double-free", "use-after-free")):
                return stderr_text[:500]
    except subprocess.TimeoutExpired:
        pass
    except FileNotFoundError:
        pass
    return None


def _heuristic_fuzz(source_path: str) -> List[ConcolicFinding]:
    """
    Tier 3: compile the file and run it with ASAN + boundary-value seeds.
    Only sinks we can identify in the source are targeted.
    """
    findings: List[ConcolicFinding] = []
    src = _read(source_path)
    if not _SINK_PATTERN.search(src):
        return []  # no obvious unsafe sinks

    src_lines = src.splitlines()
    seen: Set[Tuple[str, int]] = set()

    # Find source-level unsafe sinks with their line numbers for reporting
    sinks: List[Tuple[str, int]] = []
    for m in _SINK_PATTERN.finditer(src):
        ln   = _lineno(src, m.start())
        name = m.group(0).split("(")[0].strip()
        sinks.append((name, ln))

    with tempfile.TemporaryDirectory(prefix="og_hfuzz_") as tmpdir:
        binary = os.path.join(tmpdir, "target")
        if not _compile_target(source_path, binary):
            return []  # compilation failed (missing main, etc.)

        for seed in _BOUNDARY_SEEDS:
            crash_report = _run_with_seed(binary, seed)
            if crash_report:
                issue = "heap-buffer-overflow"
                if "stack" in crash_report:
                    issue = "stack-buffer-overflow"
                elif "undefined" in crash_report:
                    issue = "undefined-behavior"
                elif "double-free" in crash_report:
                    issue = "double-free"
                elif "use-after-free" in crash_report:
                    issue = "use-after-free"

                # Report all first-matching sinks
                for sink_name, sink_ln in sinks[:3]:
                    key = (issue, sink_ln)
                    if key not in seen:
                        seen.add(key)
                        findings.append(ConcolicFinding(
                            issue_type=issue,
                            line=sink_ln,
                            snippet=_snip(src_lines, sink_ln),
                            confidence="HIGH",
                            trigger_input=seed.hex()[:64],
                            note=(
                                f"Heuristic fuzzing: seed 0x{seed.hex()[:32]}... "
                                f"causes crash at/near {sink_name}() — ASAN report: "
                                f"{crash_report[:200]}"
                            ),
                            stage="Concolic",
                        ))

    return findings


# ── Public API ────────────────────────────────────────────────────────────────
C_EXTENSIONS = {".c", ".cpp", ".cc", ".cxx"}


class ConcolicFuzzer:
    """
    Concolic/hybrid fuzzing engine — three tiers:
      Tier 1: angr symbolic execution (if installed)
      Tier 2: AFL++ coverage-guided fuzzing (if installed)
      Tier 3: heuristic boundary-value mutation (always available)
    """

    def __init__(self, afl_timeout: int = 20):
        self._afl_timeout = afl_timeout

    @staticmethod
    def is_angr_available() -> bool:
        return _HAS_ANGR

    @staticmethod
    def is_afl_available() -> bool:
        return bool(shutil.which("afl-fuzz"))

    def fuzz(self, file_path: str) -> List[ConcolicFinding]:
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in C_EXTENSIONS:
            return []

        findings: List[ConcolicFinding] = []

        # ── Tier 1: angr ──────────────────────────────────────────────────────
        if _HAS_ANGR:
            with tempfile.TemporaryDirectory(prefix="og_angr_") as tmpdir:
                binary = os.path.join(tmpdir, "angr_target")
                if _compile_target(file_path, binary):
                    findings.extend(_fuzz_with_angr(binary))

        # ── Tier 2: AFL++ ─────────────────────────────────────────────────────
        if self.is_afl_available() and not findings:
            findings.extend(_fuzz_with_afl(file_path, self._afl_timeout))

        # ── Tier 3: Heuristic ─────────────────────────────────────────────────
        # Always run tier 3 so we have concrete crash evidence when available
        h_findings = _heuristic_fuzz(file_path)
        existing_lines = {f.line for f in findings}
        for f in h_findings:
            if f.line not in existing_lines:
                findings.append(f)

        return findings
