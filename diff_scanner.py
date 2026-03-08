"""
diff_scanner.py — Git‑aware differential scanning for OverflowGuard v10.0

Instead of rescanning every file in a repository, this module uses
``git diff`` to discover only the files that have actually changed and
limits scanning to those.  This drastically reduces scan time for large
repos where only a few files have been modified.

Modes of operation
------------------
1. **Staged changes** (default) — files in the git index (``git diff --cached``)
2. **Working-tree changes** — uncommitted modifications (``git diff``)
3. **Between commits** — diff between two arbitrary commits / branches
4. **Since last tag** — diff since the most recent annotated tag

Exported API
------------
    DiffScanner        — main class
    DiffResult         — dataclass with changed file info
    get_changed_files  — convenience function
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class DiffMode(Enum):
    """Which ``git diff`` variant to use."""
    STAGED   = "staged"      # git diff --cached (HEAD vs index)
    WORKING  = "working"     # git diff (index vs working tree)
    HEAD     = "head"        # git diff HEAD (HEAD vs working tree)
    COMMITS  = "commits"     # git diff <base>..<target>
    LAST_TAG = "last_tag"    # git diff <latest-tag>..HEAD


@dataclass
class DiffResult:
    """Information about a single changed file."""
    file_path: str              # absolute path to the changed file
    relative_path: str          # path relative to the repo root
    status: str                 # A(dded) | M(odified) | D(eleted) | R(enamed) | C(opied)
    additions: int = 0          # number of added lines
    deletions: int = 0          # number of deleted lines
    changed_lines: List[int] = field(default_factory=list)  # 1-based line numbers that changed
    old_path: Optional[str] = None   # for renames: original path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_git(args: List[str], cwd: str) -> Tuple[int, str, str]:
    """Run a git command and return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            ["git"] + args,
            capture_output=True,
            text=True,
            cwd=cwd,
            timeout=30,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return -1, "", "git not found on PATH"
    except subprocess.TimeoutExpired:
        return -2, "", "git command timed out"


def _find_repo_root(path: str) -> Optional[str]:
    """Find the git repository root for *path*."""
    rc, out, _ = _run_git(["rev-parse", "--show-toplevel"], cwd=path if os.path.isdir(path) else os.path.dirname(path))
    if rc == 0:
        return out.strip()
    return None


def _get_latest_tag(cwd: str) -> Optional[str]:
    """Return the most recent annotated tag reachable from HEAD."""
    rc, out, _ = _run_git(["describe", "--tags", "--abbrev=0"], cwd=cwd)
    if rc == 0:
        return out.strip()
    return None


def _parse_numstat(line: str) -> Tuple[int, int, str]:
    """Parse a ``git diff --numstat`` line → (additions, deletions, path)."""
    parts = line.split("\t", 2)
    if len(parts) < 3:
        return 0, 0, line.strip()
    adds = int(parts[0]) if parts[0] != "-" else 0
    dels = int(parts[1]) if parts[1] != "-" else 0
    return adds, dels, parts[2].strip()


def _parse_changed_lines(diff_output: str, file_path: str) -> List[int]:
    """
    Extract the 1-based line numbers that were added/modified in the new
    version of *file_path* from unified-diff output.
    """
    changed: List[int] = []
    in_file = False
    current_line = 0

    for raw_line in diff_output.splitlines():
        # Detect the start of a diff section for this file
        if raw_line.startswith("+++ b/"):
            in_file = raw_line[6:].strip() == file_path
            continue
        if raw_line.startswith("--- "):
            continue
        if not in_file:
            continue
        if raw_line.startswith("@@"):
            # Parse hunk header: @@ -old_start,old_count +new_start,new_count @@
            import re
            m = re.search(r"\+(\d+)(?:,\d+)?", raw_line)
            if m:
                current_line = int(m.group(1))
            continue
        if raw_line.startswith("+"):
            changed.append(current_line)
            current_line += 1
        elif raw_line.startswith("-"):
            pass  # deleted line — don't increment new-file counter
        else:
            current_line += 1

    return changed


# ---------------------------------------------------------------------------
# Scannable-file filter (mirrors main.py's _SCAN_EXTS)
# ---------------------------------------------------------------------------

_SCAN_EXTS: Set[str] = {
    ".c", ".cpp", ".cc", ".py", ".go", ".rs", ".java",
    ".js", ".mjs", ".cjs", ".jsx",
    ".ts", ".tsx",
    ".php", ".rb", ".cs",
    ".kt", ".kts",
    ".swift",
    ".scala", ".sc",
}


def _is_scannable(path: str) -> bool:
    """Return True if *path* has an extension we know how to scan."""
    _, ext = os.path.splitext(path)
    return ext.lower() in _SCAN_EXTS


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class DiffScanner:
    """
    Discover changed files via ``git diff`` and return only those that should
    be scanned.

    Usage::

        scanner = DiffScanner("/path/to/repo")
        results = scanner.get_changed_files(mode=DiffMode.HEAD)
        for r in results:
            analyze_file(r.file_path, audit_obj)
    """

    def __init__(self, repo_path: str):
        self.repo_path = os.path.abspath(repo_path)
        self.repo_root = _find_repo_root(self.repo_path)
        if self.repo_root is None:
            raise RuntimeError(
                f"'{self.repo_path}' is not inside a git repository. "
                "Differential scanning requires git."
            )

    # ====== public API ====================================================

    def get_changed_files(
        self,
        mode: DiffMode = DiffMode.HEAD,
        base: Optional[str] = None,
        target: Optional[str] = None,
        include_deleted: bool = False,
    ) -> List[DiffResult]:
        """
        Return a list of :class:`DiffResult` for files changed according to
        *mode*.

        Parameters
        ----------
        mode : DiffMode
            Which diff strategy to use.
        base, target : str, optional
            Required when *mode* is ``COMMITS``.  ``base`` and ``target``
            can be commit SHAs, branch names, or tag names.
        include_deleted : bool
            If True, include files with status ``D`` (deleted).
        """
        diff_args = self._build_diff_args(mode, base, target)

        # 1. Get name-status list
        rc, out, err = _run_git(diff_args + ["--name-status"], cwd=self.repo_root)
        if rc != 0:
            raise RuntimeError(f"git diff failed: {err.strip()}")

        # 2. Get numstat for additions / deletions
        rc2, numstat_out, _ = _run_git(diff_args + ["--numstat"], cwd=self.repo_root)
        numstat_map: Dict[str, Tuple[int, int]] = {}
        if rc2 == 0:
            for line in numstat_out.strip().splitlines():
                if not line.strip():
                    continue
                adds, dels, path = _parse_numstat(line)
                numstat_map[path] = (adds, dels)

        # 3. Get full unified diff for changed-line extraction
        rc3, full_diff, _ = _run_git(diff_args + ["-U0"], cwd=self.repo_root)

        # 4. Build results
        results: List[DiffResult] = []
        for line in out.strip().splitlines():
            if not line.strip():
                continue
            parts = line.split("\t")
            status = parts[0][0]  # first char: A, M, D, R, C
            rel_path = parts[-1]
            old_path = parts[1] if len(parts) > 2 else None

            if status == "D" and not include_deleted:
                continue

            if not _is_scannable(rel_path):
                continue

            abs_path = os.path.join(self.repo_root, rel_path)
            if not os.path.isfile(abs_path) and status != "D":
                continue

            adds, dels = numstat_map.get(rel_path, (0, 0))
            changed_lines = _parse_changed_lines(full_diff, rel_path) if rc3 == 0 else []

            results.append(DiffResult(
                file_path=abs_path,
                relative_path=rel_path,
                status=status,
                additions=adds,
                deletions=dels,
                changed_lines=changed_lines,
                old_path=old_path,
            ))

        return results

    def summary(self, results: List[DiffResult]) -> str:
        """Return a human-readable summary of the diff results."""
        if not results:
            return "No scannable files changed."
        lines = [f"Differential scan: {len(results)} changed file(s)"]
        for r in results:
            status_label = {
                "A": "Added",
                "M": "Modified",
                "D": "Deleted",
                "R": "Renamed",
                "C": "Copied",
            }.get(r.status, r.status)
            lines.append(
                f"  [{status_label:>8}]  {r.relative_path}  "
                f"(+{r.additions}/-{r.deletions}, "
                f"{len(r.changed_lines)} changed lines)"
            )
        return "\n".join(lines)

    # ====== internals =====================================================

    def _build_diff_args(
        self,
        mode: DiffMode,
        base: Optional[str],
        target: Optional[str],
    ) -> List[str]:
        """Build the ``git diff`` argument list for the given mode."""
        if mode == DiffMode.STAGED:
            return ["diff", "--cached"]
        elif mode == DiffMode.WORKING:
            return ["diff"]
        elif mode == DiffMode.HEAD:
            return ["diff", "HEAD"]
        elif mode == DiffMode.COMMITS:
            if not base:
                raise ValueError("DiffMode.COMMITS requires 'base' parameter")
            tgt = target or "HEAD"
            return ["diff", f"{base}..{tgt}"]
        elif mode == DiffMode.LAST_TAG:
            tag = _get_latest_tag(self.repo_root)
            if tag is None:
                # Fallback: diff against the initial commit
                rc, out, _ = _run_git(
                    ["rev-list", "--max-parents=0", "HEAD"],
                    cwd=self.repo_root,
                )
                if rc != 0 or not out.strip():
                    raise RuntimeError("No tags or commits found for LAST_TAG mode")
                initial = out.strip().splitlines()[0]
                return ["diff", f"{initial}..HEAD"]
            return ["diff", f"{tag}..HEAD"]
        else:
            raise ValueError(f"Unknown DiffMode: {mode}")


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def get_changed_files(
    repo_path: str,
    mode: str = "head",
    base: Optional[str] = None,
    target: Optional[str] = None,
) -> List[DiffResult]:
    """
    Convenience wrapper: return changed scannable files.

    Parameters
    ----------
    repo_path : str
        Path to the repository (or a file inside it).
    mode : str
        One of "staged", "working", "head", "commits", "last_tag".
    base, target : str, optional
        For "commits" mode only.

    Returns
    -------
    list of DiffResult
    """
    mode_enum = DiffMode(mode.lower())
    scanner = DiffScanner(repo_path)
    return scanner.get_changed_files(mode=mode_enum, base=base, target=target)
