"""incremental_analysis.py – Incremental Cross-File Analysis

Only re-analyses files that changed (via git diff) plus their dependency cone –
files that import/include the changed files. This dramatically speeds up
repeat scans in CI and developer workflows.

Usage:
    from incremental_analysis import IncrementalAnalyzer
    analyzer = IncrementalAnalyzer(repo_path)
    result = analyzer.run()
    # result.changed_files  — directly modified files
    # result.affected_files — upstream/downstream dependents
    # result.all_scan_files — union ready for scanning
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from collections import defaultdict

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class IncrementalResult:
    """Result of incremental dependency-cone analysis."""
    changed_files: List[str]          # files directly modified in the diff
    affected_files: List[str]         # files that depend on changed files
    all_scan_files: List[str]         # union (changed + affected)
    dep_graph_edges: int              # number of dependency edges found
    skipped_files: int                # unchanged files not in the cone

    @property
    def savings_pct(self) -> float:
        total = len(self.all_scan_files) + self.skipped_files
        if total == 0:
            return 0.0
        return (self.skipped_files / total) * 100.0


# ---------------------------------------------------------------------------
# Import/include extractors  (lightweight versions for dependency mapping)
# ---------------------------------------------------------------------------

_INCLUDE_RE_C = re.compile(r'#\s*include\s*[<"]([^>"]+)[>"]')
_IMPORT_RE_PY = re.compile(r'(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))')
_IMPORT_RE_JAVA = re.compile(r'import\s+(?:static\s+)?([\w.]+);')
_IMPORT_RE_GO = re.compile(r'"([^"]+)"')
_IMPORT_RE_JS = re.compile(r'''(?:import\s.*?from\s+['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\))''')
_IMPORT_RE_RUST = re.compile(r'(?:use\s+([\w:]+)|mod\s+(\w+))')


def _extract_deps(file_path: str, content: str) -> Set[str]:
    """Extract dependency names/paths from a source file (lightweight)."""
    ext = os.path.splitext(file_path)[1].lower()
    deps: Set[str] = set()

    if ext in (".c", ".cpp", ".cc", ".h", ".hpp", ".cxx"):
        for m in _INCLUDE_RE_C.finditer(content):
            deps.add(m.group(1))
    elif ext == ".py":
        for m in _IMPORT_RE_PY.finditer(content):
            mod = m.group(1) or m.group(2)
            if mod:
                deps.add(mod.replace(".", "/"))
    elif ext == ".java":
        for m in _IMPORT_RE_JAVA.finditer(content):
            deps.add(m.group(1).replace(".", "/"))
    elif ext == ".go":
        for m in _IMPORT_RE_GO.finditer(content):
            deps.add(m.group(1))
    elif ext in (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"):
        for m in _IMPORT_RE_JS.finditer(content):
            dep = m.group(1) or m.group(2)
            if dep:
                deps.add(dep)
    elif ext == ".rs":
        for m in _IMPORT_RE_RUST.finditer(content):
            dep = m.group(1) or m.group(2)
            if dep:
                deps.add(dep)

    return deps


def _resolve_dep_to_file(dep: str, all_files: Dict[str, str], src_dir: str) -> Optional[str]:
    """Try to resolve a dependency reference to an actual file in the project."""
    # Normalise
    dep_clean = dep.strip().rstrip(";")

    # Strategy 1: direct basename match
    dep_base = os.path.basename(dep_clean)
    for fpath, fname_lower in all_files.items():
        if fname_lower == dep_base.lower():
            return fpath
        # without extension
        no_ext = os.path.splitext(fname_lower)[0]
        if no_ext == dep_base.lower() or no_ext == dep_clean.lower().replace("/", "."):
            return fpath

    # Strategy 2: path suffix match
    # e.g. dep = "utils/helpers" matches "/project/src/utils/helpers.py"
    dep_norm = dep_clean.replace(".", "/").replace("::", "/").lower()
    for fpath in all_files:
        fpath_norm = fpath.lower().replace("\\", "/")
        no_ext = os.path.splitext(fpath_norm)[0]
        if no_ext.endswith(dep_norm):
            return fpath

    return None


# ---------------------------------------------------------------------------
# Git integration
# ---------------------------------------------------------------------------

def _git_changed_files(repo_path: str, base: str = "HEAD~1") -> List[str]:
    """Get list of changed files via git diff."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMRT", base],
            cwd=repo_path,
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            # Try against default branch
            for branch in ("main", "master"):
                result = subprocess.run(
                    ["git", "diff", "--name-only", "--diff-filter=ACMRT", branch],
                    cwd=repo_path,
                    capture_output=True, text=True, timeout=30,
                )
                if result.returncode == 0:
                    break
        if result.returncode != 0:
            return []

        files = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if line:
                full = os.path.join(repo_path, line)
                if os.path.isfile(full):
                    files.append(full)
        return files
    except (subprocess.SubprocessError, OSError):
        return []


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

SCAN_EXTS = {
    ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp",
    ".py", ".java", ".go", ".rs",
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".rb", ".php", ".scala", ".kt",
}


class IncrementalAnalyzer:
    """Incremental cross-file analysis: only scan changed files + dependency cone."""

    def __init__(self, repo_path: str, base_ref: str = "HEAD~1"):
        self.repo_path = os.path.abspath(repo_path)
        self.base_ref = base_ref
        # dep_graph: file → set of files it imports
        self._dep_graph: Dict[str, Set[str]] = defaultdict(set)
        # reverse_dep: file → set of files that import it
        self._reverse_dep: Dict[str, Set[str]] = defaultdict(set)
        self._all_project_files: Dict[str, str] = {}  # abs_path → basename.lower()

    def _collect_project_files(self) -> List[str]:
        """Walk project and collect all source files."""
        SKIP = {".git", ".hg", "node_modules", "__pycache__", ".venv", "venv",
                "target", "build", "dist", ".tox"}
        result = []
        for dirpath, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in SKIP]
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in SCAN_EXTS:
                    full = os.path.join(dirpath, f)
                    result.append(full)
                    self._all_project_files[full] = f.lower()
        return result

    def _build_dep_graph(self, file_paths: List[str]) -> None:
        """Build forward and reverse dependency graphs."""
        for fpath in file_paths:
            try:
                with open(fpath, "r", errors="ignore") as fh:
                    content = fh.read(65536)  # cap at 64KB for speed
            except (OSError, IOError):
                continue

            src_dir = os.path.dirname(fpath)
            deps = _extract_deps(fpath, content)
            for dep in deps:
                resolved = _resolve_dep_to_file(dep, self._all_project_files, src_dir)
                if resolved and resolved != fpath:
                    self._dep_graph[fpath].add(resolved)
                    self._reverse_dep[resolved].add(fpath)

    def _get_dependency_cone(self, changed: Set[str]) -> Set[str]:
        """BFS from changed files through reverse dependencies to find the full impact cone."""
        affected: Set[str] = set()
        queue = list(changed)
        visited: Set[str] = set(changed)

        while queue:
            current = queue.pop(0)
            # Files that import 'current' are affected
            for dep in self._reverse_dep.get(current, set()):
                if dep not in visited:
                    visited.add(dep)
                    affected.add(dep)
                    queue.append(dep)

        return affected

    def run(self, changed_files: Optional[List[str]] = None) -> IncrementalResult:
        """Execute incremental analysis.

        Args:
            changed_files: Explicit list of changed files. If None, uses git diff.

        Returns:
            IncrementalResult with changed, affected, and all files to scan.
        """
        # Phase 1: Collect all project files
        all_files = self._collect_project_files()

        # Phase 2: Build dependency graph
        self._build_dep_graph(all_files)

        # Phase 3: Determine changed files
        if changed_files is None:
            changed_files = _git_changed_files(self.repo_path, self.base_ref)

        # Filter to only source files
        changed_set = {f for f in changed_files
                       if os.path.splitext(f)[1].lower() in SCAN_EXTS}

        # Phase 4: Compute dependency cone
        affected = self._get_dependency_cone(changed_set)

        # Phase 5: Build result
        all_scan = sorted(changed_set | affected)
        skipped = len(all_files) - len(all_scan)

        edge_count = sum(len(v) for v in self._dep_graph.values())

        return IncrementalResult(
            changed_files=sorted(changed_set),
            affected_files=sorted(affected),
            all_scan_files=all_scan,
            dep_graph_edges=edge_count,
            skipped_files=max(0, skipped),
        )

    def summary(self, result: IncrementalResult) -> str:
        """Format a CLI summary of incremental analysis."""
        lines = [
            f"Incremental Analysis:",
            f"  Changed files:  {len(result.changed_files)}",
            f"  Affected files: {len(result.affected_files)} (dependency cone)",
            f"  Total to scan:  {len(result.all_scan_files)}",
            f"  Skipped:        {result.skipped_files} unchanged files",
            f"  Savings:        {result.savings_pct:.0f}% fewer files to scan",
            f"  Dep graph:      {result.dep_graph_edges} edges",
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Convenience entry-point
# ---------------------------------------------------------------------------

def run_incremental_analysis(repo_path: str, base_ref: str = "HEAD~1",
                              changed_files: Optional[List[str]] = None,
                              verbose: bool = False) -> IncrementalResult:
    """High-level entry point for incremental analysis."""
    analyzer = IncrementalAnalyzer(repo_path, base_ref=base_ref)
    result = analyzer.run(changed_files=changed_files)
    if verbose:
        print(analyzer.summary(result))
    return result


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    base = sys.argv[2] if len(sys.argv) > 2 else "HEAD~1"
    analyzer = IncrementalAnalyzer(target, base_ref=base)
    result = analyzer.run()
    print(analyzer.summary(result))
    if result.changed_files:
        print("\n  Changed:")
        for f in result.changed_files:
            print(f"    {f}")
    if result.affected_files:
        print("\n  Affected (dependency cone):")
        for f in result.affected_files:
            print(f"    {f}")
