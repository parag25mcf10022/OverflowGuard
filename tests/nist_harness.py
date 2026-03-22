"""NIST SARD precision/recall harness.

Runs OverflowGuard on each sample suite under nist-samples/*, compares the
produced SARIF with the suite's manifest.sarif ground truth, and prints
precision/recall/F1.

Assumptions:
- Each suite directory contains a manifest.sarif with expected findings.
- Running `python main.py <suite_dir> --format sarif --no-owasp` produces a
  SARIF file in results/ named after the suite directory.

This harness is lightweight and uses only the standard library.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
NIST_ROOT = ROOT / "samples"
RESULTS_DIR = ROOT / "results"


@dataclass(frozen=True)
class Finding:
    """Simplified finding for set-based comparison."""

    cwe: str
    file: str  # relative file path
    line: int


@dataclass
class Metrics:
    tp: int
    fp: int
    fn: int

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return (self.tp / denom) if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return (self.tp / denom) if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r / (p + r)) if (p + r) else 0.0


def _load_sarif_findings(path: Path) -> Set[Finding]:
    """Parse SARIF file into a set of (cwe, file, line)."""

    if not path.exists() or path.stat().st_size == 0:
        return set()
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return set()
    results = data.get("runs", [{}])[0].get("results", [])
    findings: Set[Finding] = set()
    for res in results:
        props = res.get("properties", {})
        cwe = props.get("cwe", "") or props.get("tags", [""])[0]
        cwe_norm = _normalize_cwe(cwe)
        locations = res.get("locations", [])
        if not locations:
            continue
        phys = locations[0].get("physicalLocation", {})
        artifact = phys.get("artifactLocation", {})
        rel_path = artifact.get("uri", "")
        line = phys.get("region", {}).get("startLine", 0) or 0
        findings.add(Finding(cwe=cwe_norm, file=rel_path, line=int(line)))
    return findings


def _normalize_cwe(value: str) -> str:
    if not value:
        return ""
    import re

    m = re.search(r"(\d+)", str(value))
    return f"CWE-{m.group(1)}" if m else ""


def _run_scan(suite_dir: Path) -> Path:
    """Run OverflowGuard on suite_dir and return expected SARIF path."""

    sarif_name = f"{suite_dir.name}.sarif"
    target_sarif = RESULTS_DIR / sarif_name

    cmd = [
        sys.executable,
        str(ROOT / "main.py"),
        str(suite_dir),
        "--format",
        "sarif",
        "--no-owasp",
    ]
    subprocess.run(cmd, check=True, cwd=ROOT)
    return target_sarif


def _compare(gt: Set[Finding], pred: Set[Finding]) -> Metrics:
    tp = len(gt & pred)
    fp = len(pred - gt)
    fn = len(gt - pred)
    return Metrics(tp=tp, fp=fp, fn=fn)


def evaluate_suite(suite_dir: Path) -> Tuple[Metrics, Set[Finding], Set[Finding]]:
    """Run scan on suite_dir and compare against manifest."""

    manifest = suite_dir / "manifest.sarif"
    gt = _load_sarif_findings(manifest)
    pred_path = _run_scan(suite_dir)
    pred = _load_sarif_findings(pred_path)
    metrics = _compare(gt, pred)
    return metrics, gt, pred


def main() -> int:
    suites = sorted(p for p in NIST_ROOT.iterdir() if (p / "manifest.sarif").exists())
    if not suites:
        print("No suites with manifest.sarif found under nist-samples/")
        return 1

    overall_tp = overall_fp = overall_fn = 0

    print("NIST SARD validation (precision/recall/F1)")
    print("Suite\tTP\tFP\tFN\tPrecision\tRecall\tF1")

    for suite in suites:
        metrics, _, _ = evaluate_suite(suite)
        overall_tp += metrics.tp
        overall_fp += metrics.fp
        overall_fn += metrics.fn
        print(
            f"{suite.name}\t{metrics.tp}\t{metrics.fp}\t{metrics.fn}\t"
            f"{metrics.precision:.2f}\t{metrics.recall:.2f}\t{metrics.f1:.2f}"
        )

    overall = Metrics(tp=overall_tp, fp=overall_fp, fn=overall_fn)
    print("-- Totals --")
    print(
        f"TP={overall.tp} FP={overall.fp} FN={overall.fn} "
        f"Precision={overall.precision:.2f} Recall={overall.recall:.2f} F1={overall.f1:.2f}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
