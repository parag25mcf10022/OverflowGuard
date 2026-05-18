"""
trend_tracker.py — Severity trend tracking for OverflowGuard v11.0

SQLite-backed historical scan results. Stores per-scan totals and enables
"findings over time" comparisons, quality-gate enforcement, and regression
detection.

Copyright 2026 Parag Bagade — MIT Licence
"""

from __future__ import annotations
import os
import json
import sqlite3
import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ScanRecord:
    """A single historical scan entry."""
    scan_id: str
    timestamp: str
    project: str
    target: str
    version: str
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    files_scanned: int
    sca_vulns: int = 0
    secrets: int = 0
    iac_issues: int = 0
    duration_sec: float = 0.0
    git_commit: str = ""
    git_branch: str = ""


@dataclass
class TrendReport:
    """Comparison between two scans."""
    current: ScanRecord
    previous: Optional[ScanRecord]
    new_findings: int = 0
    fixed_findings: int = 0
    delta_critical: int = 0
    delta_high: int = 0
    delta_medium: int = 0
    delta_low: int = 0
    trend: str = "stable"        # improving | stable | degrading
    quality_gate: str = "pass"   # pass | fail
    gate_reason: str = ""        # human-readable explanation of gate failure


# ---------------------------------------------------------------------------
# Trend tracker engine
# ---------------------------------------------------------------------------

_DB_PATH = os.path.join(os.path.expanduser("~"), ".overflowguard", "trends.db")


class TrendTracker:
    """SQLite-backed historical scan tracker."""

    def __init__(self, db_path: str = _DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id      TEXT PRIMARY KEY,
                    timestamp    TEXT NOT NULL,
                    project      TEXT NOT NULL,
                    target       TEXT NOT NULL,
                    version      TEXT NOT NULL,
                    total        INTEGER NOT NULL DEFAULT 0,
                    critical     INTEGER NOT NULL DEFAULT 0,
                    high         INTEGER NOT NULL DEFAULT 0,
                    medium       INTEGER NOT NULL DEFAULT 0,
                    low          INTEGER NOT NULL DEFAULT 0,
                    info         INTEGER NOT NULL DEFAULT 0,
                    files        INTEGER NOT NULL DEFAULT 0,
                    sca          INTEGER NOT NULL DEFAULT 0,
                    secrets      INTEGER NOT NULL DEFAULT 0,
                    iac          INTEGER NOT NULL DEFAULT 0,
                    duration     REAL NOT NULL DEFAULT 0.0,
                    git_commit   TEXT NOT NULL DEFAULT '',
                    git_branch   TEXT NOT NULL DEFAULT '',
                    findings_json TEXT NOT NULL DEFAULT '[]'
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_project
                ON scans(project, timestamp DESC)
            """)

    # ── Record a scan ─────────────────────────────────────────────────────

    def record_scan(
        self,
        project: str,
        target: str,
        stats: Dict,
        findings_summary: List[Dict] = None,
        version: str = "v11.0",
        duration_sec: float = 0.0,
        sca_count: int = 0,
        secrets_count: int = 0,
        iac_count: int = 0,
    ) -> ScanRecord:
        """Record a completed scan and return the ScanRecord."""
        import uuid
        scan_id = str(uuid.uuid4())[:12]
        now = datetime.datetime.now().isoformat()

        # Try to get git info
        git_commit, git_branch = self._get_git_info()

        record = ScanRecord(
            scan_id=scan_id,
            timestamp=now,
            project=project,
            target=target,
            version=version,
            total_findings=sum(stats.get(s, 0) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")),
            critical=stats.get("CRITICAL", 0),
            high=stats.get("HIGH", 0),
            medium=stats.get("MEDIUM", 0),
            low=stats.get("LOW", 0),
            info=stats.get("INFO", 0),
            files_scanned=stats.get("scanned", 0),
            sca_vulns=sca_count,
            secrets=secrets_count,
            iac_issues=iac_count,
            duration_sec=duration_sec,
            git_commit=git_commit,
            git_branch=git_branch,
        )

        findings_json = json.dumps(findings_summary or [])

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO scans (scan_id, timestamp, project, target, version,
                                   total, critical, high, medium, low, info,
                                   files, sca, secrets, iac, duration,
                                   git_commit, git_branch, findings_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.scan_id, record.timestamp, record.project, record.target,
                record.version, record.total_findings,
                record.critical, record.high, record.medium, record.low, record.info,
                record.files_scanned, record.sca_vulns, record.secrets, record.iac_issues,
                record.duration_sec, record.git_commit, record.git_branch,
                findings_json,
            ))

        return record

    # ── Query history ─────────────────────────────────────────────────────

    def get_history(self, project: str, limit: int = 20) -> List[ScanRecord]:
        """Get the last N scans for a project, newest first."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("""
                SELECT scan_id, timestamp, project, target, version,
                       total, critical, high, medium, low, info,
                       files, sca, secrets, iac, duration,
                       git_commit, git_branch
                FROM scans
                WHERE project = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (project, limit)).fetchall()

        return [ScanRecord(
            scan_id=r[0], timestamp=r[1], project=r[2], target=r[3],
            version=r[4], total_findings=r[5],
            critical=r[6], high=r[7], medium=r[8], low=r[9], info=r[10],
            files_scanned=r[11], sca_vulns=r[12], secrets=r[13],
            iac_issues=r[14], duration_sec=r[15],
            git_commit=r[16], git_branch=r[17],
        ) for r in rows]

    def get_previous_scan(self, project: str) -> Optional[ScanRecord]:
        """Get the most recent previous scan for comparison."""
        history = self.get_history(project, limit=2)
        return history[1] if len(history) >= 2 else (history[0] if history else None)

    # ── Trend analysis ────────────────────────────────────────────────────

    def compare(
        self,
        current: ScanRecord,
        previous: Optional[ScanRecord] = None,
        max_critical: Optional[int] = None,
        max_high: Optional[int] = None,
    ) -> TrendReport:
        """Compare current scan with previous and produce a trend report.

        max_critical / max_high: absolute upper bounds; quality gate fails if
        the current scan's count exceeds either, regardless of delta.
        """
        if previous is None:
            previous = self.get_previous_scan(current.project)

        if previous is None:
            gate_reason = ""
            gate = "pass"
            if max_critical is not None and current.critical > max_critical:
                gate = "fail"
                gate_reason = f"CRITICAL count {current.critical} exceeds --max-critical {max_critical}"
            if max_high is not None and current.high > max_high:
                gate = "fail"
                gate_reason += ("; " if gate_reason else "") + f"HIGH count {current.high} exceeds --max-high {max_high}"
            return TrendReport(
                current=current,
                previous=None,
                trend="baseline",
                quality_gate=gate,
                gate_reason=gate_reason,
            )

        delta_total = current.total_findings - previous.total_findings
        delta_crit = current.critical - previous.critical
        delta_high = current.high - previous.high
        delta_med = current.medium - previous.medium
        delta_low = current.low - previous.low

        # Determine trend
        if delta_crit > 0 or delta_high > 0:
            trend = "degrading"
        elif delta_total < 0:
            trend = "improving"
        elif delta_total == 0:
            trend = "stable"
        else:
            trend = "degrading" if delta_total > 0 else "stable"

        # Quality gate: delta-based (new CRITICAL/HIGH) + optional absolute thresholds
        gate = "pass"
        gate_reason = ""
        if delta_crit > 0:
            gate = "fail"
            gate_reason = f"+{delta_crit} new CRITICAL finding(s)"
        if delta_high > 0:
            gate = "fail"
            gate_reason += ("; " if gate_reason else "") + f"+{delta_high} new HIGH finding(s)"
        if max_critical is not None and current.critical > max_critical:
            gate = "fail"
            gate_reason += ("; " if gate_reason else "") + f"CRITICAL count {current.critical} exceeds --max-critical {max_critical}"
        if max_high is not None and current.high > max_high:
            gate = "fail"
            gate_reason += ("; " if gate_reason else "") + f"HIGH count {current.high} exceeds --max-high {max_high}"

        return TrendReport(
            current=current,
            previous=previous,
            new_findings=max(0, delta_total),
            fixed_findings=max(0, -delta_total),
            delta_critical=delta_crit,
            delta_high=delta_high,
            delta_medium=delta_med,
            delta_low=delta_low,
            trend=trend,
            quality_gate=gate,
            gate_reason=gate_reason,
        )

    # ── Formatting ────────────────────────────────────────────────────────

    def format_trend_cli(self, report: TrendReport) -> str:
        """Format trend report for CLI display."""
        lines = []
        lines.append(f"  Trend: {report.trend.upper()}")

        if report.previous:
            prev = report.previous
            def _delta(val):
                if val > 0: return f"+{val}"
                elif val < 0: return f"{val}"
                return "0"

            lines.append(f"  vs. previous scan ({prev.timestamp[:10]}, commit {prev.git_commit[:8] or 'N/A'}):")
            lines.append(f"    Findings: {report.current.total_findings} (was {prev.total_findings}, delta: {_delta(report.current.total_findings - prev.total_findings)})")
            lines.append(f"    CRITICAL: {report.current.critical} ({_delta(report.delta_critical)})  "
                         f"HIGH: {report.current.high} ({_delta(report.delta_high)})  "
                         f"MEDIUM: {report.current.medium} ({_delta(report.delta_medium)})  "
                         f"LOW: {report.current.low} ({_delta(report.delta_low)})")
            if report.new_findings > 0:
                lines.append(f"    New findings: {report.new_findings}")
            if report.fixed_findings > 0:
                lines.append(f"    Fixed findings: {report.fixed_findings}")
        else:
            lines.append(f"  (First scan recorded — no previous data to compare)")

        gate_str = report.quality_gate.upper()
        if report.quality_gate == "fail" and report.gate_reason:
            gate_str += f" ({report.gate_reason})"
        lines.append(f"  Quality gate: {gate_str}")
        return "\n".join(lines)

    def get_trend_data_for_json(self, project: str, limit: int = 10) -> Dict:
        """Get trend data suitable for JSON output."""
        history = self.get_history(project, limit=limit)
        return {
            "project": project,
            "scan_count": len(history),
            "scans": [
                {
                    "scan_id": r.scan_id,
                    "timestamp": r.timestamp,
                    "total": r.total_findings,
                    "critical": r.critical,
                    "high": r.high,
                    "medium": r.medium,
                    "low": r.low,
                    "files": r.files_scanned,
                    "git_commit": r.git_commit,
                    "git_branch": r.git_branch,
                }
                for r in history
            ],
        }

    # ── Helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _get_git_info() -> Tuple[str, str]:
        """Try to get current git commit and branch."""
        import subprocess
        commit = ""
        branch = ""
        try:
            commit = subprocess.check_output(
                ["git", "rev-parse", "HEAD"],
                stderr=subprocess.DEVNULL, timeout=5
            ).decode().strip()[:12]
        except Exception:
            pass
        try:
            branch = subprocess.check_output(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                stderr=subprocess.DEVNULL, timeout=5
            ).decode().strip()
        except Exception:
            pass
        return commit, branch

    def purge_old(self, project: str, keep: int = 100) -> int:
        """Delete scans older than the most recent *keep* entries."""
        with sqlite3.connect(self.db_path) as conn:
            result = conn.execute("""
                DELETE FROM scans
                WHERE project = ? AND scan_id NOT IN (
                    SELECT scan_id FROM scans
                    WHERE project = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                )
            """, (project, project, keep))
            return result.rowcount
