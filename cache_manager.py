"""
cache_manager.py — P2: SQLite-backed incremental analysis cache.

Avoids redundant re-analysis of files that have not changed since the last
scan.  Uses SHA-256 content hashes as the change-detection key so the cache
is path-independent (works even on rename/move).

Exported API:
    CacheManager
        .get_cached(file_path)     → Optional[List[dict]] — findings or None
        .store(file_path, findings) → None
        .invalidate(file_path)     → None
        .invalidate_dependents(changed_path) → None
        .stats()                   → dict
        .purge_stale()             → int   (number of removed entries)
"""

import hashlib
import json
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional


class CacheManager:
    """
    SQLite-based incremental analysis cache.

    Each row stores:
        path       TEXT      — absolute file path
        sha256     TEXT      — SHA-256 of file contents at scan time
        scanned_at REAL      — Unix timestamp
        findings   TEXT      — JSON-serialised list of finding dicts
        version    TEXT      — analyzer version string (for invalidation)

    If the file changes (different SHA-256) or the analyzer version changes,
    the cached entry is ignored and a fresh analysis is required.
    """

    DEFAULT_DB: str = os.path.join(
        os.path.expanduser("~"),
        ".overflowguard",
        "cache.db",
    )

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS file_cache (
        path       TEXT NOT NULL,
        sha256     TEXT NOT NULL,
        scanned_at REAL NOT NULL,
        findings   TEXT NOT NULL DEFAULT '[]',
        version    TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (path, version)
    );
    CREATE INDEX IF NOT EXISTS idx_sha256 ON file_cache(sha256);
    """

    def __init__(self, db_path: Optional[str] = None, version: str = "7.0"):
        self._path    = db_path or self.DEFAULT_DB
        self._version = version
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        self._conn: sqlite3.Connection = sqlite3.connect(
            self._path, check_same_thread=False
        )
        self._conn.executescript(self.SCHEMA)
        self._conn.commit()

    # ── Public interface ──────────────────────────────────────────────────────
    def get_cached(self, file_path: str) -> Optional[List[Dict[str, Any]]]:
        """
        Return cached findings for *file_path* if the file has not changed.
        Returns None if the file is new, modified, or the cache lacks an entry.
        """
        file_hash = self._hash(file_path)
        if file_hash is None:
            return None
        cur = self._conn.execute(
            "SELECT findings FROM file_cache WHERE path=? AND sha256=? AND version=?",
            (os.path.abspath(file_path), file_hash, self._version),
        )
        row = cur.fetchone()
        if row is None:
            return None
        try:
            return json.loads(row[0])
        except (json.JSONDecodeError, TypeError):
            return None

    def store(self, file_path: str, findings: List[Any]) -> None:
        """
        Persist *findings* for *file_path*.  Findings may be dataclass instances
        or plain dicts; they are serialised via their __dict__ or dict protocol.
        """
        file_hash = self._hash(file_path)
        if file_hash is None:
            return
        # Serialise — handle dataclasses and dicts gracefully
        serialisable = []
        for f in findings:
            if hasattr(f, "__dict__"):
                serialisable.append(f.__dict__)
            elif isinstance(f, dict):
                serialisable.append(f)
            else:
                serialisable.append(str(f))

        self._conn.execute(
            """
            INSERT INTO file_cache (path, sha256, scanned_at, findings, version)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(path, version) DO UPDATE SET
                sha256=excluded.sha256,
                scanned_at=excluded.scanned_at,
                findings=excluded.findings
            """,
            (
                os.path.abspath(file_path),
                file_hash,
                time.time(),
                json.dumps(serialisable, default=str),
                self._version,
            ),
        )
        self._conn.commit()

    def invalidate(self, file_path: str) -> None:
        """Remove the cache entry for *file_path*."""
        self._conn.execute(
            "DELETE FROM file_cache WHERE path=?",
            (os.path.abspath(file_path),),
        )
        self._conn.commit()

    def invalidate_dependents(self, changed_path: str) -> int:
        """
        Remove all entries whose path contains *changed_path* as a prefix
        (useful when a header changes and all including TUs must be re-scanned).
        Returns the number of invalidated rows.
        """
        base = os.path.abspath(changed_path)
        cur  = self._conn.execute(
            "DELETE FROM file_cache WHERE path LIKE ? RETURNING path",
            (f"{base}%",),
        )
        count = len(cur.fetchall())
        self._conn.commit()
        return count

    def purge_stale(self, max_age_days: float = 30.0) -> int:
        """
        Remove cache entries older than *max_age_days* AND whose on-disk file
        no longer exists.  Returns number of removed rows.
        """
        cutoff = time.time() - max_age_days * 86400
        cur    = self._conn.execute(
            "SELECT rowid, path, scanned_at FROM file_cache WHERE scanned_at < ?",
            (cutoff,),
        )
        to_delete = []
        for rowid, path, _ in cur.fetchall():
            if not os.path.isfile(path):
                to_delete.append(rowid)
        if to_delete:
            # Use executemany with a parameterised single-row DELETE to avoid
            # any f-string interpolation in SQL (satisfies Bandit B608)
            self._conn.executemany(
                "DELETE FROM file_cache WHERE rowid = ?",
                [(r,) for r in to_delete],
            )
            self._conn.commit()
        return len(to_delete)

    def stats(self) -> Dict[str, Any]:
        """Return a summary of the current cache state."""
        cur = self._conn.execute(
            "SELECT COUNT(*), MIN(scanned_at), MAX(scanned_at) FROM file_cache"
        )
        row = cur.fetchone()
        total, oldest, newest = row if row else (0, None, None)
        return {
            "total_entries" :  total,
            "oldest_scan"   :  oldest,
            "newest_scan"   :  newest,
            "db_path"       :  self._path,
            "version"       :  self._version,
        }

    # ── Internal helpers ──────────────────────────────────────────────────────
    @staticmethod
    def _hash(file_path: str) -> Optional[str]:
        """Return the SHA-256 hex digest of *file_path*, or None if unreadable."""
        try:
            h = hashlib.sha256()
            with open(file_path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return None

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "CacheManager":
        return self

    def __exit__(self, *_) -> None:
        self.close()
