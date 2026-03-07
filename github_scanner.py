"""
github_scanner.py — GitHub repository scanner for OverflowGuard v8.1

Accepts a GitHub repo URL or owner/repo shorthand and makes it available as a
local directory so the full OverflowGuard pipeline (SAST + SCA + Secrets +
SBOM + SARIF) can run on it.

Two acquisition strategies (tried in order)
-------------------------------------------
1. git clone  — fastest, most complete; requires `git` in PATH.
   Supports private repos when a token is supplied (GITHUB_TOKEN env var or prompt).
2. GitHub Contents API (fallback) — downloads source files one-by-one via
   https://api.github.com.  No git required.  Subject to rate limits
   (60 req/hr unauthenticated, 5 000 req/hr with token).

Supported input formats
-----------------------
  https://github.com/owner/repo
  https://github.com/owner/repo.git
  https://github.com/owner/repo/tree/branch
  git@github.com:owner/repo.git
  owner/repo
  owner/repo@branch
  owner/repo@v1.2.3

Usage
-----
    from github_scanner import fetch_repo

    with fetch_repo("torvalds/linux", branch="master", token=None) as local_path:
        # `local_path` is a temporary directory; analyse it normally
        ...
    # Temp directory is deleted automatically on context exit

Author : Parag Bagade
"""

from __future__ import annotations

import os
import re
import json
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from typing import Generator, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_GH_API_BASE   = "https://api.github.com"
_GH_RAW_BASE   = "https://raw.githubusercontent.com"
_API_TIMEOUT   = 20   # seconds per HTTP call
_CLONE_TIMEOUT = 300  # seconds for git clone (large repos can take a while)
_RETRY_WAIT    = 3    # seconds between retries on 429

# File extensions to download via Contents API (same set as SAST pipeline)
_SCAN_EXTS = {
    ".c", ".cc", ".cpp", ".h", ".go", ".rs", ".java", ".py",
    # manifests / config for SCA + secrets
    "requirements.txt", "pyproject.toml", "Pipfile",
    "package.json", "package-lock.json",
    "Cargo.toml", "Cargo.lock",
    "go.mod", "go.sum",
    "pom.xml", "build.gradle",
    ".env", ".env.local", ".env.production",
    ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".json", ".xml", ".properties",
    "Dockerfile", "docker-compose.yml",
}

_SKIP_DIRS = {
    ".git", ".github", "node_modules", "__pycache__", ".venv",
    "venv", "env", "site-packages", "dist-packages",
    "dist", "build", "target", ".tox", ".mypy_cache", ".pytest_cache",
}

# ---------------------------------------------------------------------------
# URL / shorthand parser
# ---------------------------------------------------------------------------

def parse_repo_input(raw: str) -> Tuple[str, str, Optional[str]]:
    """
    Parse any supported GitHub input format.

    Returns
    -------
    (owner, repo, branch_or_tag_or_commit)   — branch may be None
    """
    raw = raw.strip()

    # SSH: git@github.com:owner/repo.git
    m = re.match(r"git@github\.com:([^/]+)/([^.@\s]+?)(?:\.git)?(?:@(.+))?$", raw)
    if m:
        return m.group(1), m.group(2), m.group(3)

    # HTTPS with /tree/branch:
    # https://github.com/owner/repo/tree/branch
    m = re.match(
        r"https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/tree/([^/\s]+).*", raw
    )
    if m:
        return m.group(1), m.group(2), m.group(3)

    # Plain HTTPS: https://github.com/owner/repo or .git variant
    m = re.match(r"https?://github\.com/([^/]+)/([^/.\s]+?)(?:\.git)?/?$", raw)
    if m:
        return m.group(1), m.group(2), None

    # Shorthand: owner/repo@branch  or  owner/repo
    m = re.match(r"^([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:@(.+))?$", raw)
    if m:
        return m.group(1), m.group(2), m.group(3)

    raise ValueError(
        f"Cannot parse GitHub repo from input: {raw!r}\n"
        "Supported formats:\n"
        "  https://github.com/owner/repo\n"
        "  owner/repo\n"
        "  owner/repo@branch\n"
        "  git@github.com:owner/repo.git"
    )


def is_github_input(raw: str) -> bool:
    """Return True if *raw* looks like a GitHub repo reference."""
    raw = raw.strip()
    if re.match(r"https?://github\.com/", raw):
        return True
    if re.match(r"git@github\.com:", raw):
        return True
    # owner/repo  or  owner/repo@branch  (no spaces, one slash, no path sep)
    if re.match(r"^[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+(?:@[^\s]+)?$", raw):
        # make sure it is not a local relative path that happens to have a /
        return not os.path.exists(raw)
    return False


# ---------------------------------------------------------------------------
# Authentication helper
# ---------------------------------------------------------------------------

def _get_token(token: Optional[str] = None) -> Optional[str]:
    """Return a GitHub token from argument → env → None."""
    if token:
        return token
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


def _auth_headers(token: Optional[str]) -> dict:
    h = {"Accept": "application/vnd.github.v3+json", "User-Agent": "OverflowGuard/8.1"}
    if token:
        h["Authorization"] = f"token {token}"
    return h


# ---------------------------------------------------------------------------
# Strategy 1: git clone
# ---------------------------------------------------------------------------

def _clone(
    owner:  str,
    repo:   str,
    branch: Optional[str],
    token:  Optional[str],
    dest:   str,
) -> bool:
    """
    Clone the repo into *dest*.  Returns True on success.
    Uses a shallow clone (--depth 1) for speed.
    """
    if not shutil.which("git"):
        return False

    if token:
        url = f"https://{token}@github.com/{owner}/{repo}.git"
    else:
        url = f"https://github.com/{owner}/{repo}.git"

    cmd = ["git", "clone", "--depth", "1", "--single-branch"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [url, dest]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=_CLONE_TIMEOUT,
        )
        if result.returncode == 0:
            return True
        err = result.stderr.decode(errors="replace")
        # Surface useful errors (bad branch, private repo, etc.)
        if "Repository not found" in err or "not found" in err.lower():
            raise RuntimeError(
                f"Repository {owner}/{repo} not found or access denied.\n"
                "If private, set GITHUB_TOKEN environment variable."
            )
        if "does not exist" in err or "Remote branch" in err:
            raise RuntimeError(
                f"Branch/tag '{branch}' does not exist in {owner}/{repo}."
            )
        return False
    except subprocess.TimeoutExpired:
        print(f"  [GitHub] git clone timed out after {_CLONE_TIMEOUT}s.")
        return False
    except RuntimeError:
        raise
    except Exception as e:
        print(f"  [GitHub] git clone failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Strategy 2: GitHub Contents API (fallback)
# ---------------------------------------------------------------------------

def _api_get(url: str, headers: dict, retries: int = 3) -> Optional[dict]:
    """GET *url* and return parsed JSON or None on failure."""
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=_API_TIMEOUT) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 403:
                # Rate limited
                reset = e.headers.get("X-RateLimit-Reset", "")
                wait  = max(1, int(reset) - int(time.time())) if reset else _RETRY_WAIT
                wait  = min(wait, 30)
                print(f"  [GitHub API] Rate limited — waiting {wait}s …")
                time.sleep(wait)
            elif e.code == 404:
                return None
            else:
                return None
        except Exception:
            time.sleep(_RETRY_WAIT)
    return None


def _should_download(name: str, is_dir: bool) -> bool:
    if is_dir:
        return name not in _SKIP_DIRS
    _, ext = os.path.splitext(name)
    return ext.lower() in _SCAN_EXTS or name in _SCAN_EXTS


def _api_clone(
    owner:   str,
    repo:    str,
    branch:  Optional[str],
    token:   Optional[str],
    dest:    str,
    _path:   str = "",
    _depth:  int = 0,
) -> int:
    """
    Recursively fetch repo contents via the Contents API.
    Returns number of files downloaded.
    """
    if _depth > 10:
        return 0   # safety: no infinite recursion

    headers  = _auth_headers(token)
    ref_part = f"?ref={branch}" if branch else ""
    url      = f"{_GH_API_BASE}/repos/{owner}/{repo}/contents/{_path}{ref_part}"

    entries = _api_get(url, headers)
    if not entries or not isinstance(entries, list):
        return 0

    count = 0
    for entry in entries:
        name     = entry.get("name", "")
        etype    = entry.get("type", "")
        rel_path = entry.get("path", name)

        if etype == "dir":
            if not _should_download(name, True):
                continue
            sub_dest = os.path.join(dest, rel_path)
            os.makedirs(sub_dest, exist_ok=True)
            count += _api_clone(
                owner, repo, branch, token, dest, rel_path, _depth + 1
            )
        elif etype == "file":
            if not _should_download(name, False):
                continue
            raw_url = entry.get("download_url")
            if not raw_url:
                continue
            local_path = os.path.join(dest, rel_path)
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            try:
                req = urllib.request.Request(raw_url, headers=headers)
                with urllib.request.urlopen(req, timeout=_API_TIMEOUT) as resp:
                    with open(local_path, "wb") as fh:
                        fh.write(resp.read())
                count += 1
            except Exception:
                pass  # skip unreadable files silently

    return count


# ---------------------------------------------------------------------------
# Repo metadata fetcher
# ---------------------------------------------------------------------------

def get_repo_info(owner: str, repo: str, token: Optional[str]) -> dict:
    """Fetch basic repo metadata from the GitHub API."""
    url     = f"{_GH_API_BASE}/repos/{owner}/{repo}"
    headers = _auth_headers(token)
    data    = _api_get(url, headers)
    if not data:
        return {"full_name": f"{owner}/{repo}"}
    return {
        "full_name":    data.get("full_name", f"{owner}/{repo}"),
        "description":  data.get("description", ""),
        "language":     data.get("language", ""),
        "stars":        data.get("stargazers_count", 0),
        "forks":        data.get("forks_count", 0),
        "default_branch": data.get("default_branch", "main"),
        "private":      data.get("private", False),
        "topics":       data.get("topics", []),
        "license":      (data.get("license") or {}).get("spdx_id", ""),
        "html_url":     data.get("html_url", f"https://github.com/{owner}/{repo}"),
        "open_issues":  data.get("open_issues_count", 0),
        "size_kb":      data.get("size", 0),
    }


# ---------------------------------------------------------------------------
# Public context-manager API
# ---------------------------------------------------------------------------

@contextmanager
def fetch_repo(
    repo_input: str,
    branch:     Optional[str] = None,
    token:      Optional[str] = None,
) -> Generator[Tuple[str, dict], None, None]:
    """
    Context manager that makes a GitHub repo available as a local temp directory.

    Parameters
    ----------
    repo_input  : any supported format (URL, owner/repo, owner/repo@branch)
    branch      : explicit branch / tag / commit SHA (overrides @branch in input)
    token       : GitHub personal access token (or read from GITHUB_TOKEN env var)

    Yields
    ------
    (local_dir_path, repo_info_dict)

    Cleans up the temp directory on exit.

    Example
    -------
    with fetch_repo("pallets/flask", branch="main") as (local_path, info):
        print(info["stars"])   # e.g. 65000
        # run OverflowGuard pipeline on local_path
    """
    owner, repo, parsed_branch = parse_repo_input(repo_input)
    effective_branch = branch or parsed_branch
    token            = _get_token(token)

    print(f"\n{'─'*65}")
    print(f"  🐙  GitHub Repo Scanner — OverflowGuard v8.1")
    print(f"  Repository : {owner}/{repo}"
          + (f"  @{effective_branch}" if effective_branch else ""))
    print(f"  Auth       : {'token supplied ✓' if token else 'unauthenticated (60 req/hr limit)'}")
    print(f"{'─'*65}")

    # Fetch repo metadata (best-effort — never fatal)
    print("  [GitHub] Fetching repository metadata …")
    info = get_repo_info(owner, repo, token)
    if info.get("default_branch") and not effective_branch:
        effective_branch = info["default_branch"]

    print(f"  [GitHub] {info.get('full_name','')} ⭐ {info.get('stars',0)}  "
          f"🍴 {info.get('forks',0)}  📦 {info.get('size_kb',0)} KB  "
          f"🔒 {'private' if info.get('private') else 'public'}")
    if info.get("description"):
        print(f"  [GitHub] {info['description']}")
    if info.get("license"):
        print(f"  [GitHub] License: {info['license']}")

    tmp_dir = tempfile.mkdtemp(prefix=f"og_gh_{owner}_{repo}_")
    strategy = "none"
    try:
        # ── Strategy 1: git clone ─────────────────────────────────────────
        print("  [GitHub] Attempting git clone (shallow) …")
        cloned = False
        try:
            cloned = _clone(owner, repo, effective_branch, token, tmp_dir)
        except RuntimeError as e:
            print(f"  [GitHub] {Fore_RED}{e}{Style_RESET}")
            raise

        if cloned:
            strategy = "git-clone"
            print(f"  [GitHub] ✓ Cloned via git  →  {tmp_dir}")
        else:
            # ── Strategy 2: Contents API ──────────────────────────────────
            print("  [GitHub] git not available — falling back to Contents API …")
            n = _api_clone(owner, repo, effective_branch, token, tmp_dir)
            if n == 0:
                raise RuntimeError(
                    f"Could not retrieve any files from {owner}/{repo}. "
                    "Check the repo name, branch, and token."
                )
            strategy = "contents-api"
            print(f"  [GitHub] ✓ Downloaded {n} files via Contents API  →  {tmp_dir}")

        info["_local_path"] = tmp_dir
        info["_strategy"]   = strategy
        info["_owner"]      = owner
        info["_repo"]       = repo
        info["_branch"]     = effective_branch or ""
        yield tmp_dir, info

    finally:
        # Always clean up the temp directory
        if os.path.isdir(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Colour helpers (optional colorama)
# ---------------------------------------------------------------------------
try:
    from colorama import Fore as _Fore, Style as _Style
    Fore_RED    = _Fore.RED
    Fore_GREEN  = _Fore.GREEN
    Fore_CYAN   = _Fore.CYAN
    Style_RESET = _Style.RESET_ALL
except ImportError:
    Fore_RED = Fore_GREEN = Fore_CYAN = Style_RESET = ""


# ---------------------------------------------------------------------------
# CLI smoke-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "parag25mcf10022/OverflowGuard"
    print(f"Testing github_scanner with: {target}")
    with fetch_repo(target) as (local, info):
        files = []
        for root, _, fs in os.walk(local):
            files.extend(os.path.join(root, f) for f in fs)
        print(f"\nFiles available locally: {len(files)}")
        for f in files[:10]:
            print(f"  {f}")
        if len(files) > 10:
            print(f"  … and {len(files)-10} more")
