"""
ml_filter.py — P3: Machine-learning false-positive filter.

Uses a scikit-learn RandomForestClassifier when available; falls back to a
hand-tuned heuristic scoring function otherwise.  Both paths expose the same
public API so callers need not care which backend is active.

Training mode:
    from ml_filter import MLFilter
    mlf = MLFilter()
    mlf.train(labeled_findings)   # list of (finding_dict, label: bool)
    mlf.save_model()

Inference mode (normal use):
    mlf   = MLFilter()            # auto-loads saved model if present
    score = mlf.score(finding)    # float 0.0–1.0 (1.0 = likely true positive)
    kept  = mlf.filter(findings)  # suppress findings scoring below threshold

Exported API:
    MLFilter
        .score(finding) → float       (probability of being a true positive)
        .filter(findings, threshold)  → filtered list
        .train(labeled)               → None   (requires scikit-learn)
        .save_model(path)             → None
        .load_model(path)             → None
"""

import json
import os
import pickle
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

try:
    import sklearn  # type: ignore
    from sklearn.ensemble import RandomForestClassifier  # type: ignore
    from sklearn.preprocessing import LabelEncoder        # type: ignore
    _HAS_SKLEARN = True
except ImportError:
    _HAS_SKLEARN = False


# ── Feature Extraction ────────────────────────────────────────────────────────
# Maps issue_type strings to a numeric severity score for feature encoding
_SEVERITY_MAP: Dict[str, float] = {
    "stack-buffer-overflow":  1.0,
    "heap-buffer-overflow":   1.0,
    "os-command-injection":   1.0,
    "format-string":          0.9,
    "use-after-free":         0.9,
    "double-free":            0.9,
    "race-condition":         0.8,
    "data-race":              0.8,
    "integer-overflow":       0.75,
    "integer-truncation":     0.7,
    "negative-index":         0.7,
    "off-by-one":             0.65,
    "sql-injection":          0.9,
    "path-traversal":         0.8,
    "null-pointer-deref":     0.6,
    "uninitialized-variable": 0.5,
    "volatile-misuse":        0.7,
    "missing-atomic":         0.6,
    "double-checked-locking": 0.8,
    "thread-in-destructor":   0.75,
    "concurrent-map-write":   0.8,
    "goroutine-loop-closure": 0.85,
    "potential-stack-overflow": 0.4,
    "waitgroup-add-in-goroutine": 0.8,
}

_CONFIDENCE_MAP: Dict[str, float] = {
    "HIGH":   1.0,
    "MEDIUM": 0.6,
    "LOW":    0.3,
}

_STAGE_MAP: Dict[str, float] = {
    "AST":               0.5,
    "Taint":             0.7,
    "Deep":              0.75,
    "Dataflow":          0.8,
    "Interprocedural":   0.85,
    "Symbolic":          0.9,
    "Concurrency":       0.8,
    "LLVM":              0.9,
    "Concolic":          0.95,
    "StaticTool":        0.6,
}


def _extract_features(finding: Any) -> List[float]:
    """
    Convert a finding (dataclass or dict) to a fixed-length numeric feature vector.
    Feature vector (10 dimensions):
      [0]  severity score          (issue_type)
      [1]  confidence score        (HIGH/MEDIUM/LOW)
      [2]  stage score             (e.g. Symbolic = 0.9)
      [3]  line number (log-scaled)
      [4]  snippet length          (proxy for complexity)
      [5]  note length             (longer = more context = more likely real)
      [6]  has_cve                 (binary)
      [7]  is_interprocedural      (binary)
      [8]  snippet_has_unsafe_call (strcpy/gets/system etc.)
      [9]  repeated_finding_flag   (1 if same issue_type seen before)
    """
    if hasattr(finding, "__dict__"):
        d = finding.__dict__
    elif isinstance(finding, dict):
        d = finding
    else:
        d = {}

    issue_type  = str(d.get("issue_type", ""))
    confidence  = str(d.get("confidence", "LOW")).upper()
    stage       = str(d.get("stage", ""))
    line        = int(d.get("line", 1))
    snippet     = str(d.get("snippet", ""))
    note        = str(d.get("note", ""))

    severity    = _SEVERITY_MAP.get(issue_type, 0.4)
    conf_score  = _CONFIDENCE_MAP.get(confidence, 0.3)
    stage_score = _STAGE_MAP.get(stage, 0.5)
    line_scaled = min(1.0, line / 5000.0)
    snip_len    = min(1.0, len(snippet) / 200.0)
    note_len    = min(1.0, len(note) / 500.0)
    has_cve     = 1.0 if "CVE-" in note else 0.0
    is_interpro = 1.0 if stage == "Interprocedural" else 0.0
    unsafe_fns  = {"strcpy", "strcat", "gets", "sprintf", "system", "memcpy"}
    has_unsafe  = 1.0 if any(fn in snippet for fn in unsafe_fns) else 0.0
    # Field 9 left as 0.0 — caller may set this if deduplication context available
    repeated    = 0.0

    return [
        severity, conf_score, stage_score, line_scaled,
        snip_len, note_len, has_cve, is_interpro, has_unsafe, repeated,
    ]


# ── Heuristic scorer (no sklearn) ─────────────────────────────────────────────
def _heuristic_score(features: List[float]) -> float:
    """
    Weighted linear combination of features → probability [0, 1].
    Weights were hand-tuned on the OverflowGuard sample dataset.
    """
    weights = [0.30, 0.20, 0.15, 0.02, 0.03, 0.05, 0.08, 0.07, 0.07, -0.05]
    score = sum(w * f for w, f in zip(weights, features))
    # Normalize to [0, 1]
    return max(0.0, min(1.0, score))


# ── MLFilter ──────────────────────────────────────────────────────────────────
DEFAULT_MODEL_PATH = os.path.join(
    os.path.expanduser("~"), ".overflowguard", "ml_model.pkl"
)

DEFAULT_THRESHOLD = 0.35  # findings scoring below this are suppressed


class MLFilter:
    """
    False-positive filter for OverflowGuard findings.

    When scikit-learn is installed and a trained model exists, uses it.
    Otherwise falls back to heuristic scoring — no functionality is lost,
    only precision may differ.

    Usage:
        mlf = MLFilter()
        kept = mlf.filter(findings)        # uses default threshold (0.35)
        kept = mlf.filter(findings, 0.5)   # stricter
    """

    def __init__(self, model_path: Optional[str] = None):
        self._model_path = model_path or DEFAULT_MODEL_PATH
        self._clf        = None
        self._using_ml   = False

        if _HAS_SKLEARN and os.path.isfile(self._model_path):
            # Safety: only auto-load from the well-known OverflowGuard model dir.
            # Never load a pickle from an arbitrary / user-supplied path without
            # explicit confirmation — pickle.load() executes arbitrary code.
            _safe_prefix = os.path.join(os.path.expanduser("~"), ".overflowguard")
            if not os.path.abspath(self._model_path).startswith(_safe_prefix):
                pass  # refuse to auto-load from unexpected location
            else:
                try:
                    with open(self._model_path, "rb") as fh:
                        self._clf = pickle.load(fh)  # nosec B301 — trusted path only
                    self._using_ml = True
                except Exception:
                    self._clf      = None
                    self._using_ml = False

    # ── Inference ─────────────────────────────────────────────────────────────
    def score(self, finding: Any) -> float:
        """Return probability [0.0, 1.0] that *finding* is a true positive."""
        features = _extract_features(finding)
        if self._using_ml and self._clf is not None:
            try:
                prob = self._clf.predict_proba([features])[0][1]
                return float(prob)
            except Exception:
                pass
        return _heuristic_score(features)

    def filter(
        self,
        findings: List[Any],
        threshold: float = DEFAULT_THRESHOLD,
    ) -> List[Any]:
        """
        Return only findings that score >= *threshold*.
        Findings with confidence=HIGH always pass regardless of score.
        """
        result = []
        for f in findings:
            conf = (
                f.confidence
                if hasattr(f, "confidence")
                else str(f.get("confidence", ""))
            ).upper()
            if conf == "HIGH":
                result.append(f)
                continue
            if self.score(f) >= threshold:
                result.append(f)
        return result

    # ── Training ──────────────────────────────────────────────────────────────
    def train(
        self,
        labeled: List[Tuple[Any, bool]],
        n_estimators: int = 200,
    ) -> "MLFilter":
        """
        Train a RandomForest classifier on a labeled dataset.

        labeled: list of (finding, is_true_positive: bool) pairs
        Requires scikit-learn.  Raises ImportError if unavailable.
        """
        if not _HAS_SKLEARN:
            raise ImportError(
                "scikit-learn is required for MLFilter.train(). "
                "Install it with: pip install scikit-learn"
            )
        if not labeled:
            raise ValueError("labeled dataset is empty")

        X = [_extract_features(f) for f, _ in labeled]
        y = [int(label) for _, label in labeled]

        clf = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=8,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        clf.fit(X, y)
        self._clf      = clf
        self._using_ml = True
        return self

    def save_model(self, path: Optional[str] = None) -> str:
        """Persist the trained model to disk.  Returns the saved path."""
        if not _HAS_SKLEARN or self._clf is None:
            raise ValueError("No trained model to save")
        target = path or self._model_path
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as fh:
            pickle.dump(self._clf, fh, protocol=pickle.HIGHEST_PROTOCOL)
        return target

    def load_model(self, path: str) -> "MLFilter":
        """Load a previously saved model from *path*.

        WARNING: only call this with a model file you generated and trust.
        pickle.load() can execute arbitrary code if the file is tampered with.
        """
        with open(path, "rb") as fh:
            self._clf = pickle.load(fh)  # nosec B301 — caller is responsible for path trust
        self._using_ml = _HAS_SKLEARN
        return self

    @property
    def backend(self) -> str:
        return "RandomForest (sklearn)" if self._using_ml else "heuristic"
