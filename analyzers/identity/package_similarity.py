"""
Package namespace similarity (Phase 3.3).

Combines normalized Levenshtein ratio with segment/token overlap to
produce a [0,1] similarity score and a match-state classification.

Match states:
  EXACT_MATCH  — package names are identical
  NEAR_MATCH   — very similar namespace (common cloning trick)
  UNRELATED    — distinct namespaces
"""
import logging
from difflib import SequenceMatcher
from typing import Optional

logger = logging.getLogger("clonedetector.identity.package_similarity")

EXACT_MATCH = "EXACT_MATCH"
NEAR_MATCH = "NEAR_MATCH"
UNRELATED = "UNRELATED"

# Thresholds for match-state classification.
NEAR_MATCH_THRESHOLD = 0.60
UNRELATED_THRESHOLD = 0.30


def _normalize_package(pkg: Optional[str]) -> Optional[str]:
    """Normalize a package name: lowercase, strip whitespace."""
    if not pkg:
        return None
    return pkg.strip().lower()


def _segment_similarity(a: Optional[str], b: Optional[str]) -> float:
    """
    Jaccard similarity over package segments.
    e.g. com.bank.app vs com.bank.appp → segments {com,bank,app} vs {com,bank,appp}
    """
    if not a or not b:
        return 0.0
    sa = set(_normalize_package(a).split("."))
    sb = set(_normalize_package(b).split("."))
    if not sa and not sb:
        return 1.0
    intersection = len(sa & sb)
    union = len(sa | sb)
    if union == 0:
        return 0.0
    return intersection / union


def _levenshtein_ratio(a: Optional[str], b: Optional[str]) -> float:
    """Normalized Levenshtein similarity from difflib.SequenceMatcher."""
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


def _suffix_boost(a: Optional[str], b: Optional[str]) -> float:
    """
    Reward package names where one is a prefix/suffix extension of the other
    (e.g. com.bank.app vs com.bank.app2). Very common cloning pattern.
    Returns 1.0 when one name is a substring of the other (but not equal).
    """
    if not a or not b:
        return 0.0
    if a == b:
        return 0.0
    na, nb = _normalize_package(a), _normalize_package(b)
    if na in nb or nb in na:
        return 1.0
    return 0.0


def compute_similarity(baseline_pkg: Optional[str], candidate_pkg: Optional[str]) -> float:
    """
    Compute a blended similarity score in [0, 1].

    Formula (documented):
      score = 0.50 * segment_jaccard + 0.40 * levenshtein_ratio + 0.10 * suffix_boost

    Where:
      segment_jaccard = overlap of namespace tokens / total tokens
      levenshtein_ratio = difflib SequenceMatcher ratio
      suffix_boost = 1.0 if one package is a substring of the other (common clone trick)

    Exact match returns 1.0 directly (before formula).
    Inputs that are None yield 0.0 similarity (handled by the caller).
    """
    if not baseline_pkg or not candidate_pkg:
        return 0.0
    if baseline_pkg == candidate_pkg:
        return 1.0

    seg_sim = _segment_similarity(baseline_pkg, candidate_pkg)
    lev_sim = _levenshtein_ratio(baseline_pkg, candidate_pkg)
    boost = _suffix_boost(baseline_pkg, candidate_pkg)

    score = 0.50 * seg_sim + 0.40 * lev_sim + 0.10 * boost
    return round(min(score, 1.0), 4)


def classify_match_state(baseline_pkg: Optional[str], candidate_pkg: Optional[str], similarity: float) -> str:
    """
    Classify the package relationship into EXACT_MATCH, NEAR_MATCH, UNRELATED.
    """
    if baseline_pkg and candidate_pkg and baseline_pkg == candidate_pkg:
        return EXACT_MATCH

    if similarity >= NEAR_MATCH_THRESHOLD:
        return NEAR_MATCH
    if similarity < UNRELATED_THRESHOLD:
        return UNRELATED
    # Between UNRELATED_THRESHOLD and NEAR_MATCH_THRESHOLD: treat as NEAR_MATCH
    return NEAR_MATCH


def analyze_package_similarity(baseline_pkg: Optional[str], candidate_pkg: Optional[str]) -> dict:
    """
    Full package similarity analysis.

    Returns:
      {
        "similarity": float | None,  # null if either package name missing
        "match_state": EXACT_MATCH | NEAR_MATCH | UNRELATED,
        "baseline_segments": list[str] | None,
        "candidate_segments": list[str] | None,
      }
    """
    if not baseline_pkg or not candidate_pkg:
        return {
            "similarity": None,
            "match_state": UNRELATED if (not baseline_pkg or not candidate_pkg) else UNRELATED,
            "baseline_segments": _segments(baseline_pkg),
            "candidate_segments": _segments(candidate_pkg),
        }

    sim = compute_similarity(baseline_pkg, candidate_pkg)
    state = classify_match_state(baseline_pkg, candidate_pkg, sim)
    return {
        "similarity": sim,
        "match_state": state,
        "baseline_segments": _segments(baseline_pkg),
        "candidate_segments": _segments(candidate_pkg),
    }


def _segments(pkg: Optional[str]) -> Optional[list[str]]:
    if not pkg:
        return None
    return _normalize_package(pkg).split(".")
