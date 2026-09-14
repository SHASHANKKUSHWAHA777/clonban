"""
TLSH fuzzy similarity (Phase 4.3).

Uses TLSH ( Trend Micro Locality-Sensitive Hashing ) if available.
Falls back to ssdeep if TLSH is not installed.

Key contract rules:
  - When fuzzy hash cannot be calculated (too small input, malformed DEX,
    library missing, etc.), return None — NEVER 0.
  - Distance metrics from TLSH are normalized to [0,1] similarity via a
    documented linear function.
  - Raw diagnostic information is returned alongside the score.
"""
import logging
from typing import Optional, Union

try:
    import tlsh
    HAVE_TLSH = True
except Exception:  # pragma: no cover - documented fallback
    HAVE_TLSH = False
    tlsh = None

try:
    import ssdeep
    HAVE_SSDEEP = True
except Exception:  # pragma: no cover - documented fallback
    HAVE_SSDEEP = False
    ssdeep = None

logger = logging.getLogger("clonedetector.dexrisk.tlsh")

# TLSH distance is [0, ~1000+]. Empirical maximum for practical DEX files:
# scores above 1000 are effectively dissimilar. We map distance 0 → 1.0,
# distance MAX_DISTANCE → 0.0 linearly.
TLSH_MAX_DISTANCE = 1000.0


def normalize_tlsh_distance(distance: int) -> float:
    """
    Convert a TLSH distance (int) to a normalized similarity in [0, 1].

    Documented mapping:
      similarity = max(0, 1 - distance / MAX_DISTANCE)

    This is a simple, explainable linear normalization. It does NOT claim
    cryptographic or obfuscation-proof accuracy.
    """
    if distance < 0:
        return 0.0
    similarity = 1.0 - (distance / TLSH_MAX_DISTANCE)
    return max(0.0, min(1.0, similarity))


def normalize_ssdeep_score(score: int) -> float:
    """
    ssdeep.compare returns 0-100. Normalize to [0, 1].
    """
    if score < 0:
        return 0.0
    return max(0.0, min(1.0, score / 100.0))


def compute_tlsh(data: bytes) -> Optional[str]:
    """Compute a TLSH hash of *data*. Returns None on any failure."""
    if not HAVE_TLSH:
        return None
    if not data or len(data) < 512:
        # TLSH requires a minimum amount of data to produce a meaningful hash.
        logger.info("Input too small for TLSH hashing (%d bytes, minimum 512)", len(data) if data else 0)
        return None
    try:
        return tlsh.hash(data)
    except Exception:
        logger.warning("TLSH hashing failed", exc_info=True)
        return None


def compute_ssdeep(data: bytes) -> Optional[str]:
    """Compute an ssdeep hash of *data*. Returns None on any failure."""
    if not HAVE_SSDEEP:
        return None
    if not data:
        return None
    try:
        return ssdeep.hash(data)
    except Exception:
        logger.warning("ssdeep hashing failed", exc_info=True)
        return None


def calculate_dex_fuzzy_similarity(baseline_bytes: bytes, candidate_bytes: bytes) -> dict:
    """
    Calculate fuzzy similarity between two DEX byte blobs.

    Tries TLSH first, falls back to ssdeep.

    Returns:
      {
        "algorithm": "TLSH" | "SSDEEP" | None,
        "available": bool,
        "distance": int | None,       # raw distance (TLSH) or None (ssdeep)
        "similarity": float | None,   # normalized [0,1] or None if unavailable
        "error": str | None,
      }

    When neither algorithm is available or input is too small,
    "similarity" is None (NOT 0).
    """
    result = {
        "algorithm": None,
        "available": False,
        "distance": None,
        "similarity": None,
        "error": None,
    }

    if not baseline_bytes or not candidate_bytes:
        result["error"] = "One or both DEX byte blobs are empty"
        return result

    # Try TLSH first
    if HAVE_TLSH:
        h_b = compute_tlsh(baseline_bytes)
        h_c = compute_tlsh(candidate_bytes)
        if h_b and h_c:
            try:
                dist = tlsh.diff(h_b, h_c)
                result["algorithm"] = "TLSH"
                result["available"] = True
                result["distance"] = dist
                result["similarity"] = round(normalize_tlsh_distance(dist), 4)
                return result
            except Exception:
                logger.warning("TLSH diff failed", exc_info=True)
                result["error"] = "TLSH diff computation failed"
        else:
            result["error"] = "TLSH hash could not be generated (input too small or malformed)"

    # Fall back to ssdeep
    if HAVE_SSDEEP:
        h_b = compute_ssdeep(baseline_bytes)
        h_c = compute_ssdeep(candidate_bytes)
        if h_b and h_c:
            try:
                score = ssdeep.compare(h_b, h_c)  # 0-100
                result["algorithm"] = "SSDEEP"
                result["available"] = True
                result["distance"] = None  # ssdeep doesn't expose distance
                result["similarity"] = round(normalize_ssdeep_score(score), 4)
                return result
            except Exception:
                logger.warning("ssdeep compare failed", exc_info=True)
                if not result["error"]:
                    result["error"] = "ssdeep compare failed"
        else:
            if not result["error"]:
                result["error"] = "ssdeep hash could not be generated"

    if not HAVE_TLSH and not HAVE_SSDEEP:
        result["error"] = "Neither TLSH nor ssdeep is available"

    return result
