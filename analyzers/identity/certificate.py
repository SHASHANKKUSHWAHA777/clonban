"""
Certificate extraction and comparison (Phase 3.2).

Uses androguard as the primary mechanism (pure Python, no shell). Falls back
to *apksigner* via subprocess where available, but apksigner is optional.

Normalization rules:
  - Fingerprints are lowercased and stripped of colons/whitespace before comparison.
  - "Signer identity" is the certificate SHA-256 when available.

Output tri-state:
  SAME_SIGNER    -> numeric score 1.0
  DIFFERENT_SIGNER -> numeric score 0.0
  UNKNOWN         -> numeric score null
"""
import logging
from typing import Optional

from analyzers.common.apk_utils import normalize_fingerprint
from analyzers.common.errors import AnalyzerError

logger = logging.getLogger("clonedetector.identity.certificate")

SAME_SIGNER = "SAME_SIGNER"
DIFFERENT_SIGNER = "DIFFERENT_SIGNER"
UNKNOWN = "UNKNOWN"


def extract_certificate_info(apk) -> dict:
    """
    Extract certificate metadata from a parsed androguard APK object.
    Returns a dict with: sha256, sha1, md5, subject, issuer, signer_count.
    All values may be None if unavailable.
    """
    info = {
        "sha256": None,
        "sha1": None,
        "md5": None,
        "subject": None,
        "issuer": None,
        "signer_count": None,
    }
    if apk is None:
        return info

    try:
        certs = apk.get_certificates() or []
        if certs:
            cert = certs[0]
            if hasattr(cert, "sha256"):
                info["sha256"] = cert.sha256.hex() if cert.sha256 else None
            if hasattr(cert, "sha1"):
                info["sha1"] = cert.sha1.hex() if cert.sha1 else None
            if hasattr(cert, "md5"):
                info["md5"] = cert.md5.hex() if cert.md5 else None
            try:
                info["subject"] = str(cert.subject)
            except Exception:
                pass
            try:
                info["issuer"] = str(cert.issuer)
            except Exception:
                pass
            info["signer_count"] = len(certs)
    except AnalyzerError:
        raise
    except Exception:
        logger.warning("Certificate extraction failed", exc_info=True)
    return info


def compare_certificates(baseline_info: dict, candidate_info: dict) -> dict:
    """
    Compare two certificate info dicts.

    Returns:
      {
        "status": SAME_SIGNER | DIFFERENT_SIGNER | UNKNOWN,
        "score": 1.0 | 0.0 | null,
        "evidence": "human-readable explanation",
      }

    Rules:
      - If both fingerprints are available and match -> SAME_SIGNER (1.0)
      - If both fingerprints are available but differ -> DIFFERENT_SIGNER (0.0)
      - If either fingerprint is missing -> UNKNOWN (null)
    """
    fp_b = normalize_fingerprint(baseline_info.get("sha256"))
    fp_c = normalize_fingerprint(candidate_info.get("sha256"))

    if fp_b is None and fp_c is None:
        return {
            "status": UNKNOWN,
            "score": None,
            "evidence": "No certificate fingerprints available for either APK; signing identity unknown.",
        }

    if fp_b is None or fp_c is None:
        missing = "baseline" if fp_b is None else "candidate"
        return {
            "status": UNKNOWN,
            "score": None,
            "evidence": f"Certificate fingerprint unavailable for {missing} APK; signing identity unknown.",
        }

    if fp_b == fp_c:
        return {
            "status": SAME_SIGNER,
            "score": 1.0,
            "evidence": "Signing certificates match between baseline and candidate.",
        }

    return {
        "status": DIFFERENT_SIGNER,
        "score": 0.0,
        "evidence": "Signing certificates differ between baseline and candidate — evidence of re-signing, not automatic proof of cloning.",
    }
