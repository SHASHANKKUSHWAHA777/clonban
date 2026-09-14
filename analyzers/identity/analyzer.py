"""
Identity Analyzer (V3 — Phase 3)

Extracts package identity from both APKs and produces structured evidence
that the platform/scoring layer can consume.

A matching certificate is strong evidence of common origin; a different
certificate is evidence of re-signing, NOT automatic proof of cloning
(legitimate apps get re-signed too, e.g. by app stores).

Frozen contract (additive — legacy fields kept for backward compatibility):
{
  "service": "identity",
  "certificate_status": "SAME_SIGNER | DIFFERENT_SIGNER | UNKNOWN",
  "certificate_identity_score": 0.0,          # 1.0 / 0.0 / null
  "package_similarity": 0.0,                  # [0,1] or null
  "manifest_findings": [],

  "baseline": {"package_name", "app_label", "version_name", "version_code", ...},
  "candidate": {"package_name", "app_label", "version_name", "version_code", ...},
  "package_match_state": "EXACT_MATCH | NEAR_MATCH | UNRELATED",
  "permissions_baseline": [],
  "permissions_candidate": [],
  "new_permissions": [],
  "removed_permissions": [],
  "exported_components_baseline": [],
  "exported_components_candidate": [],
  "errors": [{"stage": "...", "message": "..."}],
}

Legacy fields preserved for scoring engine / tasks.py:
  certificate_score, certificate_match, package_score,
  manifest_score, permissions_score, findings, apks
"""
import logging
import re
from typing import Optional

from androguard.core.apk import APK

from analyzers.common.apk_utils import (
    normalize_fingerprint,
    parse_apk,
    validate_apk,
    discover_dex_files,
)
from analyzers.common.errors import AnalyzerError
from analyzers.identity.certificate import (
    extract_certificate_info,
    compare_certificates,
    SAME_SIGNER,
    DIFFERENT_SIGNER,
    UNKNOWN,
)
from analyzers.identity.package_similarity import (
    analyze_package_similarity,
    compute_similarity as compute_package_similarity,
    UNRELATED as UNRELATED_PKG,
)
from analyzers.identity.manifest import (
    extract_apk_metadata,
    build_manifest_findings,
    _clean_metadata,
    normalize_permission,
)

logger = logging.getLogger("clonedetector.identity")

# Legacy aliases kept for backward compatibility with scoring engine.
SAME_SIGNER_SCORE = 1.0
DIFFERENT_SIGNER_SCORE = 0.0
UNKNOWN_SCORE = None


# Backward-compat alias for existing unit tests that import _token_similarity.
def _token_similarity(a: str, b: str) -> float:
    """Backward-compatible alias for package_similarity.compute_similarity."""
    return compute_package_similarity(a, b)


def _extract_apk_info(path: str) -> dict:
    """
    Parse an APK and return a metadata dict.

    Uses common.apk_utils.validate_apk + parse_apk for robustness.
    On failure, returns is_valid=False with parse_error set, and all
    numeric/identity fields stay None (never silently 0).
    """
    info = {
        "package_name": None, "app_label": None, "version_name": None,
        "version_code": None, "min_sdk": None, "target_sdk": None,
        "permissions": [], "activities": [], "services": [],
        "receivers": [], "providers": [],
        "exported_components": [],
        "cert_sha256": None, "cert_subject": None, "cert_issuer": None,
        "cert_signer_count": None,
        "icon_path": None, "is_valid": True, "parse_error": None,
        "dex_files": [],
        "_apk_obj": None, "_icon_name": None,
    }

    # Validate before parsing.
    err = validate_apk(path, label="APK")
    if err:
        info["is_valid"] = False
        info["parse_error"] = err
        return info

    try:
        apk = parse_apk(path)
        info["_apk_obj"] = apk
        # Use manifest.py's extraction which handles more edge cases.
        metadata = extract_apk_metadata(apk, label=path)
        # Copy non-internal keys into info.
        for k, v in metadata.items():
            if not k.startswith("_"):
                info[k] = v
        info["_apk_obj"] = apk
        info["_icon_name"] = metadata.get("_icon_name")
    except AnalyzerError as e:
        info["is_valid"] = False
        info["parse_error"] = e.message
    except Exception as e:
        logger.exception("Failed to parse APK %s", path)
        info["is_valid"] = False
        info["parse_error"] = str(e)

    return info


def _safe_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _clean(info: dict) -> dict:
    """Strip internal fields (prefixed with _) from metadata dict."""
    return {k: v for k, v in info.items() if not k.startswith("_")}


def _diff_permissions(baseline_perms: list, candidate_perms: list) -> tuple[list, list]:
    """
    Compute (new_permissions, removed_permissions) as sorted, deduplicated lists.
    Normalizes permission names (strips android.permission. prefix).
    """
    from analyzers.identity.manifest import normalize_permission
    b_set = set(normalize_permission(p) for p in (baseline_perms or []))
    c_set = set(normalize_permission(p) for p in (candidate_perms or []))
    new_perms = sorted(c_set - b_set)
    removed_perms = sorted(b_set - c_set)
    return new_perms, removed_perms


def _build_metadata_block(info: dict) -> dict:
    """
    Build the V3 baseline/candidate metadata sub-object.
    """
    return {
        "package_name": info.get("package_name"),
        "app_label": info.get("app_label"),
        "version_name": info.get("version_name"),
        "version_code": str(info.get("version_code")) if info.get("version_code") is not None else None,
        "min_sdk": info.get("min_sdk"),
        "target_sdk": info.get("target_sdk"),
        "permissions": info.get("permissions", []),
        "activities": info.get("activities", []),
        "services": info.get("services", []),
        "receivers": info.get("receivers", []),
        "providers": info.get("providers", []),
        "exported_components": info.get("exported_components", []),
        "cert_sha256": info.get("cert_sha256"),
        "cert_subject": info.get("cert_subject"),
        "cert_issuer": info.get("cert_issuer"),
        "cert_signer_count": info.get("cert_signer_count"),
    }


def analyze(original_path: str, candidate_path: str) -> dict:
    """
    Analyze baseline (original) vs candidate APK identity.

    Returns V3 contract dict with both V3 fields and legacy aliases.
    Never crashes the FastAPI process — all errors are captured in the
    "errors" list and unavailable signals are null, never 0.
    """
    logger = logging.getLogger("clonedetector.identity")
    errors = []
    findings = []

    # ---- Step 1: Validate and extract both APKs ----
    orig = _extract_apk_info(original_path)
    cand = _extract_apk_info(candidate_path)

    # ---- Handle parse failures gracefully ----
    if not orig["is_valid"] or not cand["is_valid"]:
        # Do NOT return certificate_score=0.0 or package_similarity=0.0.
        # Instead: unknown status, null scores, and a structured error.
        for role, info in [("original", orig), ("candidate", cand)]:
            if not info["is_valid"]:
                errors.append({
                    "stage": "parse",
                    "message": f"Failed to parse {role} APK: {info.get('parse_error')}",
                })

        # If at least one APK parsed, we can still do partial analysis.
        # If neither parsed, return all-null results.
        has_orig = orig["is_valid"]
        has_cand = cand["is_valid"]

        result = _build_result(
            orig, cand,
            cert_status=UNKNOWN if not has_orig or not has_cand else UNKNOWN,
            cert_score=None,
            package_similarity=None,
            package_match_state=UNRELATED_PKG,
            manifest_score=0.0,
            permissions_score=0.0,
            findings=findings,
            errors=errors,
        )
        result["errors"].append({
            "stage": "parse",
            "message": "One or both APKs could not be fully parsed; identity scores are unavailable (null).",
        })
        return result

    # ---- Step 2: Certificate analysis ----
    cert_info_b = extract_certificate_info(orig["_apk_obj"])
    cert_info_c = extract_certificate_info(cand["_apk_obj"])
    cert_comparison = compare_certificates(cert_info_b, cert_info_c)

    if cert_comparison["status"] == DIFFERENT_SIGNER:
        findings.append({
            "type": "CERT_MISMATCH",
            "severity": "medium",
            "evidence": cert_comparison["evidence"],
            "source_apk": "both",
        })

    # ---- Step 3: Package namespace similarity ----
    pkg_analysis = analyze_package_similarity(orig["package_name"], cand["package_name"])
    package_similarity = pkg_analysis["similarity"]
    package_match_state = pkg_analysis["match_state"]

    if package_match_state == "EXACT_MATCH" and cert_comparison["status"] == DIFFERENT_SIGNER:
        findings.append({
            "type": "SAME_PACKAGE_DIFFERENT_CERT",
            "severity": "high",
            "evidence": "Identical package name but different signing certificate — classic impersonation pattern.",
            "source_apk": "both",
        })

    # ---- Step 4: Permission diffing ----
    new_permissions, removed_permissions = _diff_permissions(
        orig["permissions"], cand["permissions"]
    )

    # ---- Step 5: Build manifest findings ----
    manifest_findings = build_manifest_findings(orig, cand)

    # Legacy compat: combine all findings for tasks.py and scoring engine.
    findings.extend(manifest_findings)

    # ---- Step 6: Build result with V3 fields + legacy aliases ----
    result = _build_result(
        orig, cand,
        cert_status=cert_comparison["status"],
        cert_score=cert_comparison["score"],
        package_similarity=package_similarity,
        package_match_state=package_match_state,
        manifest_score=_manifest_similarity(orig, cand),
        permissions_score=_permissions_similarity(orig, cand),
        findings=findings,
        errors=errors,
    )
    result["manifest_findings"] = manifest_findings
    result["new_permissions"] = new_permissions
    result["removed_permissions"] = removed_permissions
    result["permissions_baseline"] = orig["permissions"]
    result["permissions_candidate"] = cand["permissions"]
    result["exported_components_baseline"] = orig.get("exported_components", [])
    result["exported_components_candidate"] = cand.get("exported_components", [])
    result["errors"] = errors

    return result


def _build_result(
    orig: dict, cand: dict,
    cert_status: str, cert_score,
    package_similarity, package_match_state: str,
    manifest_score: float, permissions_score: float,
    findings: list, errors: list,
) -> dict:
    """
    Build the result dict with both V3 fields and legacy aliases.
    """
    cert_match_bool = (cert_status == SAME_SIGNER)

    return {
        # V3 contract fields
        "service": "identity",
        "certificate_status": cert_status,
        "certificate_identity_score": cert_score,
        "package_similarity": package_similarity,
        "package_match_state": package_match_state,
        "manifest_findings": [],
        "permissions_baseline": [],
        "permissions_candidate": [],
        "new_permissions": [],
        "removed_permissions": [],
        "exported_components_baseline": [],
        "exported_components_candidate": [],
        "errors": errors,

        # Legacy aliases (for scoring engine + tasks.py backward compat)
        "certificate_score": cert_score if cert_score is not None else 0.0,
        "certificate_match": cert_match_bool,
        "package_score": package_similarity if package_similarity is not None else 0.0,
        "manifest_score": manifest_score,
        "permissions_score": permissions_score,
        "findings": findings,

        # Metadata blocks
        "baseline": _build_metadata_block(orig),
        "candidate": _build_metadata_block(cand),

        # APK-level detail (legacy — used by tasks.py _persist_apk_extras)
        "apks": {
            "original": _clean(orig),
            "candidate": _clean(cand),
        },
    }


def _manifest_similarity(orig: dict, cand: dict) -> float:
    """Component set overlap (activities, services, receivers, providers)."""
    def norm(lst):
        return {re.sub(r"^android\.", "", x) for x in (lst or [])}

    parts = []
    for key in ("activities", "services", "receivers", "providers"):
        a, b = norm(orig.get(key)), norm(cand.get(key))
        if not a and not b:
            continue
        parts.append(len(a & b) / max(len(a | b), 1))
    return round(sum(parts) / len(parts), 4) if parts else 0.0


def _permissions_similarity(orig: dict, cand: dict) -> float:
    """Jaccard similarity of permission sets."""
    a, b = set(orig.get("permissions") or []), set(cand.get("permissions") or [])
    if not a and not b:
        return 1.0
    return round(len(a & b) / max(len(a | b), 1), 4)


def get_apk_object(path: str):
    """Helper for other analyzers (similarity/dex-risk) to reuse the parsed APK without re-parsing."""
    return APK(path)
