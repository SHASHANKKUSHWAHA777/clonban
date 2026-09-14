"""
Identity Analyzer (Phase 3)

Extracts package identity from both APKs and scores how similar/related
they are. A matching certificate is strong evidence of common origin; a
different certificate is evidence of re-signing, NOT automatic proof of
cloning (legitimate apps get re-signed too, e.g. by app stores).
"""
import logging
import re
from difflib import SequenceMatcher

from androguard.core.apk import APK

logger = logging.getLogger("clonedetector.identity")


def _extract_apk_info(path: str) -> dict:
    info = {
        "package_name": None, "app_label": None, "version_name": None,
        "version_code": None, "min_sdk": None, "target_sdk": None,
        "permissions": [], "activities": [], "services": [],
        "receivers": [], "providers": [],
        "cert_sha256": None, "cert_subject": None, "cert_issuer": None,
        "icon_path": None, "is_valid": True, "parse_error": None,
    }
    try:
        apk = APK(path)
        info["package_name"] = apk.get_package()
        info["app_label"] = apk.get_app_name()
        info["version_name"] = apk.get_androidversion_name()
        info["version_code"] = apk.get_androidversion_code()
        info["min_sdk"] = _safe_int(apk.get_min_sdk_version())
        info["target_sdk"] = _safe_int(apk.get_target_sdk_version())
        info["permissions"] = apk.get_permissions() or []
        info["activities"] = apk.get_activities() or []
        info["services"] = apk.get_services() or []
        info["receivers"] = apk.get_receivers() or []
        info["providers"] = apk.get_providers() or []

        certs = apk.get_certificates()
        if certs:
            cert = certs[0]
            info["cert_sha256"] = cert.sha256.hex() if hasattr(cert, "sha256") else None
            try:
                info["cert_subject"] = str(cert.subject)
                info["cert_issuer"] = str(cert.issuer)
            except Exception:
                pass

        icon_name = apk.get_app_icon()
        info["_apk_obj"] = apk  # kept in-process only, stripped before return
        info["_icon_name"] = icon_name
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


def _token_similarity(a: str, b: str) -> float:
    """Package name similarity: exact match, namespace overlap, and edit distance blended."""
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0

    tokens_a, tokens_b = set(a.split(".")), set(b.split("."))
    jaccard = len(tokens_a & tokens_b) / max(len(tokens_a | tokens_b), 1)

    edit_ratio = SequenceMatcher(None, a, b).ratio()

    # Reward candidate packages that just append/prepend a suffix to the
    # original namespace, a very common cloning trick (e.g. com.bank.app2)
    suffix_boost = 0.0
    if a in b or b in a:
        suffix_boost = 0.15

    score = 0.5 * jaccard + 0.4 * edit_ratio + suffix_boost
    return round(min(score, 1.0), 4)


def _manifest_similarity(orig: dict, cand: dict) -> float:
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
    a, b = set(orig.get("permissions") or []), set(cand.get("permissions") or [])
    if not a and not b:
        return 1.0
    return round(len(a & b) / max(len(a | b), 1), 4)


def analyze(original_path: str, candidate_path: str) -> dict:
    findings = []

    orig = _extract_apk_info(original_path)
    cand = _extract_apk_info(candidate_path)

    if not orig["is_valid"] or not cand["is_valid"]:
        return {
            "certificate_score": 0.0, "certificate_match": False,
            "package_score": 0.0, "manifest_score": 0.0, "permissions_score": 0.0,
            "findings": [{"type": "PARSE_ERROR", "severity": "high",
                           "evidence": f"original_error={orig.get('parse_error')} candidate_error={cand.get('parse_error')}"}],
            "apks": {"original": _clean(orig), "candidate": _clean(cand)},
        }

    cert_match = bool(orig["cert_sha256"] and cand["cert_sha256"] and orig["cert_sha256"] == cand["cert_sha256"])
    certificate_score = 1.0 if cert_match else 0.10
    if not cert_match:
        findings.append({
            "type": "CERT_MISMATCH", "severity": "medium",
            "evidence": "Signing certificates differ — evidence of re-signing, not automatic proof of cloning.",
        })

    package_score = _token_similarity(orig["package_name"], cand["package_name"])
    if orig["package_name"] == cand["package_name"] and not cert_match:
        findings.append({
            "type": "SAME_PACKAGE_DIFFERENT_CERT", "severity": "high",
            "evidence": "Identical package name but different signing certificate — classic impersonation pattern.",
        })

    manifest_score = _manifest_similarity(orig, cand)
    permissions_score = _permissions_similarity(orig, cand)

    return {
        "certificate_score": certificate_score,
        "certificate_match": cert_match,
        "package_score": package_score,
        "manifest_score": manifest_score,
        "permissions_score": permissions_score,
        "findings": findings,
        "apks": {"original": _clean(orig), "candidate": _clean(cand)},
    }


def _clean(info: dict) -> dict:
    return {k: v for k, v in info.items() if not k.startswith("_")}


def get_apk_object(path: str):
    """Helper for other analyzers (similarity/dex-risk) to reuse the parsed APK without re-parsing."""
    return APK(path)
