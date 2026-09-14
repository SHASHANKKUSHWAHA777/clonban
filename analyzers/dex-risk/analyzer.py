"""
DEX + Risk Analyzer (V3 — Phase 5)

Two separate, independently-degradable analyses bundled in one service:

A. BYTECODE RELATIONSHIP EVIDENCE
   - DEX file discovery (classes.dex, classes2.dex, ...)
   - TLSH fuzzy hashing (ssdeep fallback) for bytecode similarity
   - API reference similarity (obfuscation-resistant fallback signal)

B. SECURITY-CAPABILITY DEVIATION EVIDENCE
   - Permission diff (baseline vs candidate) → risk score
   - Exported component diff → findings
   - Deterministic risk rules with exact contributions

V3 contract (additive — legacy fields kept for backward compatibility):
{
  "service": "dex-risk",
  "bytecode_similarity": 0.0,      # float [0,1] or null
  "malware_risk_score": 0,          # int 0-100
  "risk_findings": [
    {"finding": "...", "category": "PERMISSION|COMPONENT",
     "severity": "low|medium|high", "contribution": int,
     "baseline_present": bool, "candidate_present": bool,
     "evidence": "..."}
  ],
  "dex_files_baseline": [...],
  "dex_files_candidate": [...],
  "dex_count_baseline": int,
  "dex_count_candidate": int,
  "errors": [{"stage": "...", "message": "..."}],
}

Legacy fields (for backward compat with scoring engine + tasks.py):
  dex_score, malware_risk, class_count_original/candidate,
  method_count_original/candidate, ssdeep_score, api_call_similarity,
  findings (old format with type/severity/evidence/source_apk)
"""
import logging
import os
import sys

from androguard.core.apk import APK

logger = logging.getLogger("clonedetector.dexrisk")

# --- Load sibling modules ---
# The dex-risk directory name has a hyphen, so it's not a valid Python
# package. We add this directory to sys.path so sibling modules can be
# imported by simple name (dex_extractor, tlsh_similarity, etc.).
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from dex_extractor import extract_all_dex_bytes, normalize_dex_bytes
from tlsh_similarity import calculate_dex_fuzzy_similarity
from permissions import calculate_permission_risk, normalize_permission_list
from components import extract_components, compare_exported_components, detect_suspicious_components
from risk_engine import merge_findings, calculate_risk_score


def _analyze_single_dex(apk_path: str) -> dict:
    """
    Analyze a single APK's DEX content using a single androguard parse.

    Returns:
      {
        "dex_files": list[str],
        "dex_count": int,
        "class_count": int,
        "method_count": int,
        "external_apis": set[str],
        "permissions": list[str],
        "components": list[dict],
        "dex_bytes": bytes,
        "dex_bytes_map": dict,
        "errors": list[str],
        "apk_obj": APK or None,
      }
    """
    result = {
        "dex_files": [],
        "dex_count": 0,
        "class_count": 0,
        "method_count": 0,
        "external_apis": set(),
        "permissions": [],
        "components": [],
        "dex_bytes": b"",
        "dex_bytes_map": {},
        "errors": [],
        "apk_obj": None,
    }

    try:
        apk = APK(apk_path)
        result["apk_obj"] = apk
        result["permissions"] = apk.get_permissions() or []
        result["components"] = extract_components(apk)
    except Exception as e:
        result["errors"].append(f"APK parse error: {e}")
        logger.exception("Failed to parse APK %s", apk_path)
        return result

    # DEX discovery via the already-parsed APK's ZIP archive
    try:
        dex_info = extract_all_dex_bytes(apk)
        result["dex_files"] = dex_info["dex_files"]
        result["dex_count"] = dex_info["dex_count"]
        result["dex_bytes_map"] = dex_info["bytes"]
        result["dex_bytes"] = normalize_dex_bytes(dex_info["bytes"])

        for err in dex_info["errors"]:
            result["errors"].append(err["message"])
    except Exception:
        logger.warning("DEX discovery/extraction failed for %s", apk_path, exc_info=True)

    # Class and method counts via androguard DEX objects
    try:
        from androguard.core.dex import DEX
        # Get raw DEX bytes from the APK's ZIP archive
        import zipfile as _zf
        apk_path_attr = getattr(apk, "filename", None) or getattr(apk, "_filename", None) or apk_path
        with _zf.ZipFile(apk_path_attr, "r") as zf:
            for name in dex_info["dex_files"]:
                raw_dex = zf.read(name)
                try:
                    dex_obj = DEX(raw_dex)
                    result["class_count"] += len(list(dex_obj.get_classes()))
                    result["method_count"] += len(list(dex_obj.get_methods()))
                except Exception:
                    pass
    except Exception:
        logger.warning("Class/method counting failed for %s", apk_path, exc_info=True)

    # External API references (obfuscation-resistant signal)
    try:
        from androguard.misc import AnalyzeAPK
        _, _, dx = AnalyzeAPK(apk_path)
        for ext_class in dx.get_external_classes():
            try:
                result["external_apis"].add(str(ext_class.get_vm_class().get_name()))
            except Exception:
                pass
    except Exception:
        logger.warning("External API extraction failed for %s", apk_path, exc_info=True)

    return result


def _api_call_similarity(apis_a: set, apis_b: set) -> float:
    """Jaccard similarity of external API references (obfuscation-resistant)."""
    if not apis_a and not apis_b:
        return 0.0
    return round(len(apis_a & apis_b) / max(len(apis_a | apis_b), 1), 4)


def _legacy_findings_transform(risk_findings: list) -> list[dict]:
    """
    Convert V3 risk_findings format to legacy format for backward compat.
    V3: {"finding", "category", "severity", "contribution", "evidence", ...}
    Legacy: {"type", "severity", "evidence", "source_apk"}
    """
    legacy = []
    for f in risk_findings:
        legacy.append({
            "type": f.get("finding", "UNKNOWN"),
            "severity": f.get("severity", "low"),
            "evidence": f.get("evidence", ""),
            "source_apk": "candidate",
        })
    return legacy


def analyze(original_path: str, candidate_path: str) -> dict:
    """
    Analyze two APKs for DEX structural similarity and security risk.

    Stages degrade independently — a TLSH failure does not erase permission risk.
    """
    errors = []

    # ---- DEX extraction (independent per APK) ----
    try:
        base_data = _analyze_single_dex(original_path)
    except Exception as e:
        errors.append({"stage": "DEX_EXTRACT_BASELINE", "message": str(e)})
        base_data = {
            "dex_files": [], "dex_count": 0, "class_count": 0,
            "method_count": 0, "external_apis": set(),
            "permissions": [], "components": [],
            "dex_bytes": b"", "dex_bytes_map": {},
            "errors": [str(e)], "apk_obj": None,
        }

    try:
        cand_data = _analyze_single_dex(candidate_path)
    except Exception as e:
        errors.append({"stage": "DEX_EXTRACT_CANDIDATE", "message": str(e)})
        cand_data = {
            "dex_files": [], "dex_count": 0, "class_count": 0,
            "method_count": 0, "external_apis": set(),
            "permissions": [], "components": [],
            "dex_bytes": b"", "dex_bytes_map": {},
            "errors": [str(e)], "apk_obj": None,
        }

    for e in base_data.get("errors", []):
        errors.append({"stage": "DEX_EXTRACT_BASELINE", "message": e})
    for e in cand_data.get("errors", []):
        errors.append({"stage": "DEX_EXTRACT_CANDIDATE", "message": e})

    # ---- Bytecode similarity (TLSH / ssdeep / API reference) ----
    bytecode_similarity = None

    # TLSH / ssdeep fuzzy hashing
    fuzzy_result = calculate_dex_fuzzy_similarity(
        base_data["dex_bytes"], cand_data["dex_bytes"]
    )
    if not fuzzy_result["available"]:
        errors.append({
            "stage": "TLSH",
            "message": fuzzy_result.get("error", "Fuzzy hashing unavailable"),
        })

    # API call similarity (obfuscation-resistant fallback)
    api_sim = _api_call_similarity(
        base_data["external_apis"], cand_data["external_apis"]
    )

    # Merge: use fuzzy similarity when available, API similarity as fallback.
    # Both are reported separately.
    if fuzzy_result["available"] and fuzzy_result["similarity"] is not None:
        # Weight: 60% fuzzy hash, 40% API similarity when both available.
        # When only API sim available, use that directly.
        if api_sim is not None and api_sim > 0:
            bytecode_similarity = round(0.6 * fuzzy_result["similarity"] + 0.4 * api_sim, 4)
        else:
            bytecode_similarity = fuzzy_result["similarity"]
    elif api_sim is not None and api_sim > 0:
        bytecode_similarity = api_sim
        errors.append({
            "stage": "TLSH",
            "message": "Fuzzy hashing unavailable; using API reference similarity only.",
        })
    else:
        bytecode_similarity = None
        if not fuzzy_result["available"]:
            errors.append({
                "stage": "TLSH",
                "message": "Neither TLSH/ssdeep nor API reference similarity could be computed.",
            })

    # ---- Permission risk (differential: only NEW capabilities) ----
    perm_risk = calculate_permission_risk(
        base_data["permissions"], cand_data["permissions"]
    )

    # ---- Exported component diff ----
    exported_findings = compare_exported_components(
        base_data["components"], cand_data["components"]
    )

    # ---- Suspicious component detection (reporting only, 0 contribution) ----
    suspicious_comp = detect_suspicious_components(
        cand_data["components"], cand_data["permissions"]
    )

    # ---- Merge all risk findings ----
    risk_findings = merge_findings(
        perm_risk["findings"], exported_findings, suspicious_comp
    )

    # ---- Compute final malware risk score ----
    risk_result = calculate_risk_score(risk_findings)
    malware_risk_score = risk_result["score"]

    # ---- Build legacy fields for backward compatibility ----
    legacy_findings = _legacy_findings_transform(risk_findings)

    # Legacy malware_risk is a float [0, 1]; V3 malware_risk_score is int [0, 100].
    legacy_malware_risk = round(malware_risk_score / 100.0, 4)

    # Legacy ssdeep score (if TLSH fallback was ssdeep)
    legacy_ssdeep = fuzzy_result["similarity"] if fuzzy_result.get("algorithm") == "SSDEEP" else None

    # ---- Build V3 result ----
    return {
        # V3 contract fields
        "service": "dex-risk",
        "bytecode_similarity": bytecode_similarity,
        "malware_risk_score": malware_risk_score,
        "risk_findings": risk_findings,
        "dex_files_baseline": base_data["dex_files"],
        "dex_files_candidate": cand_data["dex_files"],
        "dex_count_baseline": base_data["dex_count"],
        "dex_count_candidate": cand_data["dex_count"],
        "errors": errors,

        # Additional evidence
        "dex_extraction": {
            "baseline": {
                "dex_files": base_data["dex_files"],
                "dex_count": base_data["dex_count"],
                "total_bytes": sum(len(v) for v in base_data["dex_bytes_map"].values()),
                "success": len(base_data["dex_files"]) > 0,
            },
            "candidate": {
                "dex_files": cand_data["dex_files"],
                "dex_count": cand_data["dex_count"],
                "total_bytes": sum(len(v) for v in cand_data["dex_bytes_map"].values()),
                "success": len(cand_data["dex_files"]) > 0,
            },
        },
        "fuzzy_hash_info": {
            "algorithm": fuzzy_result.get("algorithm"),
            "available": fuzzy_result.get("available"),
            "distance": fuzzy_result.get("distance"),
            "similarity": fuzzy_result.get("similarity"),
            "error": fuzzy_result.get("error"),
        },
        "permission_findings": perm_risk["findings"],
        "component_findings": exported_findings,
        "permissions_baseline": normalize_permission_list(base_data["permissions"]),
        "permissions_candidate": normalize_permission_list(cand_data["permissions"]),

        # Legacy fields (for backward compat with scoring engine + tasks.py)
        "dex_score": bytecode_similarity if bytecode_similarity is not None else 0.0,
        "malware_risk": legacy_malware_risk,
        "class_count_original": base_data["class_count"] if base_data["class_count"] > 0 else None,
        "class_count_candidate": cand_data["class_count"] if cand_data["class_count"] > 0 else None,
        "method_count_original": base_data["method_count"] if base_data["method_count"] > 0 else None,
        "method_count_candidate": cand_data["method_count"] if cand_data["method_count"] > 0 else None,
        "ssdeep_score": legacy_ssdeep,
        "api_call_similarity": api_sim,
        "findings": legacy_findings,
    }


def get_apk_object(path: str):
    """Helper for other analyzers to reuse the parsed APK without re-parsing."""
    return APK(path)
