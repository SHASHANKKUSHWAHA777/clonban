"""
Manifest extraction (Phase 3.4).

Extracts package metadata, permissions, components (activities, services,
receivers, providers), and exported state from a parsed androguard APK.
Produces structured manifest findings for identity-level signal evidence.
"""
import logging
import re
from typing import Any, Optional

from androguard.core.apk import APK

logger = logging.getLogger("clonedetector.identity.manifest")

PERMISSION_PATTERN = re.compile(r"^android\.permission\..+")


def _safe_int(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def extract_apk_metadata(apk: APK, label: str = "APK") -> dict:
    """
    Extract all identity-level metadata from a parsed APK.

    Returns a dict consumed by:
      - the identity analyzer (for diffing baseline vs candidate)
      - tasks.py (persisted to ApkMetadata DB columns)

    All fields are optional: missing data = None, not 0.
    """
    info = {
        "package_name": None,
        "app_label": None,
        "version_name": None,
        "version_code": None,
        "min_sdk": None,
        "target_sdk": None,
        "permissions": [],
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "exported_components": [],
        "cert_sha256": None,
        "cert_subject": None,
        "cert_issuer": None,
        "cert_signer_count": None,
        "icon_path": None,
        "is_valid": True,
        "parse_error": None,
        "_apk_obj": None,
        "_icon_name": None,
    }
    if apk is None:
        info["is_valid"] = False
        info["parse_error"] = f"{label}: APK object is None"
        return info

    try:
        info["package_name"] = apk.get_package()
        info["app_label"] = apk.get_app_name()
        info["version_name"] = apk.get_androidversion_name()
        info["version_code"] = apk.get_androidversion_code()
        info["min_sdk"] = _safe_int(apk.get_min_sdk_version())
        info["target_sdk"] = _safe_int(apk.get_target_sdk_version())

        perms = apk.get_permissions() or []
        info["permissions"] = sorted(normalize_permission(p) for p in perms)

        info["activities"] = sorted(apk.get_activities() or [])
        info["services"] = sorted(apk.get_services() or [])
        info["receivers"] = sorted(apk.get_receivers() or [])
        info["providers"] = sorted(apk.get_providers() or [])

        info["exported_components"] = extract_exported_components(apk)

        certs = apk.get_certificates() or []
        if certs:
            cert = certs[0]
            if hasattr(cert, "sha256"):
                info["cert_sha256"] = cert.sha256.hex() if cert.sha256 else None
            try:
                info["cert_subject"] = str(cert.subject)
            except Exception:
                pass
            try:
                info["cert_issuer"] = str(cert.issuer)
            except Exception:
                pass
            info["cert_signer_count"] = len(certs)

        try:
            info["_icon_name"] = apk.get_app_icon()
        except Exception:
            pass

        info["_apk_obj"] = apk
    except Exception as e:
        logger.exception("Failed to parse APK %s", label)
        info["is_valid"] = False
        info["parse_error"] = str(e)

    return info


def normalize_permission(name: str) -> str:
    """Normalize Android permission names by stripping 'android.permission.' prefix."""
    if not name:
        return name
    if name.startswith("android.permission."):
        return name[len("android.permission."):]
    return name


def extract_exported_components(apk: APK) -> list[dict]:
    """
    Extract components with their exported state from the parsed APK.

    Uses androguard's get_activities(), get_services(), etc. combined with
    manifest parsing where available. Returns a list of dicts:
      {"name": str, "type": "activity|service|receiver|provider", "exported": bool|None}
    """
    components = []
    if apk is None:
        return components

    type_map = [
        ("activity", apk.get_activities),
        ("service", apk.get_services),
        ("receiver", apk.get_receivers),
        ("provider", apk.get_providers),
    ]

    for comp_type, getter in type_map:
        try:
            names = getter() or []
            for name in names:
                exported = _get_exported_state(apk, comp_type, name)
                components.append({
                    "name": name,
                    "type": comp_type,
                    "exported": exported,
                })
        except Exception:
            logger.warning("Could not extract %s list", comp_type, exc_info=True)

    return components


def _get_exported_state(apk: APK, comp_type: str, name: str) -> Optional[bool]:
    """
    Try to determine the exported state of a component from the manifest.
    Returns True/False/None (None = unknown).
    """
    # androguard's APK doesn't directly expose per-component exported state
    # in a clean API; we attempt to read from the raw manifest XML.
    try:
        manifest = apk.get_manifest()
        if manifest and isinstance(manifest, dict):
            apps = manifest.get("application", {})
            if isinstance(apps, dict):
                comps = apps.get(comp_type + "s", {})
                if isinstance(comps, list):
                    for comp in comps:
                        if isinstance(comp, dict) and comp.get("name") == name:
                            exp = comp.get("exported")
                            if exp is not None:
                                return str(exp).lower() in ("true", "1")
                            return None
                        # Also check for "$" suffix (InnerClasses)
                        if isinstance(comp, dict):
                            comp_name = comp.get("name", "")
                            if comp_name == name or comp_name.endswith(name.split(".")[-1]):
                                exp = comp.get("exported")
                                if exp is not None:
                                    return str(exp).lower() in ("true", "1")
            elif isinstance(apps, list):
                for app in apps:
                    if isinstance(app, dict):
                        comps = app.get(comp_type + "s", {})
                        if isinstance(comps, list):
                            for comp in comps:
                                if isinstance(comp, dict) and comp.get("name") == name:
                                    exp = comp.get("exported")
                                    if exp is not None:
                                        return str(exp).lower() in ("true", "1")
    except Exception:
        pass
    return None


def _clean_metadata(info: dict) -> dict:
    """Strip internal fields before returning to callers."""
    return {k: v for k, v in info.items() if not k.startswith("_")}


def build_manifest_findings(baseline: dict, candidate: dict) -> list[dict]:
    """
    Generate structured manifest findings comparing baseline vs candidate metadata.
    """
    findings = []

    # Package name comparison
    bp = baseline.get("package_name")
    cp = candidate.get("package_name")
    if bp and cp:
        if bp == cp:
            findings.append({
                "type": "PACKAGE_EXACT_MATCH",
                "severity": "INFO",
                "evidence": f"Identical package name: {bp}",
                "baseline": bp,
                "candidate": cp,
                "similarity": 1.0,
            })
        else:
            from analyzers.identity.package_similarity import compute_similarity
            sim = compute_similarity(bp, cp)
            if sim >= 0.6:
                findings.append({
                    "type": "PACKAGE_NEAR_MATCH",
                    "severity": "INFO",
                    "evidence": f"Package names are similar (similarity={sim:.2f})",
                    "baseline": bp,
                    "candidate": cp,
                    "similarity": sim,
                })
            elif sim < 0.3:
                findings.append({
                    "type": "PACKAGE_UNRELATED",
                    "severity": "INFO",
                    "evidence": f"Package names are unrelated (similarity={sim:.2f})",
                    "baseline": bp,
                    "candidate": cp,
                    "similarity": sim,
                })

    # Certificate fingerprint comparison (for manifest findings)
    bfp = baseline.get("cert_sha256")
    cfp = candidate.get("cert_sha256")
    if bfp is not None or cfp is not None:
        if bfp is not None and cfp is not None:
            if bfp.lower() == cfp.lower():
                findings.append({
                    "type": "CERTIFICATE_MATCH",
                    "severity": "INFO",
                    "evidence": f"Signing certificate SHA-256 matches: {bfp[:16]}...",
                })
            else:
                findings.append({
                    "type": "CERTIFICATE_MISMATCH",
                    "severity": "MEDIUM",
                    "evidence": "Signing certificates differ — evidence of re-signing, not automatic proof of cloning.",
                    "baseline": bfp[:16] + "..." if bfp else None,
                    "candidate": cfp[:16] + "..." if cfp else None,
                })

    # App label comparison
    bl = baseline.get("app_label")
    cl = candidate.get("app_label")
    if bl or cl:
        if bl == cl and bl is not None:
            findings.append({
                "type": "LABEL_MATCH",
                "severity": "INFO",
                "evidence": f"App label identical: '{bl}'",
            })
        elif bl != cl:
            findings.append({
                "type": "LABEL_DIFFERS",
                "severity": "INFO",
                "evidence": f"App label differs: baseline='{bl}', candidate='{cl}'",
                "baseline": bl,
                "candidate": cl,
            })

    # Version comparison
    bv = baseline.get("version_name")
    cv = candidate.get("version_name")
    bc = baseline.get("version_code")
    cc = candidate.get("version_code")
    if bv != cv:
        findings.append({
            "type": "VERSION_DIFFERS",
            "severity": "INFO",
            "evidence": f"Version name differs: {bv} vs {cv}",
            "baseline": bv,
            "candidate": cv,
        })
    if bc != cc:
        findings.append({
            "type": "VERSION_CODE_DIFFERS",
            "severity": "INFO",
            "evidence": f"Version code differs: {bc} vs {cc}",
            "baseline": bc,
            "candidate": cc,
        })

    # Missing label warning
    if cl is None and bp is not None:
        findings.append({
            "type": "MISSING_LABEL",
            "severity": "INFO",
            "evidence": f"Candidate app label is missing.",
        })

    return findings
