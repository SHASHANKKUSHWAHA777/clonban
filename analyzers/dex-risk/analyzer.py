"""
DEX + Risk Analyzer (Phase 5)

Two separate jobs bundled in one service, as specced:

1. Structural DEX similarity — obfuscation-resistant by design: we compare
   sets of *referenced Android framework API calls* (which don't change
   under simple class/method renaming) plus class/method counts and an
   ssdeep fuzzy hash of the raw classes.dex bytes.

2. Suspicious behavior indicators — permission + API-reference based
   pattern matching, each returned with severity and evidence. Presence of
   one indicator is never treated as proof of malware (project rule).
"""
import logging

try:
    import ssdeep
    HAVE_SSDEEP = True
except Exception:  # pragma: no cover - documented fallback
    HAVE_SSDEEP = False

from androguard.misc import AnalyzeAPK

logger = logging.getLogger("clonedetector.dexrisk")

# (indicator_type, severity, description, matcher)
# matcher receives (permissions:set[str], external_api_names:set[str])
SUSPICIOUS_RULES = [
    ("ACCESSIBILITY_SERVICE", "medium",
     "App declares/uses an AccessibilityService, which can read screen content and simulate input.",
     lambda perms, apis: any("BIND_ACCESSIBILITY_SERVICE" in p for p in perms)
     or any("accessibilityservice/AccessibilityService" in a for a in apis)),

    ("SMS_ACCESS", "high",
     "App requests SMS read/send/receive permissions — common in banking-trojan clones for OTP theft.",
     lambda perms, apis: any(p.endswith(("READ_SMS", "SEND_SMS", "RECEIVE_SMS")) for p in perms)),

    ("OVERLAY_PERMISSION", "high",
     "App requests SYSTEM_ALERT_WINDOW (draw-over-other-apps), commonly used for phishing overlays.",
     lambda perms, apis: any(p.endswith("SYSTEM_ALERT_WINDOW") for p in perms)),

    ("BOOT_PERSISTENCE", "low",
     "App requests RECEIVE_BOOT_COMPLETED to auto-start after device reboot.",
     lambda perms, apis: any(p.endswith("RECEIVE_BOOT_COMPLETED") for p in perms)),

    ("DEVICE_ADMIN", "high",
     "App requests device-admin binding, which resists uninstallation and can lock the device.",
     lambda perms, apis: any(p.endswith("BIND_DEVICE_ADMIN") for p in perms)
     or any("app/admin/DeviceAdminReceiver" in a for a in apis)),

    ("DYNAMIC_CODE_LOADING", "high",
     "App references DexClassLoader/PathClassLoader, allowing code to be loaded at runtime outside static review.",
     lambda perms, apis: any("dalvik/system/DexClassLoader" in a or "dalvik/system/PathClassLoader" in a for a in apis)),

    ("WEBVIEW_JS_INTERFACE", "medium",
     "App references WebView JavascriptInterface bindings, a common vector for WebView-based abuse.",
     lambda perms, apis: any("webkit/JavascriptInterface" in a for a in apis)),

    ("SUSPICIOUS_NETWORK_API", "low",
     "App references low-level raw socket APIs directly rather than standard HTTP client libraries.",
     lambda perms, apis: any(a.startswith("Ljava/net/Socket;") for a in apis)),
]


def _analyze_single(apk_path: str):
    """Returns (class_count, method_count, external_api_set, permissions_set, raw_dex_bytes)."""
    a, d_list, dx = AnalyzeAPK(apk_path)

    class_count = sum(len(list(d.get_classes())) for d in d_list)
    method_count = sum(len(list(d.get_methods())) for d in d_list)

    external_apis = set()
    try:
        for ext_class in dx.get_external_classes():
            external_apis.add(str(ext_class.get_vm_class().get_name()))
    except Exception:
        logger.warning("external class extraction failed for %s", apk_path, exc_info=True)

    permissions = set(a.get_permissions() or [])

    raw_dex = b""
    try:
        raw_dex = d_list[0].get_buff() if d_list else b""
    except Exception:
        pass

    return class_count, method_count, external_apis, permissions, raw_dex


def _ssdeep_score(raw_a: bytes, raw_b: bytes) -> float | None:
    if not HAVE_SSDEEP or not raw_a or not raw_b:
        return None
    try:
        hash_a = ssdeep.hash(raw_a)
        hash_b = ssdeep.hash(raw_b)
        similarity = ssdeep.compare(hash_a, hash_b)  # 0-100
        return round(similarity / 100.0, 4)
    except Exception:
        logger.warning("ssdeep comparison failed", exc_info=True)
        return None


def _api_call_similarity(apis_a: set, apis_b: set) -> float:
    if not apis_a and not apis_b:
        return 0.0
    return round(len(apis_a & apis_b) / max(len(apis_a | apis_b), 1), 4)


def _run_findings(label: str, permissions: set, apis: set) -> list[dict]:
    findings = []
    for ftype, severity, description, matcher in SUSPICIOUS_RULES:
        try:
            if matcher(permissions, apis):
                findings.append({
                    "type": ftype, "severity": severity,
                    "evidence": description, "source_apk": label,
                })
        except Exception:
            continue
    return findings


def analyze(original_path: str, candidate_path: str) -> dict:
    class_a, method_a, apis_a, perms_a, raw_a = _analyze_single(original_path)
    class_b, method_b, apis_b, perms_b, raw_b = _analyze_single(candidate_path)

    api_similarity = _api_call_similarity(apis_a, apis_b)
    ssdeep_score = _ssdeep_score(raw_a, raw_b)

    # dex_score blends the obfuscation-resistant API-reference similarity
    # with the fuzzy binary hash when available; falls back to API-only.
    if ssdeep_score is not None:
        dex_score = round(0.6 * api_similarity + 0.4 * ssdeep_score, 4)
    else:
        dex_score = api_similarity

    findings = _run_findings("original", perms_a, apis_a) + _run_findings("candidate", perms_b, apis_b)

    # Malware risk is driven by findings on the CANDIDATE only, weighted by
    # severity — the original app's own behavior is not itself "risk".
    severity_weight = {"low": 0.15, "medium": 0.35, "high": 0.6}
    candidate_findings = [f for f in findings if f["source_apk"] == "candidate"]
    if candidate_findings:
        malware_risk = min(1.0, sum(severity_weight.get(f["severity"], 0.2) for f in candidate_findings))
    else:
        malware_risk = 0.0

    return {
        "dex_score": dex_score,
        "malware_risk": round(malware_risk, 4),
        "class_count_original": class_a,
        "class_count_candidate": class_b,
        "method_count_original": method_a,
        "method_count_candidate": method_b,
        "ssdeep_score": ssdeep_score,
        "api_call_similarity": api_similarity,
        "findings": findings,
    }
