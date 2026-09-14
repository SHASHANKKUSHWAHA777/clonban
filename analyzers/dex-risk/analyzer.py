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

# ---------------------------------------------------------------------------
# Sensitive API Clusters — groups of framework API patterns that perform
# security-relevant operations. Membership overlap in these clusters is
# weighted more heavily than generic "app uses java.lang.String".
# ---------------------------------------------------------------------------

SENSITIVE_API_CLUSTERS = {
    "crypto": [
        "Ljavax/crypto/", "Ljava/security/", "Ljavax/net/ssl/",
    ],
    "network": [
        "Ljava/net/", "Lorg/apache/http/", "Lokhttp3/", "Landroid/net/",
    ],
    "sms_telephony": [
        "Landroid/telephony/SmsManager", "Landroid/telephony/TelephonyManager",
        "SEND_SMS", "READ_SMS", "RECEIVE_SMS",
    ],
    "reflection_dynamic": [
        "Ljava/lang/reflect/", "Ldalvik/system/DexClassLoader",
        "Ldalvik/system/PathClassLoader", "Ldalvik/system/InMemoryDex",
    ],
    "device_admin": [
        "Landroid/app/admin/DeviceAdminReceiver", "BIND_DEVICE_ADMIN",
    ],
    "accessibility": [
        "Landroid/accessibilityservice/", "BIND_ACCESSIBILITY_SERVICE",
    ],
    "content_provider": [
        "Landroid/content/ContentResolver;->query",
        "Landroid/content/ContentResolver;->insert",
        "Landroid/content/ContentResolver;->delete",
    ],
    "camera_media": [
        "Landroid/hardware/Camera", "Landroid/media/MediaRecorder",
        "Landroid/hardware/camera2/",
    ],
    "location": [
        "Landroid/location/LocationManager", "ACCESS_FINE_LOCATION",
        "ACCESS_COARSE_LOCATION",
    ],
    "webview": [
        "Landroid/webkit/WebView", "Landroid/webkit/JavascriptInterface",
    ],
}

# Common / low-signal framework classes that almost every app references.
# These receive reduced weight in the weighted Jaccard to avoid inflating
# similarity between unrelated apps.

COMMON_LOW_SIGNAL_PREFIXES = [
    "Ljava/lang/String", "Ljava/lang/Object", "Ljava/lang/Integer",
    "Ljava/lang/Boolean", "Ljava/lang/Long", "Ljava/lang/Float",
    "Ljava/lang/Double", "Ljava/lang/StringBuilder", "Ljava/lang/Exception",
    "Ljava/lang/Throwable", "Ljava/lang/Class", "Ljava/lang/System",
    "Ljava/util/List", "Ljava/util/Map", "Ljava/util/Set",
    "Ljava/util/ArrayList", "Ljava/util/HashMap", "Ljava/util/HashSet",
    "Ljava/util/Iterator", "Ljava/util/Collections",
    "Ljava/io/InputStream", "Ljava/io/OutputStream",
    "Landroid/os/Bundle", "Landroid/os/Handler",
    "Landroid/content/Context", "Landroid/content/Intent",
    "Landroid/view/View", "Landroid/util/Log",
    "Landroid/app/Activity", "Landroid/widget/TextView",
    "Landroid/widget/Button",
]

# Weights: low-signal classes get 0.2, sensitive clusters get 3.0, everything
# else gets 1.0.
WEIGHT_LOW_SIGNAL = 0.2
WEIGHT_SENSITIVE = 3.0
WEIGHT_DEFAULT = 1.0


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
    """Returns (class_count, method_count, external_api_classes, external_api_methods, permissions, raw_dex)."""
    a, d_list, dx = AnalyzeAPK(apk_path)

    class_count = sum(len(list(d.get_classes())) for d in d_list)
    method_count = sum(len(list(d.get_methods())) for d in d_list)

    external_api_classes = set()
    external_api_methods = set()
    try:
        for ext_class in dx.get_external_classes():
            class_name = str(ext_class.get_vm_class().get_name())
            external_api_classes.add(class_name)
            # Extract method-level references for finer-grained comparison
            try:
                for method in ext_class.get_vm_class().get_methods():
                    method_sig = f"{class_name}->{method.get_name()}"
                    external_api_methods.add(method_sig)
            except Exception:
                pass  # some external classes may not enumerate methods cleanly
    except Exception:
        logger.warning("external class extraction failed for %s", apk_path, exc_info=True)

    permissions = set(a.get_permissions() or [])

    raw_dex = b""
    try:
        raw_dex = d_list[0].get_buff() if d_list else b""
    except Exception:
        pass

    return class_count, method_count, external_api_classes, external_api_methods, permissions, raw_dex


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


def _api_weight(api_name: str) -> float:
    """Return a weight for the given API name based on signal value.

    Low-signal ubiquitous classes (String, Object, List, etc.) are down-weighted
    to 0.2; APIs matching sensitive clusters are boosted to 3.0; everything else
    gets 1.0.
    """
    for prefix in COMMON_LOW_SIGNAL_PREFIXES:
        if api_name.startswith(prefix):
            return WEIGHT_LOW_SIGNAL
    for cluster_patterns in SENSITIVE_API_CLUSTERS.values():
        for pattern in cluster_patterns:
            if pattern in api_name:
                return WEIGHT_SENSITIVE
    return WEIGHT_DEFAULT


def _weighted_api_similarity(apis_a: set, apis_b: set) -> float:
    """Weighted Jaccard similarity — rare/sensitive APIs contribute more than
    ubiquitous classes like java.lang.String."""
    all_apis = apis_a | apis_b
    if not all_apis:
        return 0.0
    num = 0.0
    den = 0.0
    for api in all_apis:
        w = _api_weight(api)
        in_a = 1.0 if api in apis_a else 0.0
        in_b = 1.0 if api in apis_b else 0.0
        num += w * min(in_a, in_b)
        den += w * max(in_a, in_b)
    return round(num / den, 4) if den > 0 else 0.0


def _sensitive_cluster_similarity(apis_a: set, apis_b: set) -> float:
    """Compare which sensitive API clusters each APK touches.

    Two APKs that both use crypto + SMS + reflection but different generic APIs
    should score high here, because the *functional capability surface* matches.
    """
    def _cluster_membership(apis: set) -> set:
        clusters = set()
        for cluster_name, patterns in SENSITIVE_API_CLUSTERS.items():
            for api in apis:
                if any(p in api for p in patterns):
                    clusters.add(cluster_name)
                    break
        return clusters

    clusters_a = _cluster_membership(apis_a)
    clusters_b = _cluster_membership(apis_b)
    if not clusters_a and not clusters_b:
        return 0.0
    return round(len(clusters_a & clusters_b) / max(len(clusters_a | clusters_b), 1), 4)


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
    class_a, method_a, api_classes_a, api_methods_a, perms_a, raw_a = _analyze_single(original_path)
    class_b, method_b, api_classes_b, api_methods_b, perms_b, raw_b = _analyze_single(candidate_path)

    # Weighted API similarity (class-level, with sensitive boosting)
    weighted_api_sim = _weighted_api_similarity(api_classes_a, api_classes_b)

    # Method-level similarity (finer grained but same weighting logic)
    method_api_sim = _weighted_api_similarity(api_methods_a, api_methods_b)

    # Sensitive cluster overlap
    cluster_sim = _sensitive_cluster_similarity(api_classes_a, api_classes_b)

    ssdeep_score = _ssdeep_score(raw_a, raw_b)

    # Legacy unweighted Jaccard for backward-compatible output field
    legacy_api_similarity = round(len(api_classes_a & api_classes_b) / max(len(api_classes_a | api_classes_b), 1), 4) \
        if (api_classes_a or api_classes_b) else 0.0

    # dex_score blends the obfuscation-resistant API-reference similarity
    # with the fuzzy binary hash when available; falls back to API+cluster only.
    if ssdeep_score is not None:
        dex_score = round(
            0.35 * weighted_api_sim +
            0.20 * method_api_sim +
            0.25 * ssdeep_score +
            0.20 * cluster_sim,
            4
        )
    else:
        # Without ssdeep, redistribute its weight to the other signals
        dex_score = round(
            0.45 * weighted_api_sim +
            0.25 * method_api_sim +
            0.30 * cluster_sim,
            4
        )

    findings = _run_findings("original", perms_a, api_classes_a) + _run_findings("candidate", perms_b, api_classes_b)

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
        "api_call_similarity": legacy_api_similarity,
        "weighted_api_similarity": weighted_api_sim,
        "method_api_similarity": method_api_sim,
        "cluster_similarity": cluster_sim,
        "findings": findings,
    }
