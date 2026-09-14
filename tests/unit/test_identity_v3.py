"""
Unit tests for the Identity Analyzer V3 contract.

Tests:
  - exact package match
  - renamed (near) package match
  - unrelated package
  - same certificate
  - different certificate
  - unknown certificate
  - malformed APK handling
  - missing label
  - permission diffing
  - null propagation for unavailable signals
"""
import importlib.util
import sys
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from analyzers.identity.certificate import (
    compare_certificates,
    SAME_SIGNER,
    DIFFERENT_SIGNER,
    UNKNOWN,
)
from analyzers.identity.package_similarity import (
    compute_similarity,
    classify_match_state,
    analyze_package_similarity,
    EXACT_MATCH,
    NEAR_MATCH,
    UNRELATED,
)
from analyzers.identity.manifest import (
    normalize_permission,
    build_manifest_findings,
)
from analyzers.common.apk_utils import normalize_fingerprint


# ---------------------------------------------------------------------------
# Package similarity tests
# ---------------------------------------------------------------------------

def test_exact_package_match():
    assert compute_similarity("com.example.bank", "com.example.bank") == 1.0


def test_renamed_package_scores_near_match():
    score = compute_similarity("com.example.bank", "com.example.bank2")
    assert score > 0.7
    assert classify_match_state("com.example.bank", "com.example.bank2", score) == NEAR_MATCH


def test_unrelated_packages_score_low():
    score = compute_similarity("com.bank.app", "org.example.weather")
    assert score < 0.3
    assert classify_match_state("com.bank.app", "org.example.weather", score) == UNRELATED


def test_package_match_state_exact():
    result = analyze_package_similarity("com.bank.app", "com.bank.app")
    assert result["match_state"] == EXACT_MATCH
    assert result["similarity"] == 1.0


def test_package_match_state_near():
    result = analyze_package_similarity("com.bank.app", "com.bank.appp")
    assert result["match_state"] == NEAR_MATCH
    assert result["similarity"] > 0.7


def test_package_match_state_unrelated():
    result = analyze_package_similarity("com.bank.app", "org.weather.forecast")
    assert result["match_state"] == UNRELATED
    assert result["similarity"] < 0.3


def test_package_similarity_null_when_missing():
    result = analyze_package_similarity("com.bank.app", None)
    assert result["similarity"] is None
    assert result["match_state"] == UNRELATED


def test_package_similarity_none_baseline():
    result = analyze_package_similarity(None, "com.bank.app")
    assert result["similarity"] is None
    assert result["match_state"] == UNRELATED


# ---------------------------------------------------------------------------
# Certificate tests
# ---------------------------------------------------------------------------

def test_same_signer_returns_1():
    info_b = {"sha256": "AA:BB:CC:DD", "subject": "CN=test", "issuer": "CN=test"}
    info_c = {"sha256": "aa:bb:cc:dd", "subject": "CN=test", "issuer": "CN=test"}
    result = compare_certificates(info_b, info_c)
    assert result["status"] == SAME_SIGNER
    assert result["score"] == 1.0


def test_different_signer_returns_0():
    info_b = {"sha256": "AA:BB:CC:DD", "subject": "CN=a", "issuer": "CN=a"}
    info_c = {"sha256": "EE:FF:00:11", "subject": "CN=b", "issuer": "CN=b"}
    result = compare_certificates(info_b, info_c)
    assert result["status"] == DIFFERENT_SIGNER
    assert result["score"] == 0.0
    # Must NOT be described as malware/clone
    assert "malware" not in result["evidence"].lower()
    assert "clone" not in result["evidence"].lower()


def test_unknown_when_both_missing():
    info_b = {"sha256": None, "subject": None, "issuer": None}
    info_c = {"sha256": None, "subject": None, "issuer": None}
    result = compare_certificates(info_b, info_c)
    assert result["status"] == UNKNOWN
    assert result["score"] is None


def test_unknown_when_one_missing():
    info_b = {"sha256": "AA:BB:CC:DD", "subject": "CN=test", "issuer": "CN=test"}
    info_c = {"sha256": None, "subject": None, "issuer": None}
    result = compare_certificates(info_b, info_c)
    assert result["status"] == UNKNOWN
    assert result["score"] is None


def test_fingerprint_normalization():
    fp = "AA:BB:CC:DD:EE:FF"
    assert normalize_fingerprint(fp) == "aabbccddeeff"
    assert normalize_fingerprint("AA BB CC DD") == "aabbccdd"
    assert normalize_fingerprint(None) is None
    assert normalize_fingerprint("") is None


# ---------------------------------------------------------------------------
# Permission normalization tests
# ---------------------------------------------------------------------------

def test_normalize_permission_strip_prefix():
    assert normalize_permission("android.permission.SEND_SMS") == "SEND_SMS"
    assert normalize_permission("SEND_SMS") == "SEND_SMS"


def test_normalize_permission_empty():
    assert normalize_permission(None) is None
    assert normalize_permission("") == ""


# ---------------------------------------------------------------------------
# APK validation / error handling tests
# ---------------------------------------------------------------------------

def _load_identity():
    """Load identity analyzer module via importlib (to handle path correctly)."""
    spec = importlib.util.spec_from_file_location(
        "identity_analyzer", str(ROOT / "analyzers" / "identity" / "analyzer.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_malformed_apk_returns_null_scores():
    """A corrupt/empty APK should return null scores, not 0.0."""
    import tempfile
    fd, tmp_path = tempfile.mkstemp(suffix=".apk")
    os.write(fd, b"not a valid zip file at all")
    os.close(fd)
    try:
        identity = _load_identity()
        result = identity.analyze(tmp_path, tmp_path)
        assert result["service"] == "identity"
        assert result["certificate_status"] == "UNKNOWN"
        assert result["certificate_identity_score"] is None
        assert len(result.get("errors", [])) > 0
    finally:
        os.unlink(tmp_path)


def test_nonexistent_apk_returns_error():
    identity = _load_identity()
    result = identity.analyze("/nonexistent/path/a.apk", "/nonexistent/path/b.apk")
    assert result["service"] == "identity"
    assert result["certificate_status"] == "UNKNOWN"
    assert result["certificate_identity_score"] is None
    assert len(result.get("errors", [])) > 0


def test_identity_contract_has_required_fields():
    """Verify the V3 identity contract fields are present in the output."""
    import tempfile
    import zipfile
    fd_b, path_b = tempfile.mkstemp(suffix=".apk")
    os.close(fd_b)
    fd_c, path_c = tempfile.mkstemp(suffix=".apk")
    os.close(fd_c)
    try:
        # Create minimal valid ZIPs
        with zipfile.ZipFile(path_b, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"\x00")
        with zipfile.ZipFile(path_c, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"\x00")

        identity = _load_identity()
        result = identity.analyze(path_b, path_c)
        # V3 required fields
        assert "service" in result and result["service"] == "identity"
        assert "certificate_status" in result
        assert "certificate_identity_score" in result
        assert "package_similarity" in result
        assert "manifest_findings" in result
        assert "errors" in result
    finally:
        for p in [path_b, path_c]:
            if os.path.exists(p):
                os.unlink(p)


# ---------------------------------------------------------------------------
# Manifest findings tests
# ---------------------------------------------------------------------------

def test_manifest_findings_identical_packages():
    baseline = {"package_name": "com.example.bank", "app_label": "BankApp"}
    candidate = {"package_name": "com.example.bank", "app_label": "BankApp"}
    findings = build_manifest_findings(baseline, candidate)
    types = [f["type"] for f in findings]
    assert "PACKAGE_EXACT_MATCH" in types


def test_manifest_findings_near_match():
    baseline = {"package_name": "com.example.bank", "app_label": "BankApp"}
    candidate = {"package_name": "com.example.banq", "app_label": "BankApp"}
    findings = build_manifest_findings(baseline, candidate)
    types = [f["type"] for f in findings]
    assert "PACKAGE_NEAR_MATCH" in types


def test_manifest_findings_missing_label():
    baseline = {"package_name": "com.example.bank", "app_label": "BankApp"}
    candidate = {"package_name": "com.example.banq", "app_label": None}
    findings = build_manifest_findings(baseline, candidate)
    types = [f["type"] for f in findings]
    assert "MISSING_LABEL" in types


# ---------------------------------------------------------------------------
# Permission diffing tests (using identity analyzer's _diff_permissions)
# ---------------------------------------------------------------------------

def test_permission_diff_correct():
    identity = _load_identity()
    baseline_perms = ["android.permission.INTERNET", "android.permission.CAMERA"]
    candidate_perms = ["android.permission.INTERNET", "android.permission.RECEIVE_SMS"]
    new_perms, removed_perms = identity._diff_permissions(baseline_perms, candidate_perms)
    assert "RECEIVE_SMS" in new_perms
    assert "CAMERA" in removed_perms
    assert "INTERNET" not in new_perms
    assert "INTERNET" not in removed_perms


def test_permission_diff_normalizes():
    identity = _load_identity()
    baseline = ["android.permission.INTERNET"]
    candidate = ["INTERNET", "SEND_SMS"]
    new_perms, _ = identity._diff_permissions(baseline, candidate)
    # INTERNET should not be in new_perms (it's in both, normalized)
    assert "INTERNET" not in new_perms
    assert "SEND_SMS" in new_perms
