"""
Unit tests for the DEX-Risk Analyzer V3 contract.

Tests:
  - TLSH similarity calculation (with fallback to ssdeep, or unavailable)
  - TLSH normalization function (documented linear mapping)
  - Permission risk engine:
      no new permissions → 0
      new SMS → +30
      accessibility → +30
      overlay → +25
      boot → +15
      dangerous permissions → +5 each, max 4
      total capped at 100
  - Component diff (exported components, max 2 counted)
  - Risk engine score calculation
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

# dex-risk dir has a hyphen; add it to sys.path for sibling imports
_DEX_RISK_DIR = str(ROOT / "analyzers" / "dex-risk")
if _DEX_RISK_DIR not in sys.path:
    sys.path.insert(0, _DEX_RISK_DIR)

from tlsh_similarity import (
    normalize_tlsh_distance,
    normalize_ssdeep_score,
    calculate_dex_fuzzy_similarity,
)
from permissions import (
    calculate_permission_risk,
    diff_permissions,
    normalize_permission,
    categorize_permission,
)
from risk_engine import calculate_risk_score, merge_findings
from components import compare_exported_components


# ---------------------------------------------------------------------------
# TLSH similarity tests
# ---------------------------------------------------------------------------

def test_normalize_tlsh_distance_zero():
    """Distance 0 → similarity 1.0"""
    assert normalize_tlsh_distance(0) == 1.0


def test_normalize_tlsh_distance_max():
    """Distance 1000 → similarity 0.0"""
    assert normalize_tlsh_distance(1000) == 0.0


def test_normalize_tlsh_distance_midpoint():
    """Distance 500 → similarity 0.5"""
    assert normalize_tlsh_distance(500) == 0.5


def test_normalize_tlsh_distance_clamp_high():
    """Distance > 1000 → similarity 0.0 (clamped)"""
    assert normalize_tlsh_distance(2000) == 0.0


def test_normalize_tlsh_distance_negative():
    assert normalize_tlsh_distance(-1) == 0.0


def test_normalize_ssdeep_score():
    assert normalize_ssdeep_score(100) == 1.0
    assert normalize_ssdeep_score(0) == 0.0
    assert normalize_ssdeep_score(50) == 0.5


def test_fuzzy_similarity_empty_input():
    result = calculate_dex_fuzzy_similarity(b"", b"")
    assert result["similarity"] is None
    assert result["available"] is False
    assert result["error"] is not None


def test_fuzzy_similarity_small_input():
    """Input below 512 bytes should not produce TLSH hash."""
    result = calculate_dex_fuzzy_similarity(b"x" * 100, b"x" * 100)
    if not result["available"]:
        assert result["similarity"] is None
        assert result["error"] is not None
    # If ssdeep is available, it may still work; just check it doesn't crash


def test_fuzzy_similarity_large_identical():
    """Identical large inputs should produce high similarity."""
    data = b"x" * 2000
    result = calculate_dex_fuzzy_similarity(data, data)
    if result["available"] and result["similarity"] is not None:
        assert result["similarity"] > 0.9


# ---------------------------------------------------------------------------
# Permission risk engine tests
# ---------------------------------------------------------------------------

def test_no_new_permissions_zero():
    baseline = ["INTERNET", "CAMERA"]
    candidate = ["INTERNET", "CAMERA"]
    result = calculate_permission_risk(baseline, candidate)
    assert result["score"] == 0


def test_new_sms_gives_30():
    baseline = ["INTERNET"]
    candidate = ["INTERNET", "RECEIVE_SMS"]
    result = calculate_permission_risk(baseline, candidate)
    assert result["score"] == 30
    sms_finding = [f for f in result["findings"] if "SMS" in f["finding"]]
    assert len(sms_finding) == 1
    assert sms_finding[0]["contribution"] == 30


def test_new_send_sms_gives_30():
    baseline = ["INTERNET"]
    candidate = ["INTERNET", "SEND_SMS"]
    result = calculate_permission_risk(baseline, candidate)
    assert result["score"] == 30


def test_new_accessibility_gives_30():
    baseline = ["INTERNET"]
    candidate = ["INTERNET", "BIND_ACCESSIBILITY_SERVICE"]
    result = calculate_permission_risk(baseline, candidate)
    assert result["score"] == 30


def test_new_overlay_gives_25():
    baseline = ["INTERNET"]
    candidate = ["INTERNET", "SYSTEM_ALERT_WINDOW"]
    result = calculate_permission_risk(baseline, candidate)
    assert result["score"] == 25


def test_new_boot_completed_gives_15():
    baseline = ["INTERNET"]
    candidate = ["INTERNET", "RECEIVE_BOOT_COMPLETED"]
    result = calculate_permission_risk(baseline, candidate)
    assert result["score"] == 15


def test_all_risk_permissions_sum_to_100():
    """30 + 30 + 25 + 15 + 5 = 105, capped at 100."""
    baseline = ["INTERNET"]
    candidate = [
        "INTERNET",
        "BIND_ACCESSIBILITY_SERVICE",  # +30
        "RECEIVE_SMS",                  # +30
        "SYSTEM_ALERT_WINDOW",          # +25
        "RECEIVE_BOOT_COMPLETED",       # +15
        "CAMERA",                       # +5 (dangerous)
    ]
    result = calculate_permission_risk(baseline, candidate)
    assert result["score"] == 100


def test_dangerous_permissions_max_four():
    """5 dangerous permissions should give 4*5=20, not 25."""
    baseline = ["INTERNET"]
    candidate = ["INTERNET",
                 "READ_CONTACTS", "WRITE_CONTACTS", "CAMERA",
                 "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION"]
    result = calculate_permission_risk(baseline, candidate)
    assert result["score"] == 20  # 4 * 5 = 20, capped


def test_total_capped_at_100():
    """110 contributions should still yield 100."""
    baseline = []
    candidate = [
        "BIND_ACCESSIBILITY_SERVICE",   # 30
        "RECEIVE_SMS",                  # 30
        "SYSTEM_ALERT_WINDOW",          # 25
        "RECEIVE_BOOT_COMPLETED",       # 15
        "CAMERA", "READ_CONTACTS",      # 5 + 5 = 10
    ]
    result = calculate_permission_risk(baseline, candidate)
    assert result["score"] == 100  # 30+30+25+15+10 = 110, capped


def test_permission_categorization():
    assert categorize_permission("SEND_SMS") == "SMS"
    assert categorize_permission("RECEIVE_SMS") == "SMS"
    assert categorize_permission("BIND_ACCESSIBILITY_SERVICE") == "accessibility"
    assert categorize_permission("SYSTEM_ALERT_WINDOW") == "overlay"
    assert categorize_permission("RECEIVE_BOOT_COMPLETED") == "boot"
    assert categorize_permission("CAMERA") == "dangerous"
    assert categorize_permission("INTERNET") == "other"


def test_diff_permissions_dedup():
    b, c, new, removed = diff_permissions(
        ["INTERNET", "INTERNET"],
        ["INTERNET", "SEND_SMS", "SEND_SMS"]
    )
    assert len(c) == 2  # INTERNET, SEND_SMS (deduplicated)
    assert new == ["SEND_SMS"]
    assert removed == []


def test_existing_permission_not_scored():
    """RECEIVE_SMS in baseline should give 0."""
    baseline = ["RECEIVE_SMS"]
    candidate = ["RECEIVE_SMS", "INTERNET"]
    result = calculate_permission_risk(baseline, candidate)
    assert result["score"] == 0


def test_permission_normalization_with_prefix():
    normalized = normalize_permission("android.permission.SYSTEM_ALERT_WINDOW")
    assert normalized == "SYSTEM_ALERT_WINDOW"


# ---------------------------------------------------------------------------
# Component diff tests
# ---------------------------------------------------------------------------

def test_no_new_exported_components():
    baseline_comps = [
        {"name": "com.app.Receiver", "type": "receiver", "exported": True},
    ]
    candidate_comps = [
        {"name": "com.app.Receiver", "type": "receiver", "exported": True},
    ]
    comp_findings = compare_exported_components(baseline_comps, candidate_comps)
    assert len(comp_findings) == 0


def test_one_new_exported_component():
    baseline_comps = []
    candidate_comps = [
        {"name": "com.app.NewReceiver", "type": "receiver", "exported": True},
    ]
    findings = compare_exported_components(baseline_comps, candidate_comps)
    assert len(findings) == 1
    assert findings[0]["contribution"] == 10
    assert findings[0]["finding"] == "NEW_EXPORTED_COMPONENT"


def test_two_new_exported_components():
    baseline_comps = []
    candidate_comps = [
        {"name": "com.app.Recv1", "type": "receiver", "exported": True},
        {"name": "com.app.Recv2", "type": "receiver", "exported": True},
    ]
    findings = compare_exported_components(baseline_comps, candidate_comps)
    scored = [f for f in findings if f["contribution"] > 0]
    assert len(scored) == 2
    assert scored[0]["contribution"] == 10
    assert scored[1]["contribution"] == 10


def test_three_new_exported_components_capped():
    """3 new exported components → only 2 counted (+20), third is report-only."""
    baseline_comps = []
    candidate_comps = [
        {"name": "com.app.Recv1", "type": "receiver", "exported": True},
        {"name": "com.app.Recv2", "type": "receiver", "exported": True},
        {"name": "com.app.Recv3", "type": "receiver", "exported": True},
    ]
    findings = compare_exported_components(baseline_comps, candidate_comps)
    scored = [f for f in findings if f["contribution"] > 0]
    assert len(scored) == 2  # capped at 2
    assert len(findings) == 3  # third is report-only (contribution 0)


def test_non_exported_component_not_scored():
    baseline_comps = []
    candidate_comps = [
        {"name": "com.app.Receiver", "type": "receiver", "exported": False},
    ]
    findings = compare_exported_components(baseline_comps, candidate_comps)
    assert len(findings) == 0


# ---------------------------------------------------------------------------
# Risk engine tests
# ---------------------------------------------------------------------------

def test_risk_score_sum():
    findings = [
        {"finding": "A", "contribution": 30, "severity": "high"},
        {"finding": "B", "contribution": 25, "severity": "high"},
        {"finding": "C", "contribution": 10, "severity": "medium"},
    ]
    result = calculate_risk_score(findings)
    assert result["score"] == 65
    assert result["total_contributions"] == 65


def test_risk_score_capped_at_100():
    findings = [
        {"finding": "A", "contribution": 30},
        {"finding": "B", "contribution": 30},
        {"finding": "C", "contribution": 30},
        {"finding": "D", "contribution": 30},
    ]
    result = calculate_risk_score(findings)
    assert result["score"] == 100
    assert result["total_contributions"] == 120


def test_risk_score_zero():
    result = calculate_risk_score([])
    assert result["score"] == 0


def test_merge_findings():
    perm_findings = [{"finding": "A", "category": "PERMISSION", "contribution": 30, "severity": "high"}]
    comp_findings = [{"finding": "B", "category": "COMPONENT", "contribution": 10, "severity": "medium"}]
    merged = merge_findings(perm_findings, comp_findings, [])
    assert len(merged) == 2
