"""
Run with: pytest tests/unit -v
(from repo root, with backend + scoring on PYTHONPATH — see tests/README.md)
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scoring.engine import compute_scores, DEFAULT_WEIGHTS


def _identity(cert_match=False, findings=None, manifest_score=0.7, permissions_score=0.8):
    return {
        "certificate_score": 1.0 if cert_match else 0.10,
        "certificate_match": cert_match,
        "package_score": 0.8,
        "manifest_score": manifest_score,
        "permissions_score": permissions_score,
        "findings": findings or [],
    }


def _similarity(icon=0.9, strings=0.8, layout=0.7, resources=0.85):
    return {"icon_score": icon, "string_score": strings, "layout_score": layout, "resource_score": resources}


def _dex(dex_score=0.8, malware_risk=0.0):
    return {"dex_score": dex_score, "malware_risk": malware_risk}


# ---- Existing tests (updated for 9-signal helpers) ----

def test_high_similarity_gives_high_clone_probability():
    scores = compute_scores(_identity(cert_match=False), _similarity(), _dex())
    assert scores["clone_probability"] > 0.6


def test_no_similarity_gives_low_clone_probability():
    identity = {"certificate_score": 0.0, "certificate_match": False, "package_score": 0.0,
                "manifest_score": 0.0, "permissions_score": 0.0, "findings": []}
    similarity = {"icon_score": 0.0, "string_score": 0.0, "layout_score": 0.0, "resource_score": 0.0}
    dex = {"dex_score": 0.0, "malware_risk": 0.0}
    scores = compute_scores(identity, similarity, dex)
    assert scores["clone_probability"] < 0.1


def test_clone_probability_and_malware_risk_are_independent():
    """A highly similar app with zero risky findings should show high clone
    probability but near-zero malware risk — the two must not be conflated."""
    scores = compute_scores(_identity(), _similarity(), _dex(dex_score=0.9, malware_risk=0.0))
    assert scores["clone_probability"] > 0.5
    assert scores["malware_risk"] == 0.0


def test_low_similarity_but_high_malware_risk_still_flags_risk():
    identity = {"certificate_score": 0.1, "certificate_match": False, "package_score": 0.05,
                "manifest_score": 0.0, "permissions_score": 0.0, "findings": []}
    similarity = {"icon_score": 0.05, "string_score": 0.05, "layout_score": 0.05, "resource_score": 0.05}
    dex = {"dex_score": 0.1, "malware_risk": 0.9}
    scores = compute_scores(identity, similarity, dex)
    assert scores["clone_probability"] < 0.2
    assert scores["malware_risk"] == 0.9


def test_weights_are_normalized_even_if_input_doesnt_sum_to_one():
    unbalanced = {k: 1.0 for k in DEFAULT_WEIGHTS}  # all 1.0, sums to 9.0
    scores = compute_scores(_identity(), _similarity(icon=1, strings=1, layout=1, resources=1),
                             _dex(dex_score=1), weights=unbalanced)
    assert abs(sum(scores["weights_used"].values()) - 1.0) < 1e-6


def test_confidence_drops_on_parse_error():
    identity_ok = _identity(findings=[])
    identity_bad = _identity(findings=[{"type": "PARSE_ERROR", "severity": "high", "evidence": "bad zip"}])
    sim, dex = _similarity(), _dex()
    scores_ok = compute_scores(identity_ok, sim, dex)
    scores_bad = compute_scores(identity_bad, sim, dex)
    assert scores_bad["confidence"] < scores_ok["confidence"]


# ---- New tests for 9-signal expansion ----

def test_default_weights_have_nine_signals():
    """The engine must now expose exactly 9 weighted signals."""
    assert len(DEFAULT_WEIGHTS) == 9
    assert "manifest" in DEFAULT_WEIGHTS
    assert "permissions" in DEFAULT_WEIGHTS


def test_default_weights_sum_to_one():
    """Weights should sum to ~1.0 (within floating-point tolerance)."""
    assert abs(sum(DEFAULT_WEIGHTS.values()) - 1.0) < 0.01


def test_manifest_and_permissions_affect_clone_probability():
    """If manifest and permissions scores are high, clone_probability should
    be higher than if they were zero, all else equal."""
    scores_high = compute_scores(
        _identity(manifest_score=0.9, permissions_score=0.9),
        _similarity(), _dex()
    )
    scores_zero = compute_scores(
        _identity(manifest_score=0.0, permissions_score=0.0),
        _similarity(), _dex()
    )
    assert scores_high["clone_probability"] > scores_zero["clone_probability"]


def test_component_scores_include_manifest_permissions():
    """Component scores dict must include the new signals."""
    scores = compute_scores(_identity(), _similarity(), _dex())
    assert "manifest" in scores["component_scores"]
    assert "permissions" in scores["component_scores"]
    assert scores["component_scores"]["manifest"] == 0.7
    assert scores["component_scores"]["permissions"] == 0.8


def test_verdict_summary_mentions_strongest_signal():
    """The strongest signal's name must appear in the verdict text."""
    scores = compute_scores(
        _identity(manifest_score=0.0, permissions_score=0.0),
        _similarity(icon=0.1, strings=0.1, layout=0.1, resources=0.1),
        _dex(dex_score=1.0),
    )
    assert "dex" in scores["verdict_summary"]


def test_confidence_with_nine_all_active():
    """When all 9 signals are non-zero the coverage should be near 1.0."""
    scores = compute_scores(
        _identity(cert_match=False, manifest_score=0.5, permissions_score=0.5),
        _similarity(icon=0.5, strings=0.5, layout=0.5, resources=0.5),
        _dex(dex_score=0.5),
    )
    # certificate_score = 0.10 (non-zero) + 8 others non-zero → coverage = 9/9 = 1.0
    assert scores["confidence"] > 0.8
