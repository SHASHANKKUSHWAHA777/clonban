import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from analyzers.identity.analyzer import _token_similarity, _manifest_similarity, _permissions_similarity


def test_exact_package_match():
    assert _token_similarity("com.example.bank", "com.example.bank") == 1.0


def test_completely_unrelated_packages_score_low():
    assert _token_similarity("com.example.bank", "org.other.unrelated") < 0.3


def test_suffix_variant_scores_high():
    # a common cloning trick: appending a digit/suffix to the original namespace
    score = _token_similarity("com.example.bank", "com.example.bank2")
    assert score > 0.7


def test_manifest_similarity_identical_components():
    orig = {"activities": ["a.MainActivity"], "services": [], "receivers": [], "providers": []}
    cand = {"activities": ["a.MainActivity"], "services": [], "receivers": [], "providers": []}
    assert _manifest_similarity(orig, cand) == 1.0


def test_permissions_similarity_partial_overlap():
    orig = {"permissions": ["INTERNET", "CAMERA"]}
    cand = {"permissions": ["INTERNET", "READ_SMS"]}
    score = _permissions_similarity(orig, cand)
    assert 0.0 < score < 1.0
