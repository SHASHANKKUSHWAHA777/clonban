"""
Unit tests for the enhanced similarity & DEX analyzers.

These test the pure-function helpers directly (no APK files needed).
Run with: pytest tests/unit -v
"""
import sys
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# Shannon entropy filter (from analyzers/similarity/analyzer.py)
# ---------------------------------------------------------------------------

from analyzers.similarity.analyzer import (
    _shannon_entropy,
    _is_meaningful_string,
    _jaccard_counter,
    _jaccard_sets,
)


class TestShannonEntropy:
    def test_empty_string_has_zero_entropy(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char_repeated_has_zero_entropy(self):
        assert _shannon_entropy("aaaaaaa") == 0.0

    def test_english_text_has_moderate_entropy(self):
        entropy = _shannon_entropy("Hello World this is a normal string")
        assert 2.5 < entropy < 4.5

    def test_random_hex_has_high_entropy(self):
        # 64 hex chars — simulating encrypted/base64 blob
        blob = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
        entropy = _shannon_entropy(blob)
        assert entropy > 3.5

    def test_meaningful_filter_rejects_empty(self):
        assert not _is_meaningful_string("")

    def test_meaningful_filter_rejects_single_char(self):
        assert not _is_meaningful_string("x")

    def test_meaningful_filter_accepts_normal_text(self):
        assert _is_meaningful_string("Enter your password")

    def test_meaningful_filter_rejects_repeated_chars(self):
        # Very low entropy — below ENTROPY_LOW threshold
        assert not _is_meaningful_string("aaaaaaaaaaaa")


# ---------------------------------------------------------------------------
# Jaccard helpers
# ---------------------------------------------------------------------------

class TestJaccardHelpers:
    def test_counter_jaccard_identical(self):
        c = Counter({"A": 5, "B": 3})
        assert _jaccard_counter(c, c) == 1.0

    def test_counter_jaccard_disjoint(self):
        a = Counter({"A": 5})
        b = Counter({"B": 3})
        assert _jaccard_counter(a, b) == 0.0

    def test_counter_jaccard_partial(self):
        a = Counter({"A": 4, "B": 2})
        b = Counter({"A": 2, "C": 3})
        # min-sum = min(4,2) + min(2,0) + min(0,3) = 2
        # max-sum = max(4,2) + max(2,0) + max(0,3) = 4+2+3 = 9
        assert abs(_jaccard_counter(a, b) - 2 / 9) < 0.001

    def test_counter_jaccard_both_empty(self):
        assert _jaccard_counter(Counter(), Counter()) == 0.0

    def test_set_jaccard_identical(self):
        s = {"a", "b", "c"}
        assert _jaccard_sets(s, s) == 1.0

    def test_set_jaccard_disjoint(self):
        assert _jaccard_sets({"a"}, {"b"}) == 0.0

    def test_set_jaccard_both_empty(self):
        assert _jaccard_sets(set(), set()) == 0.0


# ---------------------------------------------------------------------------
# Weighted API similarity (from analyzers/dex-risk/analyzer.py)
# ---------------------------------------------------------------------------

# Import from dex-risk which has a hyphenated directory — use importlib
import importlib.util

_dex_spec = importlib.util.spec_from_file_location(
    "dexrisk_analyzer",
    str(ROOT / "analyzers" / "dex-risk" / "analyzer.py"),
)
_dex_mod = importlib.util.module_from_spec(_dex_spec)
_dex_spec.loader.exec_module(_dex_mod)

_weighted_api_similarity = _dex_mod._weighted_api_similarity
_sensitive_cluster_similarity = _dex_mod._sensitive_cluster_similarity
_api_weight = _dex_mod._api_weight


class TestApiWeighting:
    def test_string_is_low_signal(self):
        assert _api_weight("Ljava/lang/String;") == 0.2

    def test_dex_class_loader_is_sensitive(self):
        assert _api_weight("Ldalvik/system/DexClassLoader;") == 3.0

    def test_unknown_api_gets_default_weight(self):
        assert _api_weight("Lcom/example/MyCustomClass;") == 1.0

    def test_crypto_api_is_sensitive(self):
        assert _api_weight("Ljavax/crypto/Cipher;") == 3.0


class TestWeightedApiSimilarity:
    def test_identical_sets(self):
        apis = {"Ljava/lang/String;", "Ldalvik/system/DexClassLoader;"}
        assert _weighted_api_similarity(apis, apis) == 1.0

    def test_disjoint_sets(self):
        a = {"Ljava/lang/String;"}
        b = {"Ldalvik/system/DexClassLoader;"}
        sim = _weighted_api_similarity(a, b)
        assert sim == 0.0

    def test_empty_sets(self):
        assert _weighted_api_similarity(set(), set()) == 0.0

    def test_sensitive_overlap_scores_higher_than_generic(self):
        """Two apps sharing a sensitive API should score higher than two
        apps sharing only a generic ubiquitous class."""
        sensitive_common = {"Ldalvik/system/DexClassLoader;"}
        generic_common = {"Ljava/lang/String;"}
        only_a = {"Lcom/example/A;"}

        sim_sensitive = _weighted_api_similarity(sensitive_common | only_a, sensitive_common)
        sim_generic = _weighted_api_similarity(generic_common | only_a, generic_common)
        assert sim_sensitive > sim_generic


class TestSensitiveClusterSimilarity:
    def test_same_clusters(self):
        apis = {"Ljavax/crypto/Cipher;", "Ljava/net/Socket;"}
        assert _sensitive_cluster_similarity(apis, apis) == 1.0

    def test_disjoint_clusters(self):
        a = {"Ljavax/crypto/Cipher;"}  # crypto cluster
        b = {"Landroid/telephony/SmsManager;"}  # sms cluster
        sim = _sensitive_cluster_similarity(a, b)
        assert sim == 0.0

    def test_no_sensitive_apis(self):
        a = {"Ljava/lang/String;"}
        b = {"Ljava/lang/Object;"}
        assert _sensitive_cluster_similarity(a, b) == 0.0
