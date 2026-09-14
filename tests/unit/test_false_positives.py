"""
False Positive Regression Tests (V3)

These tests guard against specific scenarios where the analyzer pipeline
incorrectly flags non-clone apps as clones, or flags benign behavior as
malicious. Each test encodes a concrete false positive that was reported
or anticipated, then asserts the system does NOT over-flag.

Test categories:
  1. Legitimate forks (open-source apps rebuilt with different signing keys)
  2. Apps using common libraries (shared SDK strings/assets that match)
  3. Apps with similar package naming patterns but different content
  4. Minimal apps with sparse resources
  5. Apps with obfuscation (should not lower clone_probability via broken hashes)
  6. Permission additions that are benign (not all new perms are suspicious)
  7. Shared resources between unrelated apps (SDK/framework files)
  8. Confidence inflation on sparse data
"""
import io
import os
import sys
import zipfile
from pathlib import Path
from PIL import Image

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scoring"))

from engine import compute_scores


def _create_minimal_apk(path, strings=None, assets=None, images=None, permissions=None):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", b"placeholder-manifest")

        if strings:
            xml = ['<?xml version="1.0" encoding="utf-8"?>\n<resources>\n']
            for k, v in strings:
                xml.append(f'  <string name="{k}">{v}</string>\n')
            xml.append('</resources>')
            z.writestr("res/values/strings.xml", "".join(xml))

        if assets:
            for fname, content in assets.items():
                z.writestr(f"assets/{fname}", content)

        if images:
            for fname, (w, h, color) in images.items():
                buf = io.BytesIO()
                img = Image.new("RGBA", (w, h), color)
                img.save(buf, format="PNG")
                z.writestr(f"res/drawable/{fname}.png", buf.getvalue())

        if permissions:
            for perm in permissions:
                assert isinstance(perm, str)


# ---------------------------------------------------------------------------
# 1. Legitimate forks (different signing key, same app)
# ---------------------------------------------------------------------------

def test_legitimate_fork_not_flagged_as_malware():
    """
    A fork (same code, different signing key) should have high clone_probability
    but LOW malware_risk_score — the fork is not malicious, just unsigned differently.
    """
    identity = {
        "certificate_status": "DIFFERENT_SIGNER",
        "certificate_identity_score": 0.0,
        "package_similarity": 1.0,
    }
    similarity = {
        "icon_score": 0.99,
        "string_score": 0.98,
        "layout_score": 0.95,
        "resource_score": 0.97,
    }
    dex = {
        "bytecode_similarity": 0.99,
        "malware_risk_score": 5,
        "risk_findings": [],
    }

    scores = compute_scores(identity, similarity, dex)
    assert scores["clone_probability"] >= 0.75  # high but not necessarily ≥0.85
    assert scores["malware_risk"] < 0.5


# ---------------------------------------------------------------------------
# 2. Apps with common library SDKs
# ---------------------------------------------------------------------------

def test_library_sdk_matches_dont_overstate_clone_probability():
    """
    Two apps that both use Firebase SDK will share some strings and assets.
    This shared library overlap should NOT by itself push clone_probability
    above 0.5 when package/icon/code differ significantly.
    """
    shared_strings = [("lib_version", "com.google.firebase.messaging 23.0.0")]
    shared_assets = {"firebase_manifest.xml": "<meta-data>google services</meta-data>"}

    path_a = str(ROOT / "tests" / "fixtures" / "fp_lib_a.apk")
    _create_minimal_apk(path_a,
                        strings=shared_strings + [("app_name", "App A"), ("feature_a", "A unique feature")],
                        assets={**shared_assets, "app_a_data.json": '{"unique": true}'},
                        images={"logo": (64, 64, (10, 20, 30, 255))})

    path_b = str(ROOT / "tests" / "fixtures" / "fp_lib_b.apk")
    _create_minimal_apk(path_b,
                        strings=shared_strings + [("app_name", "App B"), ("feature_b", "B unique feature")],
                        assets={**shared_assets, "app_b_data.json": '{"unique": false}'},
                        images={"logo": (64, 64, (200, 100, 50, 255))})

    try:
        sys.path.insert(0, str(ROOT / "analyzers" / "resource"))
        from analyzer import analyze as resource_analyze
        resource_scores = resource_analyze(path_a, path_b)

        identity = {
            "certificate_status": "DIFFERENT_SIGNER",
            "certificate_identity_score": 0.0,
            "package_similarity": 0.2,
        }
        similarity = {
            "icon_score": resource_scores.get("image_score", 0.3) or 0.3,
            "string_score": resource_scores.get("string_score", 0.3) or 0.3,
            "layout_score": 0.2,
            "resource_score": resource_scores.get("resource_score", 0.4) or 0.4,
        }
        dex = {"bytecode_similarity": 0.15, "malware_risk_score": 0}

        scores = compute_scores(identity, similarity, dex)
        assert scores["clone_probability"] < 0.7
    finally:
        for p in [path_a, path_b]:
            try: os.remove(p)
            except FileNotFoundError: pass


# ---------------------------------------------------------------------------
# 3. Similar package names, different content
# ---------------------------------------------------------------------------

def test_similar_package_name_does_not_imply_clone():
    """
    Package names like 'com.social' vs 'com.social.pro' can have very high
    package_similarity. This must NOT auto-classify as clone when other signals are weak.
    """
    identity = {
        "certificate_status": "DIFFERENT_SIGNER",
        "certificate_identity_score": 0.0,
        "package_similarity": 1.0,
    }
    similarity = {"icon_score": 0.2, "string_score": 0.1, "layout_score": 0.15, "resource_score": 0.2}
    dex = {"bytecode_similarity": 0.1, "malware_risk_score": 10}

    scores = compute_scores(identity, similarity, dex)
    assert scores["clone_probability"] < 0.7


# ---------------------------------------------------------------------------
# 4. Minimal / empty apps
# ---------------------------------------------------------------------------

def test_empty_apps_no_false_malware():
    """
    Minimal placeholder apps with no resources, no permissions, and tiny DEX
    must never be flagged as malware (malware_risk == 0).
    """
    identity = {"certificate_identity_score": None, "package_similarity": None}
    similarity = {"icon_score": None, "string_score": None, "layout_score": None, "resource_score": None}
    dex = {"bytecode_similarity": None, "malware_risk_score": 0, "risk_findings": []}

    scores = compute_scores(identity, similarity, dex)
    assert scores["malware_risk"] == 0.0
    assert scores["clone_probability"] < 0.5
    assert scores["confidence"] < 0.5


# ---------------------------------------------------------------------------
# 5. Obfuscation resistance
# ---------------------------------------------------------------------------

def test_obfuscated_dex_does_not_lower_clone_probability_past_threshold():
    """
    Heavy obfuscation (name mangling) increases fuzzy hashing distance — but if
    strings and icons match, clone_probability should remain high.
    """
    identity = {"certificate_identity_score": None, "package_similarity": 0.99}
    similarity = {"icon_score": 0.98, "string_score": 0.97, "layout_score": 0.95, "resource_score": 0.96}
    dex = {"bytecode_similarity": 0.3, "malware_risk_score": 0}

    scores = compute_scores(identity, similarity, dex)
    assert scores["clone_probability"] >= 0.6


# ---------------------------------------------------------------------------
# 6. Benign permission additions
# ---------------------------------------------------------------------------

def test_benign_permission_addition_does_not_trigger_high_risk():
    """
    Adding a benign permission like ACCESS_NETWORK_STATE should not contribute
    to malware risk.
    """
    dex = {
        "bytecode_similarity": 0.5,
        "malware_risk_score": 5,
        "risk_findings": [{"finding": "NORMAL: ACCESS_NETWORK_STATE", "contribution": 0}],
    }
    identity = {"certificate_identity_score": 0.5, "package_similarity": 0.6}
    similarity = {"icon_score": 0.7, "string_score": 0.6, "layout_score": 0.5, "resource_score": 0.6}

    scores = compute_scores(identity, similarity, dex)
    assert scores["malware_risk"] <= 0.1


# ---------------------------------------------------------------------------
# 7. Shared Google/Play services resources
# ---------------------------------------------------------------------------

def test_shared_framework_resources_not_flagged():
    """
    Many apps bundle similar framework files. When only these shared files
    overlap and app-specific content differs, clone_probability should remain moderate.
    """
    path_a = str(ROOT / "tests" / "fixtures" / "fp_framework_a.apk")
    _create_minimal_apk(path_a,
                        assets={"play_services_v2.apk": "shared framework", "unique_a.dat": "A-only content"},
                        strings=[("app_name", "App A"), ("welcome", "Hello from A")],
                        images={"icon": (64, 64, (0, 100, 200, 255))})

    path_b = str(ROOT / "tests" / "fixtures" / "fp_framework_b.apk")
    _create_minimal_apk(path_b,
                        assets={"play_services_v2.apk": "shared framework", "unique_b.dat": "B-only content"},
                        strings=[("app_name", "App B"), ("welcome", "Hello from B")],
                        images={"icon": (64, 64, (255, 100, 0, 255))})

    try:
        sys.path.insert(0, str(ROOT / "analyzers" / "resource"))
        from analyzer import analyze as resource_analyze
        res = resource_analyze(path_a, path_b)

        scores = compute_scores(
            identity={"certificate_status": "DIFFERENT_SIGNER", "certificate_identity_score": 0.0,
                      "package_similarity": 0.1},
            similarity={"icon_score": res.get("image_score") or 0.1,
                        "string_score": res.get("string_score") or 0.3,
                        "layout_score": 0.0,
                        "resource_score": res.get("resource_score") or 0.25},
            dex={"bytecode_similarity": 0.1, "malware_risk_score": 0, "risk_findings": []},
        )
        assert scores["clone_probability"] < 0.6
        assert scores["malware_risk"] == 0.0
    finally:
        for p in [path_a, path_b]:
            try: os.remove(p)
            except FileNotFoundError: pass


# ---------------------------------------------------------------------------
# 8. Null propagation integrity
# ---------------------------------------------------------------------------

def test_null_signals_dont_inflate_confidence():
    """
    When most signals are null (parse failure), confidence should be low
    even if the available signals are high.
    """
    identity = {"certificate_identity_score": 1.0, "package_similarity": None}
    similarity = {"icon_score": None, "string_score": None, "layout_score": None, "resource_score": None}
    dex = {"bytecode_similarity": None, "malware_risk_score": 0, "risk_findings": []}

    scores = compute_scores(identity, similarity, dex)
    assert scores["confidence"] < 0.55  # only 1 of 7 signals available


def test_high_confidence_requires_many_signals():
    """
    To achieve confidence > 0.7, at least 5+ of 7 components must produce
    non-null, non-zero signals.
    """
    identity = {"certificate_identity_score": 0.9, "package_similarity": 0.9}
    similarity = {"icon_score": 0.8, "string_score": 0.85, "layout_score": 0.7, "resource_score": 0.75}
    dex = {"bytecode_similarity": 0.8, "malware_risk_score": 0}

    scores = compute_scores(identity, similarity, dex)
    assert scores["confidence"] >= 0.7
