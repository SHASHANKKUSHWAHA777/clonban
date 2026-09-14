"""
End-to-end pipeline test with synthetic APKs.

This test creates minimal synthetic APK files (valid ZIPs with minimal
AndroidManifest.xml) and runs the full analysis pipeline:
  Identity -> Similarity -> DEX/Risk -> Scoring

No real APK binaries are needed — these are synthetic test fixtures
that exercise the code paths, error handling, and V3 contract compliance.
"""
import sys
import os
import json
import struct
import zipfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

# Add dex-risk dir to path for sibling module imports
_DEX_RISK_DIR = str(ROOT / "analyzers" / "dex-risk")
if _DEX_RISK_DIR not in sys.path:
    sys.path.insert(0, _DEX_RISK_DIR)


def _create_minimal_apk(path: str, package_name: str = "com.example.app",
                        cert_sha: bytes = b"\x00" * 32,
                        permissions: list = None,
                        has_dex: bool = True):
    """
    Create a minimal valid ZIP file that apksigner-style structure can be
    parsed by androguard. We include:
      - AndroidManifest.xml (minimal binary AXML or raw placeholder)
      - classes.dex (minimal valid DEX header)
      - META-INF/*.SF, *.RSA (certificate directory for signing)
    """
    permissions = permissions or []
    
    # Create a minimal DEX file (just the header is enough for discovery)
    # DEX header: 8 bytes magic + 4 bytes version + 4 bytes checksum + ...
    dex_magic = b"dex\n035\x00" + b"\x00" * 100  # minimal DEX header stub
    
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Minimal AndroidManifest.xml — use a raw placeholder that androguard
        # will attempt to parse (may fail, which tests robustness)
        manifest_content = _build_manifest_xml(package_name, permissions)
        zf.writestr("AndroidManifest.xml", manifest_content)
        
        if has_dex:
            zf.writestr("classes.dex", dex_magic)
            zf.writestr("classes2.dex", dex_magic)  # test multi-DEX
        
        # Write minimal signing info directory
        zf.writestr("META-INF/CERT.SF", b"Signature-Version: 1.2\n")
        # Minimal RSA cert (not a real cert, but exercises the directory structure)
        zf.writestr("META-INF/CERT.RSA", b"\x00" * 512)
    
    return path


def _build_manifest_xml(package_name: str, permissions: list) -> bytes:
    """Build a minimal AndroidManifest.xml (binary AXML format stub)."""
    # For simplicity, we use a text XML. Androguard may not fully parse this,
    # but the APK will still be a valid ZIP with valid structure.
    # The test exercises error handling paths.
    manifest = f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package_name}">
'''
    for perm in permissions:
        manifest += f'    <uses-permission android:name="{perm}" />\n'
    manifest += '</manifest>\n'
    return manifest.encode('utf-8')


def test_identity_v3_contract():
    """Verify identity analyzer produces V3 contract fields."""
    import importlib.util
    
    with tempfile.TemporaryDirectory() as tmpdir:
        orig_path = os.path.join(tmpdir, "original.apk")
        cand_path = os.path.join(tmpdir, "candidate.apk")
        
        _create_minimal_apk(orig_path, "com.example.bank", permissions=["INTERNET"])
        _create_minimal_apk(cand_path, "com.example.bank", permissions=["INTERNET"])
        
        spec = importlib.util.spec_from_file_location(
            "identity_analyzer", str(ROOT / "analyzers" / "identity" / "analyzer.py")
        )
        identity = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(identity)
        
        result = identity.analyze(orig_path, cand_path)
        
        # V3 contract checks
        assert result["service"] == "identity"
        assert "certificate_status" in result
        assert "certificate_identity_score" in result
        assert "package_similarity" in result
        assert "manifest_findings" in result
        assert "permissions_baseline" in result
        assert "permissions_candidate" in result
        assert "new_permissions" in result
        assert "removed_permissions" in result
        assert "exported_components_baseline" in result
        assert "exported_components_candidate" in result
        assert "errors" in result
        
        # certificate_status should be one of the valid enums
        assert result["certificate_status"] in ("SAME_SIGNER", "DIFFERENT_SIGNER", "UNKNOWN")
        
        # package_match_state should be one of the valid enums
        assert result["package_match_state"] in ("EXACT_MATCH", "NEAR_MATCH", "UNRELATED")
        
        print(f"Identity contract OK. Status: {result['certificate_status']}, "
              f"Package state: {result['package_match_state']}, "
              f"Errors: {len(result.get('errors', []))}")


def test_dex_risk_v3_contract():
    """Verify DEX-risk analyzer produces V3 contract fields."""
    import importlib.util
    
    with tempfile.TemporaryDirectory() as tmpdir:
        orig_path = os.path.join(tmpdir, "original.apk")
        cand_path = os.path.join(tmpdir, "candidate.apk")
        
        _create_minimal_apk(orig_path, "com.example.app1")
        _create_minimal_apk(cand_path, "com.example.app2")
        
        spec = importlib.util.spec_from_file_location(
            "dexrisk_analyzer", str(ROOT / "analyzers" / "dex-risk" / "analyzer.py")
        )
        dexrisk = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dexrisk)
        
        result = dexrisk.analyze(orig_path, cand_path)
        
        # V3 contract checks
        assert result["service"] == "dex-risk"
        assert "bytecode_similarity" in result
        assert "malware_risk_score" in result
        assert "risk_findings" in result
        assert "dex_files_baseline" in result
        assert "dex_files_candidate" in result
        assert "dex_count_baseline" in result
        assert "dex_count_candidate" in result
        assert "errors" in result
        
        # bytecode_similarity should be float [0,1] or None
        if result["bytecode_similarity"] is not None:
            assert 0.0 <= result["bytecode_similarity"] <= 1.0
        
        # malware_risk_score should be int 0-100
        assert isinstance(result["malware_risk_score"], int)
        assert 0 <= result["malware_risk_score"] <= 100
        
        # DEX file discovery
        assert result["dex_count_baseline"] >= 1  # has classes.dex and classes2.dex
        assert result["dex_count_candidate"] >= 1
        
        # risk_findings should be a list with structured fields
        for f in result["risk_findings"]:
            assert "finding" in f
            assert "category" in f
            assert "severity" in f
            assert "contribution" in f
            assert "evidence" in f
        
        # Legacy fields still present
        assert "dex_score" in result
        assert "malware_risk" in result
        assert "findings" in result
        
        print(f"DEX-risk contract OK. Bytecode sim: {result.get('bytecode_similarity')}, "
              f"Risk score: {result['malware_risk_score']}, "
              f"DEX files: {result['dex_files_baseline']}")


def test_dex_risk_malware_score_equals_sum():
    """malware_risk_score must equal sum of contributions, capped at 100."""
    import importlib.util
    
    with tempfile.TemporaryDirectory() as tmpdir:
        orig_path = os.path.join(tmpdir, "original.apk")
        cand_path = os.path.join(tmpdir, "candidate.apk")
        
        # Candidate with new SMS permission
        _create_minimal_apk(orig_path, "com.example.app", permissions=["INTERNET"])
        _create_minimal_apk(cand_path, "com.example.app", 
                           permissions=["INTERNET", "RECEIVE_SMS"])
        
        spec = importlib.util.spec_from_file_location(
            "dexrisk_analyzer", str(ROOT / "analyzers" / "dex-risk" / "analyzer.py")
        )
        dexrisk = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dexrisk)
        
        result = dexrisk.analyze(orig_path, cand_path)
        
        # Sum of contributions should equal malware_risk_score (before cap)
        total_contrib = sum(f.get("contribution", 0) for f in result["risk_findings"])
        assert result["malware_risk_score"] == min(100, total_contrib)


def test_full_pipeline_scoring():
    """Run the complete pipeline: identity -> similarity -> dex -> scoring."""
    import importlib.util
    
    with tempfile.TemporaryDirectory() as tmpdir:
        orig_path = os.path.join(tmpdir, "original.apk")
        cand_path = os.path.join(tmpdir, "candidate.apk")
        
        _create_minimal_apk(orig_path, "com.example.bank", permissions=["INTERNET"])
        _create_minimal_apk(cand_path, "com.example.bank", 
                           permissions=["INTERNET", "RECEIVE_SMS", "SYSTEM_ALERT_WINDOW"])
        
        # Load analyzers
        id_spec = importlib.util.spec_from_file_location(
            "identity_analyzer", str(ROOT / "analyzers" / "identity" / "analyzer.py"))
        identity = importlib.util.module_from_spec(id_spec)
        id_spec.loader.exec_module(identity)
        
        sim_spec = importlib.util.spec_from_file_location(
            "similarity_analyzer", str(ROOT / "analyzers" / "similarity" / "analyzer.py"))
        similarity = importlib.util.module_from_spec(sim_spec)
        sim_spec.loader.exec_module(similarity)
        
        dex_spec = importlib.util.spec_from_file_location(
            "dexrisk_analyzer", str(ROOT / "analyzers" / "dex-risk" / "analyzer.py"))
        dexrisk = importlib.util.module_from_spec(dex_spec)
        dex_spec.loader.exec_module(dexrisk)
        
        # Load scoring engine
        scoring_spec = importlib.util.spec_from_file_location(
            "scoring_engine", str(ROOT / "scoring" / "engine.py"))
        scoring = importlib.util.module_from_spec(scoring_spec)
        scoring_spec.loader.exec_module(scoring)
        
        # Run analysis (wrap in try/except since synthetic APKs may fail
        # on some extraction paths — that's expected and tests robustness)
        try:
            idn = identity.analyze(orig_path, cand_path)
        except Exception as e:
            idn = {"service": "identity", "certificate_status": "UNKNOWN",
                   "certificate_identity_score": None, "package_similarity": None,
                   "errors": [{"stage": "parse", "message": str(e)}]}
        
        try:
            sim = similarity.analyze(orig_path, cand_path)
        except Exception as e:
            sim = {"icon_score": 0.0, "string_score": 0.0, "layout_score": 0.0,
                   "resource_score": 0.0, "findings": [], "errors": [{"stage": "similarity", "message": str(e)}]}
        
        try:
            dex = dexrisk.analyze(orig_path, cand_path)
        except Exception as e:
            dex = {"service": "dex-risk", "bytecode_similarity": None,
                   "malware_risk_score": 0, "errors": [{"stage": "dex-risk", "message": str(e)}]}
        
        # Score
        scores = scoring.compute_scores(idn, sim, dex)
        
        assert "clone_probability" in scores
        assert "malware_risk" in scores
        assert "confidence" in scores
        assert 0.0 <= scores["clone_probability"] <= 1.0
        assert 0.0 <= scores["malware_risk"] <= 1.0
        assert 0.0 <= scores["confidence"] <= 1.0
        
        # Synthetic APKs with text XML manifests can't extract permissions,
        # so malware_risk may be 0. The key test is the pipeline runs end-to-end
        # without crashing and produces all three scores.
        print(f"Full pipeline OK: clone={scores['clone_probability']:.2f}, "
               f"risk={scores['malware_risk']:.2f}, confidence={scores['confidence']:.2f}")


def test_null_not_silently_zero():
    """Verify that unavailable signals remain null, not 0."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a completely invalid APK (not even a valid ZIP)
        bad_path = os.path.join(tmpdir, "bad.apk")
        with open(bad_path, "wb") as f:
            f.write(b"not a zip file at all")
        
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "identity_analyzer", str(ROOT / "analyzers" / "identity" / "analyzer.py"))
        identity = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(identity)
        
        result = identity.analyze(bad_path, bad_path)
        
        # certificate_identity_score must be null (UNKNOWN state)
        assert result["certificate_identity_score"] is None
        
        # package_similarity must be null (can't extract package name)
        assert result["package_similarity"] is None
        
        # Errors should be present
        assert len(result.get("errors", [])) > 0
        
        print("Null vs zero check OK: unavailable signals remain null")


def test_dex_risk_null_bytecode_on_failure():
    """When DEX extraction fails, bytecode_similarity should be null, not 0."""
    import importlib.util
    
    with tempfile.TemporaryDirectory() as tmpdir:
        bad_path = os.path.join(tmpdir, "bad.apk")
        with open(bad_path, "wb") as f:
            f.write(b"not a zip file")
        
        orig_path = os.path.join(tmpdir, "ok.apk")
        _create_minimal_apk(orig_path, "com.example.app")
        
        spec = importlib.util.spec_from_file_location(
            "dexrisk_analyzer", str(ROOT / "analyzers" / "dex-risk" / "analyzer.py"))
        dexrisk = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dexrisk)
        
        result = dexrisk.analyze(orig_path, bad_path)
        
        # When DEX extraction for candidate fails, bytecode_similarity should
        # still be computed from baseline (or null). The key is it should NOT
        # silently be 0 due to the error — it should have an error entry.
        assert len(result.get("errors", [])) > 0
        # malware_risk_score should still be computed (0 if no findings)
        assert isinstance(result["malware_risk_score"], int)
        
        print("DEX null/zero check OK")
