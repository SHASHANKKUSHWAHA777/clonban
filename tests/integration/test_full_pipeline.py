"""
End-to-end pipeline test (Phase 10).

Requires real APK files under tests/samples/{original,clone,modified,unrelated}/
which are NOT included in this repo (APK binaries shouldn't be committed).
Drop your own test APKs there — see tests/samples/README.md — and this test
will run for real; otherwise it's skipped so `pytest` stays green in CI/dev
without sample binaries.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

SAMPLES = ROOT / "tests" / "samples"


def _first_apk(folder: Path) -> Path | None:
    if not folder.exists():
        return None
    apks = list(folder.glob("*.apk"))
    return apks[0] if apks else None


ORIGINAL = _first_apk(SAMPLES / "original")
CLONE = _first_apk(SAMPLES / "clone")
UNRELATED = _first_apk(SAMPLES / "unrelated")


@pytest.mark.skipif(not (ORIGINAL and CLONE), reason="drop sample APKs into tests/samples/ to run this")
def test_clone_scores_higher_than_unrelated():
    import importlib.util

    def load(path, name):
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    identity = load(ROOT / "analyzers" / "identity" / "analyzer.py", "identity")
    similarity = load(ROOT / "analyzers" / "similarity" / "analyzer.py", "similarity")
    dexrisk = load(ROOT / "analyzers" / "dex-risk" / "analyzer.py", "dexrisk")
    from scoring.engine import compute_scores

    def full_score(orig, cand):
        idn = identity.analyze(str(orig), str(cand))
        sim = similarity.analyze(str(orig), str(cand))
        dex = dexrisk.analyze(str(orig), str(cand))
        return compute_scores(idn, sim, dex)["clone_probability"]

    clone_score = full_score(ORIGINAL, CLONE)

    if UNRELATED:
        unrelated_score = full_score(ORIGINAL, UNRELATED)
        assert clone_score > unrelated_score
    else:
        assert clone_score > 0.4
