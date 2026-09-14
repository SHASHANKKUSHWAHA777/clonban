"""
Visual + Resource Similarity Analyzer (Phase 4)

Compares icons (perceptual hashing), strings.xml content (TF-IDF cosine),
compiled layout XML structure, and general resource file overlap.

KNOWN LIMITATION (documented per project rule #7): full layout diffing on
compiled AXML requires locating every res/layout/*.xml inside the APK and
decoding each with androguard's AXMLPrinter. This is done best-effort per
file; APKs that heavily obfuscate/merge resources may yield a lower-confidence
layout_score — that uncertainty should be reflected in the overall
Confidence score by the scoring engine, not hidden.
"""
import io
import logging
import zipfile
from collections import Counter

import imagehash
from PIL import Image
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from analyzers.identity.analyzer import get_apk_object

logger = logging.getLogger("clonedetector.similarity")

MAX_PHASH_DISTANCE = 64  # theoretical max for a 64-bit perceptual hash


def _extract_icon_image(apk_path: str, apk_obj) -> Image.Image | None:
    try:
        icon_name = apk_obj.get_app_icon()
        if not icon_name:
            return None
        with zipfile.ZipFile(apk_path) as z:
            data = z.read(icon_name)
        return Image.open(io.BytesIO(data)).convert("RGBA")
    except Exception:
        logger.warning("Could not extract icon from %s", apk_path, exc_info=True)
        return None


def _icon_similarity(orig_path: str, cand_path: str, orig_apk, cand_apk) -> tuple[float, int | None]:
    img_a = _extract_icon_image(orig_path, orig_apk)
    img_b = _extract_icon_image(cand_path, cand_apk)
    if img_a is None or img_b is None:
        return 0.0, None
    hash_a, hash_b = imagehash.phash(img_a), imagehash.phash(img_b)
    distance = hash_a - hash_b
    score = round(max(0.0, 1 - (distance / MAX_PHASH_DISTANCE)), 4)
    return score, int(distance)


def _extract_strings_xml_values(apk_path: str) -> list[str]:
    """Best-effort extraction of user-visible strings from res/values*/strings.xml."""
    values = []
    try:
        with zipfile.ZipFile(apk_path) as z:
            candidates = [n for n in z.namelist() if n.startswith("res/values") and n.endswith(".xml")]
            from androguard.core.axml import AXMLPrinter
            for name in candidates:
                try:
                    raw = z.read(name)
                    printer = AXMLPrinter(raw)
                    tree = printer.get_xml_obj()
                    for el in tree.iter("string"):
                        if el.text:
                            values.append(el.text.strip())
                except Exception:
                    continue
    except Exception:
        logger.warning("Could not read strings from %s", apk_path, exc_info=True)
    return values


def _string_similarity(orig_path: str, cand_path: str) -> float:
    strings_a = _extract_strings_xml_values(orig_path)
    strings_b = _extract_strings_xml_values(cand_path)
    if not strings_a or not strings_b:
        return 0.0

    doc_a = " ".join(strings_a)
    doc_b = " ".join(strings_b)
    try:
        vectorizer = TfidfVectorizer().fit([doc_a, doc_b])
        vectors = vectorizer.transform([doc_a, doc_b])
        sim = cosine_similarity(vectors[0], vectors[1])[0][0]
        return round(float(sim), 4)
    except ValueError:
        # e.g. only stopwords / empty vocab after vectorizing
        set_a, set_b = set(strings_a), set(strings_b)
        return round(len(set_a & set_b) / max(len(set_a | set_b), 1), 4)


def _layout_view_signature(apk_path: str) -> Counter:
    """Counts view tag types across every layout XML file — a coarse structural fingerprint."""
    signature = Counter()
    try:
        with zipfile.ZipFile(apk_path) as z:
            layout_files = [n for n in z.namelist() if n.startswith("res/layout") and n.endswith(".xml")]
            from androguard.core.axml import AXMLPrinter
            for name in layout_files:
                try:
                    raw = z.read(name)
                    printer = AXMLPrinter(raw)
                    tree = printer.get_xml_obj()
                    for el in tree.iter():
                        tag = el.tag.split("}")[-1] if "}" in str(el.tag) else el.tag
                        signature[tag] += 1
                except Exception:
                    continue
    except Exception:
        logger.warning("Could not read layouts from %s", apk_path, exc_info=True)
    return signature


def _layout_similarity(orig_path: str, cand_path: str) -> float:
    sig_a, sig_b = _layout_view_signature(orig_path), _layout_view_signature(cand_path)
    if not sig_a and not sig_b:
        return 0.0
    all_keys = set(sig_a) | set(sig_b)
    if not all_keys:
        return 0.0
    num = sum(min(sig_a.get(k, 0), sig_b.get(k, 0)) for k in all_keys)
    den = sum(max(sig_a.get(k, 0), sig_b.get(k, 0)) for k in all_keys)
    return round(num / den, 4) if den else 0.0


def _resource_similarity(orig_path: str, cand_path: str) -> float:
    try:
        with zipfile.ZipFile(orig_path) as za, zipfile.ZipFile(cand_path) as zb:
            names_a = {n for n in za.namelist() if n.startswith("res/")}
            names_b = {n for n in zb.namelist() if n.startswith("res/")}
        # Compare by (dir_type, basename) rather than exact path — resource
        # IDs/paths shift between builds even for the same underlying asset.
        def norm(names):
            out = set()
            for n in names:
                parts = n.split("/")
                if len(parts) >= 3:
                    out.add((parts[1].split("-")[0], parts[-1]))
            return out
        na, nb = norm(names_a), norm(names_b)
        if not na and not nb:
            return 0.0
        return round(len(na & nb) / max(len(na | nb), 1), 4)
    except Exception:
        logger.warning("Could not compare resources for %s vs %s", orig_path, cand_path, exc_info=True)
        return 0.0


def analyze(original_path: str, candidate_path: str, report_dir: str | None = None) -> dict:
    orig_apk = get_apk_object(original_path)
    cand_apk = get_apk_object(candidate_path)

    icon_score, icon_distance = _icon_similarity(original_path, candidate_path, orig_apk, cand_apk)
    string_score = _string_similarity(original_path, candidate_path)
    layout_score = _layout_similarity(original_path, candidate_path)
    resource_score = _resource_similarity(original_path, candidate_path)

    findings = []
    if icon_score >= 0.9:
        findings.append({"type": "ICON_NEAR_IDENTICAL", "severity": "low",
                          "evidence": f"Perceptual hash distance {icon_distance} of {MAX_PHASH_DISTANCE}."})

    diff_image_path = None
    if report_dir:
        diff_image_path = _save_icon_side_by_side(original_path, candidate_path, orig_apk, cand_apk, report_dir)

    return {
        "icon_score": icon_score,
        "icon_phash_distance": icon_distance,
        "string_score": string_score,
        "layout_score": layout_score,
        "resource_score": resource_score,
        "diff_image_path": diff_image_path,
        "findings": findings,
    }


def _save_icon_side_by_side(orig_path, cand_path, orig_apk, cand_apk, report_dir) -> str | None:
    try:
        img_a = _extract_icon_image(orig_path, orig_apk)
        img_b = _extract_icon_image(cand_path, cand_apk)
        if img_a is None or img_b is None:
            return None
        size = (256, 256)
        img_a = img_a.resize(size)
        img_b = img_b.resize(size)
        combined = Image.new("RGBA", (size[0] * 2 + 20, size[1]), (255, 255, 255, 255))
        combined.paste(img_a, (0, 0))
        combined.paste(img_b, (size[0] + 20, 0))
        import os
        os.makedirs(report_dir, exist_ok=True)
        out_path = f"{report_dir}/icon_diff.png"
        combined.save(out_path)
        return out_path
    except Exception:
        logger.warning("Could not build icon diff image", exc_info=True)
        return None
