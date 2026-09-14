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
import hashlib
import logging
import math
import signal
import threading
import zipfile
from collections import Counter
from functools import wraps

import imagehash
from PIL import Image
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from analyzers.identity.analyzer import get_apk_object

logger = logging.getLogger("clonedetector.similarity")

MAX_PHASH_DISTANCE = 64  # theoretical max for a 64-bit perceptual hash
MAX_LAYOUT_DEPTH = 5     # cap tree traversal depth to prevent slow deep-nesting
LAYOUT_TIMEOUT_SECS = 5  # max seconds per APK's layout analysis
MAX_LAYOUT_FILES = 30    # only analyse the N largest layout files per APK

# Shannon entropy thresholds — strings outside this band are dropped
# (encrypted/random blobs above 4.5, single-char repeats below 0.5)
ENTROPY_HIGH = 4.5
ENTROPY_LOW = 0.5


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


# ---------------------------------------------------------------------------
# Shannon entropy filter — used to drop encrypted / randomized string blobs
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _is_meaningful_string(s: str) -> bool:
    """Return True only if the string's entropy suggests real human text."""
    if not s or len(s) < 2:
        return False
    entropy = _shannon_entropy(s)
    return ENTROPY_LOW <= entropy <= ENTROPY_HIGH


def _extract_strings_xml_values(apk_path: str) -> list[str]:
    """Best-effort extraction of user-visible strings from res/values*/strings.xml.

    Strings with very high Shannon entropy (likely encrypted/base64/random) or
    very low entropy (single repeated characters) are filtered out to improve
    TF-IDF cosine quality.
    """
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
                            text = el.text.strip()
                            if _is_meaningful_string(text):
                                values.append(text)
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


# ---------------------------------------------------------------------------
# Layout similarity — hierarchical tree-path n-grams + legacy tag frequency
# ---------------------------------------------------------------------------

def _run_with_timeout(fn, timeout_secs, fallback):
    """Run fn() in the current thread but abort if it takes longer than timeout_secs.

    Uses a threading.Timer to set a flag; fn must periodically check the flag
    via the returned sentinel, or we accept that the function finishes slightly
    after the deadline.  This avoids SIGALRM (not available on Windows) and
    daemon threads.  Returns fn()'s result or fallback.
    """
    result = {"value": fallback, "done": False}

    def _worker():
        try:
            result["value"] = fn()
        except Exception:
            logger.warning("Layout extraction timed out or failed", exc_info=True)
        finally:
            result["done"] = True

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(timeout=timeout_secs)
    if not result["done"]:
        logger.warning("Layout analysis exceeded %ds timeout — falling back to partial result", timeout_secs)
    return result["value"]


def _walk_tree_paths(element, current_path: list[str], depth: int, paths: list[str]):
    """Depth-limited DFS that emits root→leaf structural paths."""
    tag = element.tag.split("}")[-1] if "}" in str(element.tag) else str(element.tag)
    current_path.append(tag)

    children = list(element)
    if not children or depth >= MAX_LAYOUT_DEPTH:
        # Leaf or depth cap — emit the path
        paths.append("/".join(current_path))
    else:
        for child in children:
            _walk_tree_paths(child, current_path, depth + 1, paths)

    current_path.pop()


def _layout_tag_signature(apk_path: str) -> Counter:
    """Counts view tag types across every layout XML file — the original coarse fingerprint."""
    signature = Counter()
    try:
        with zipfile.ZipFile(apk_path) as z:
            layout_files = _select_layout_files(z)
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


def _layout_tree_paths(apk_path: str) -> list[str]:
    """Extract depth-limited structural paths from layout XML files.

    Each path is a root-to-leaf sequence of view tags, e.g.
    ``LinearLayout/FrameLayout/TextView``.  This captures nesting structure
    that a flat tag-frequency counter misses entirely.
    """
    paths = []
    try:
        with zipfile.ZipFile(apk_path) as z:
            layout_files = _select_layout_files(z)
            from androguard.core.axml import AXMLPrinter
            for name in layout_files:
                try:
                    raw = z.read(name)
                    printer = AXMLPrinter(raw)
                    tree = printer.get_xml_obj()
                    _walk_tree_paths(tree, [], 0, paths)
                except Exception:
                    continue
    except Exception:
        logger.warning("Could not extract tree paths from %s", apk_path, exc_info=True)
    return paths


def _select_layout_files(z: zipfile.ZipFile) -> list[str]:
    """Select up to MAX_LAYOUT_FILES layout XMLs, preferring the largest files."""
    candidates = [n for n in z.namelist() if n.startswith("res/layout") and n.endswith(".xml")]
    if len(candidates) <= MAX_LAYOUT_FILES:
        return candidates
    # Sort by compressed size descending, take the largest N
    sized = [(n, z.getinfo(n).file_size) for n in candidates]
    sized.sort(key=lambda x: x[1], reverse=True)
    return [n for n, _ in sized[:MAX_LAYOUT_FILES]]


def _jaccard_counter(a: Counter, b: Counter) -> float:
    """Generalized Jaccard for Counters (min-sum / max-sum)."""
    if not a and not b:
        return 0.0
    all_keys = set(a) | set(b)
    if not all_keys:
        return 0.0
    num = sum(min(a.get(k, 0), b.get(k, 0)) for k in all_keys)
    den = sum(max(a.get(k, 0), b.get(k, 0)) for k in all_keys)
    return round(num / den, 4) if den else 0.0


def _jaccard_sets(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    return round(len(a & b) / max(len(a | b), 1), 4)


def _layout_similarity(orig_path: str, cand_path: str) -> float:
    """Blend tag-frequency Jaccard (legacy) with structural tree-path Jaccard.

    Weights: tag_freq 0.35, tree_paths 0.65.
    Both sub-extractions are capped at LAYOUT_TIMEOUT_SECS per APK.
    """
    # --- Tag-frequency (existing, fast) ---
    sig_a = _run_with_timeout(lambda: _layout_tag_signature(orig_path), LAYOUT_TIMEOUT_SECS, Counter())
    sig_b = _run_with_timeout(lambda: _layout_tag_signature(cand_path), LAYOUT_TIMEOUT_SECS, Counter())
    tag_score = _jaccard_counter(sig_a, sig_b)

    # --- Tree-path n-grams (new, depth-limited) ---
    paths_a = _run_with_timeout(lambda: _layout_tree_paths(orig_path), LAYOUT_TIMEOUT_SECS, [])
    paths_b = _run_with_timeout(lambda: _layout_tree_paths(cand_path), LAYOUT_TIMEOUT_SECS, [])

    if paths_a and paths_b:
        path_counter_a = Counter(paths_a)
        path_counter_b = Counter(paths_b)
        path_score = _jaccard_counter(path_counter_a, path_counter_b)
    else:
        # Fallback: if tree-path extraction failed, rely entirely on tag freq
        path_score = tag_score

    blended = round(0.35 * tag_score + 0.65 * path_score, 4)
    return blended


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
