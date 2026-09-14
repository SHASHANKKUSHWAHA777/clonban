"""
Resource Analyzer (V3)

Extracts and compares three independent resource categories from APK files:

  A. USER-VISIBLE STRINGS  (res/values*/strings.xml)
     - Text content, language tags, key names
     - Token-level + TF-IDF cosine similarity

  B. NON-IMAGE ASSETS      (assets/**, res/raw/**, META-INF/**)
     - File names, extensions, sizes
     - Jaccard overlap + size-distribution correlation

  C. IMAGE/DRAWABLES       (res/drawable*, res/mipmap*, res/*.png, *.webp)
     - Perceptual hashing (pHash) via imagehash
     - Hamming distance aggregation across all drawable pairs

V3 contract
-----------
{
  "service": "resource",
  "string_score": 0.92,          # float [0,1] or null
  "asset_score": 0.81,           # float [0,1] or null
  "image_score": 0.95,           # float [0,1] or null
  "resource_score": 0.90,        # weighted aggregate OR null if all sub-scores are null
  "findings": [...],             # list of notable observations
  "errors": [{"stage": "...", "message": "..."}],
  "string_details": {...},
  "asset_details": {...},
  "image_details": {...},
  # Legacy alias for backward compat with similarity.analyzer.py
  "resource_score_legacy": 0.90,
}

Every numeric score uses null when unavailable — never silently converted to 0.
"""
import hashlib
import io
import logging
import zipfile
from typing import Optional

import imagehash
from PIL import Image

logger = logging.getLogger("clonedetector.resource")

MAX_PHASH_DISTANCE = 64


def _open_apk(path: str) -> Optional[zipfile.ZipFile]:
    try:
        return zipfile.ZipFile(path, "r")
    except (zipfile.BadZipFile, FileNotFoundError, OSError) as e:
        logger.warning("Cannot open APK %s: %s", path, e)
        return None


# -----------------------------------------------------------------------
# A. Strings
# -----------------------------------------------------------------------

def _extract_strings(path: str, z: zipfile.ZipFile) -> dict:
    """Extract string values from strings.xml files; return {keys, values, langs}.

    Tries AXMLPrinter first (binary XML), then falls back to standard
    ElementTree for plain-text XML (synthetic test APKs, some build outputs).
    """
    keys: list[str] = []
    values: list[str] = []
    langs: set[str] = set()

    try:
        from androguard.core.axml import AXMLPrinter
        from xml.etree import ElementTree as ET
        string_files = [n for n in z.namelist()
                        if n.startswith("res/values") and n.endswith(".xml")]
        for name in string_files:
            try:
                raw = z.read(name)
                tree = None
                # Try AXMLPrinter (binary XML) first
                try:
                    printer = AXMLPrinter(raw)
                    tree = printer.get_xml_obj()
                except Exception:
                    logger.debug("AXMLPrinter failed for %s, trying ElementTree", name)

                # Fallback: plain XML via ElementTree
                if tree is None:
                    try:
                        tree = ET.fromstring(raw)
                    except Exception:
                        logger.debug("Plain XML parse also failed for %s", name)
                        continue

                for el in tree.iter("string"):
                    if el.text:
                        stripped = el.text.strip()
                        if stripped:
                            values.append(stripped)
                            if el.get("name"):
                                keys.append(el.get("name"))
                parts = name.split("/")
                if len(parts) >= 3 and "-" in parts[1]:
                    lang_tag = parts[1].split("-")[1]
                    langs.add(lang_tag)
                else:
                    langs.add("default")
            except Exception:
                logger.debug("Failed to parse strings.xml %s", name, exc_info=True)
    except ImportError:
        logger.warning("androguard.axml.AXMLPrinter not available")
    except Exception:
        logger.warning("Could not extract strings from %s", path, exc_info=True)

    return {"keys": keys, "values": values, "langs": langs}


def _string_similarity(strings_a: dict, strings_b: dict) -> tuple[Optional[float], dict]:
    """
    Return (score, details) where score combines token overlap and TF-IDF cosine.
    Score is None when both value sets are empty (signal genuinely unavailable).
    """
    vals_a = strings_a["values"]
    vals_b = strings_b["values"]

    if not vals_a and not vals_b:
        return None, _empty_string_details()

    if not vals_a or not vals_b:
        return 0.0, {
            "baseline_count": len(vals_a),
            "candidate_count": len(vals_b),
            "shared_tokens": 0,
            "jaccard": 0.0,
            "cosine": 0.0,
        }

    # Token-level Jaccard (lower-casing, word-split)
    tokens_a = set()
    tokens_b = set()
    for v in vals_a:
        tokens_a.update(v.lower().split())
    for v in vals_b:
        tokens_b.update(v.lower().split())

    intersection = len(tokens_a & tokens_b)
    union = len(tokens_a | tokens_b)
    jaccard = round(intersection / union, 4) if union else 0.0

    # TF-IDF cosine
    cosine: Optional[float] = None
    doc_a = " ".join(vals_a)
    doc_b = " ".join(vals_b)
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity
        vectorizer = TfidfVectorizer(lowercase=True, token_pattern=r"(?u)\b\w+\b")
        vectors = vectorizer.fit_transform([doc_a, doc_b])
        cosine = round(float(cosine_similarity(vectors[0], vectors[1])[0][0]), 4)
    except ValueError:
        cosine = jaccard
    except Exception:
        logger.warning("TF-IDF cosine failed", exc_info=True)
        cosine = jaccard

    if cosine is None:
        cosine = 0.0

    score = round(0.4 * jaccard + 0.6 * cosine, 4)
    return score, {
        "baseline_count": len(vals_a),
        "candidate_count": len(vals_b),
        "shared_tokens": intersection,
        "jaccard": jaccard,
        "cosine": cosine,
    }


def _empty_string_details() -> dict:
    return {
        "baseline_count": 0,
        "candidate_count": 0,
        "shared_tokens": 0,
        "jaccard": 0.0,
        "cosine": 0.0,
    }


# -----------------------------------------------------------------------
# B. Non-image assets
# -----------------------------------------------------------------------

def _basename_and_type(path: str) -> tuple[str, str]:
    """Return (dir_type, basename) — e.g. 'assets/icon.json' -> ('assets', 'icon.json')."""
    parts = path.split("/")
    if len(parts) >= 2:
        return (parts[0], parts[-1])
    return (path, "")


def _collect_assets(z: zipfile.ZipFile) -> dict:
    """
    Build a dict of {normalized_key: size_bytes} for all asset-like entries.
    normalized_key is (dir_type, basename) so that resource IDs that shift
    between builds don't cause false mismatches.
    """
    result: dict[tuple[str, str], int] = {}
    asset_exts = (".png", ".jpg", ".jpeg", ".webp", ".gif", ".json", ".xml",
                  ".txt", ".csv", ".html", ".otf", ".ttf", ".dat")
    for info in z.infolist():
        name = info.filename
        if info.is_dir():
            continue
        dir_type = name.split("/")[0] if "/" in name else ""
        if dir_type in ("assets", "raw"):
            key = _basename_and_type(name)
            result[key] = info.file_size
    return result


def _asset_similarity(assets_a: dict, assets_b: dict) -> tuple[Optional[float], dict]:
    """
    Compare two asset dicts keyed by (dir_type, basename) -> size.
    Returns (score, details).
    """
    keys_a = set(assets_a.keys())
    keys_b = set(assets_b.keys())

    if not keys_a and not keys_b:
        return None, _empty_asset_details()

    shared = keys_a & keys_b
    union = keys_a | keys_b
    jaccard = round(len(shared) / len(union), 4) if union else 0.0

    # Pearson correlation of sizes on shared keys
    size_corr: Optional[float] = None
    if len(shared) >= 2:
        sizes_a = [assets_a[k] for k in shared]
        sizes_b = [assets_b[k] for k in shared]
        size_corr = _pearson(sizes_a, sizes_b)

    # Score: weighted blend of name overlap and size correlation
    if size_corr is not None:
        score = round(0.5 * jaccard + 0.5 * max(size_corr, 0.0), 4)
    else:
        score = jaccard

    return score, {
        "baseline_files": len(keys_a),
        "candidate_files": len(keys_b),
        "shared_names": len(shared),
        "jaccard": jaccard,
        "size_correlation": size_corr,
    }


def _empty_asset_details() -> dict:
    return {
        "baseline_files": 0,
        "candidate_files": 0,
        "shared_names": 0,
        "jaccard": 0.0,
        "size_correlation": None,
    }


def _pearson(x: list, y: list) -> Optional[float]:
    n = len(x)
    if n < 2:
        return None
    mean_x = sum(x) / n
    mean_y = sum(y) / n
    num = sum((xi - mean_x) * (yi - mean_y) for xi, yi in zip(x, y))
    den_x = (sum((xi - mean_x) ** 2 for xi in x)) ** 0.5
    den_y = (sum((yi - mean_y) ** 2 for yi in y)) ** 0.5
    if den_x == 0 or den_y == 0:
        return None
    return round(num / (den_x * den_y), 4)


# -----------------------------------------------------------------------
# C. Images / drawables
# -----------------------------------------------------------------------

def _image_entries(z: zipfile.ZipFile) -> list[str]:
    """Return paths to image-like drawables (png, jpg, webp, gif)."""
    image_exts = (".png", ".jpg", ".jpeg", ".webp", ".gif")
    return [n for n in z.namelist()
            if (n.startswith("res/drawable") or n.startswith("res/mipmap"))
            and n.lower().endswith(image_exts)]


def _compute_phashes(z: zipfile.ZipFile) -> list[imagehash.ImageHash]:
    hashes: list[imagehash.ImageHash] = []
    for entry in _image_entries(z):
        try:
            data = z.read(entry)
            img = Image.open(io.BytesIO(data)).convert("RGBA")
            hashes.append(imagehash.phash(img))
        except Exception:
            logger.debug("Could not hash image %s", entry, exc_info=True)
    return hashes


def _image_similarity(hashes_a: list, hashes_b: list) -> tuple[Optional[float], dict]:
    if not hashes_a and not hashes_b:
        return None, _empty_image_details()

    if not hashes_a or not hashes_b:
        score = 0.0
        return score, {
            "baseline_images": len(hashes_a),
            "candidate_images": len(hashes_b),
            "avg_phash_distance": None,
            "max_phash_distance": None,
        }

    distances: list[float] = []
    for ha in hashes_a:
        min_dist = min(float(ha - hb) for hb in hashes_b)
        distances.append(min_dist)

    avg_dist = round(sum(distances) / len(distances), 4) if distances else None
    max_dist = round(max(distances), 4) if distances else None

    if avg_dist is None:
        score = 0.0
    else:
        score = round(max(0.0, 1 - (avg_dist / MAX_PHASH_DISTANCE)), 4)

    return score, {
        "baseline_images": len(hashes_a),
        "candidate_images": len(hashes_b),
        "avg_phash_distance": avg_dist,
        "max_phash_distance": max_dist,
    }


def _empty_image_details() -> dict:
    return {
        "baseline_images": 0,
        "candidate_images": 0,
        "avg_phash_distance": None,
        "max_phash_distance": None,
    }


# -----------------------------------------------------------------------
# Orchestration
# -----------------------------------------------------------------------

def analyze(original_path: str, candidate_path: str) -> dict:
    """
    Analyze resource similarity between two APKs.

    All three sub-analyses (strings, assets, images) degrade independently.
    A pHash failure in images does not void string or asset comparison.
    """
    errors: list[dict] = []
    findings: list[dict] = []
    sub_weights = {"strings": 0.4, "assets": 0.3, "images": 0.3}

    za = _open_apk(original_path)
    zb = _open_apk(candidate_path)

    if za is None:
        errors.append({"stage": "resource", "message": f"Could not open baseline APK: {original_path}"})
    if zb is None:
        errors.append({"stage": "resource", "message": f"Could not open candidate APK: {candidate_path}"})

    # ---- Strings ----
    string_score: Optional[float] = None
    string_details: dict = _empty_string_details()
    if za is not None and zb is not None:
        try:
            sa = _extract_strings(original_path, za)
            sb = _extract_strings(candidate_path, zb)
            string_score, string_details = _string_similarity(sa, sb)
            if string_score is not None and string_score >= 0.95:
                findings.append({
                    "type": "STRINGS_IDENTICAL",
                    "category": "RESOURCE",
                    "severity": "info",
                    "evidence": f"{string_details['shared_tokens']} shared tokens; cosine={string_details['cosine']}",
                })
        except Exception as e:
            errors.append({"stage": "strings", "message": str(e)})
            logger.exception("String analysis failed")

    # ---- Assets ----
    asset_score: Optional[float] = None
    asset_details: dict = _empty_asset_details()
    if za is not None and zb is not None:
        try:
            aa = _collect_assets(za)
            ab = _collect_assets(zb)
            asset_score, asset_details = _asset_similarity(aa, ab)
        except Exception as e:
            errors.append({"stage": "assets", "message": str(e)})
            logger.exception("Asset analysis failed")

    # ---- Images ----
    image_score: Optional[float] = None
    image_details: dict = _empty_image_details()
    if za is not None and zb is not None:
        try:
            ha = _compute_phashes(za)
            hb = _compute_phashes(zb)
            image_score, image_details = _image_similarity(ha, hb)
            if image_score is not None and image_score >= 0.90:
                findings.append({
                    "type": "IMAGES_IDENTICAL",
                    "category": "RESOURCE",
                    "severity": "info",
                    "evidence": f"avg pHash distance={image_details['avg_phash_distance']}",
                })
        except Exception as e:
            errors.append({"stage": "images", "message": str(e)})
            logger.exception("Image analysis failed")

    # ---- Aggregate ----
    score_lookup = {
        "strings": string_score,
        "assets": asset_score,
        "images": image_score,
    }
    available = [k for k in sub_weights if score_lookup[k] is not None]
    weighted_sum = sum(score_lookup[k] * sub_weights[k] for k in available)
    total_weight = sum(sub_weights[k] for k in available)
    resource_score: Optional[float] = (
        round(weighted_sum / total_weight, 4) if total_weight else None
    )

    # Cleanup
    if za:
        za.close()
    if zb:
        zb.close()

    result = {
        "service": "resource",
        "string_score": string_score,
        "asset_score": asset_score,
        "image_score": image_score,
        "resource_score": resource_score,
        "findings": findings,
        "errors": errors,
        "string_details": string_details,
        "asset_details": asset_details,
        "image_details": image_details,
        "resource_score_legacy": resource_score,
    }

    # Add MD5 fingerprint for caching
    for label, path in (("original", original_path), ("candidate", candidate_path)):
        try:
            with open(path, "rb") as f:
                result[f"{label}_md5"] = hashlib.md5(f.read()).hexdigest()
        except Exception:
            result[f"{label}_md5"] = None

    return result
