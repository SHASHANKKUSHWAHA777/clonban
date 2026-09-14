"""
APK utility functions.

Responsibilities:
  - APK/ZIP validation (exists + is a valid ZIP).
  - Safe ZIP extraction with path-traversal defense.
  - androguard parsing wrapper with graceful error handling.
  - DEX file discovery inside an APK (classes.dex, classes2.dex, ...).

All functions treat APK contents as untrusted input.
"""
import logging
import os
import re
import zipfile
from pathlib import Path
from typing import Optional

from androguard.core.apk import APK, BrokenAPKError as AndroguardError

from analyzers.common.errors import AnalyzerError

logger = logging.getLogger("clonedetector.apk_utils")

DEX_RE = re.compile(r"^classes(\d+)?\.dex$")

MAX_EXTRACTED_SIZE = 100 * 1024 * 1024  # 100 MiB safety limit


def is_valid_apk(path: str) -> bool:
    """Return True if *path* exists and is an openable ZIP (APK)."""
    if not path or not os.path.isfile(path):
        return False
    try:
        with zipfile.ZipFile(path, "r") as zf:
            # Trigger actual read of central directory.
            _ = zf.testzip()
        return True
    except (zipfile.BadZipFile, OSError, AndroguardError):
        return False
    except Exception:
        logger.warning("Unexpected error validating APK %s", path, exc_info=True)
        return False


def validate_apk(path: str, label: str = "APK") -> Optional[str]:
    """
    Validate APK file and return an error string, or None if valid.
    """
    if not path:
        return f"{label} path is empty"
    if not os.path.isfile(path):
        return f"{label} file does not exist: {path}"
    if os.path.getsize(path) == 0:
        return f"{label} file is empty: {path}"
    try:
        with zipfile.ZipFile(path, "r") as zf:
            bad = zf.testzip()
            if bad:
                return f"{label} ZIP integrity check failed on entry: {bad}"
    except zipfile.BadZipFile:
        return f"{label} is not a valid ZIP/APK: {path}"
    except Exception as e:
        return f"{label} could not be validated: {e}"
    return None


def safe_zip_extract(zf: zipfile.ZipFile, dest: str, max_size: int = MAX_EXTRACTED_SIZE) -> list[str]:
    """
    Extract all members of *zf* into *dest*, defending against:
      - Path traversal (../../etc/passwd).
      - Absolute paths.
      - Size overflow (entries whose uncompressed size exceeds *max_size* total).
    Returns list of extracted file paths.
    """
    dest_abs = os.path.abspath(dest)
    extracted = []
    total = 0
    for info in zf.infolist():
        if info.is_dir():
            continue
        # Sanitize: strip leading slashes, resolve within dest.
        target = os.path.normpath(os.path.join(dest_abs, info.filename))
        if not target.startswith(dest_abs + os.sep) and target != dest_abs:
            logger.warning("Path traversal blocked: %s", info.filename)
            continue
        # Size guard
        if info.file_size > max_size or total + info.file_size > max_size:
            logger.warning("File too large, skipping: %s (%d bytes)", info.filename, info.file_size)
            continue
        total += info.file_size
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with zf.open(info) as src, open(target, "wb") as dst:
            while True:
                chunk = src.read(64 * 1024)
                if not chunk:
                    break
                dst.write(chunk)
        extracted.append(target)
    return extracted


def parse_apk(path: str) -> APK:
    """
    Parse an APK via androguard. Raises AnalyzerError on failure.
    Handles androguard version differences (engine/testzip params may not exist).
    """
    try:
        try:
            apk = APK(path, testzip=False)
        except TypeError:
            # Some androguard versions don't accept testzip kwarg.
            apk = APK(path)
        if not apk.valid:
            raise AnalyzerError("parse", f"APK structure invalid: {path}", detail=str(apk.error))
        return apk
    except AnalyzerError:
        raise
    except AndroguardError as e:
        raise AnalyzerError("parse", f"APK could not be parsed: {path}", detail=str(e))
    except Exception as e:
        raise AnalyzerError("parse", f"APK could not be parsed: {path}", detail=str(e))


def normalize_fingerprint(fp: Optional[str]) -> Optional[str]:
    """
    Normalize a certificate fingerprint for comparison:
      - Strip colons and whitespace.
      - Lowercase for case-insensitive comparison.
    """
    if not fp:
        return None
    return re.sub(r"[: \t\n]", "", fp).lower()


def discover_dex_files(apk: APK) -> list[str]:
    """
    Return a deterministic list of DEX file names contained in the APK.
    e.g. ['classes.dex', 'classes2.dex', 'classes3.dex']
    """
    if not apk or not hasattr(apk, "_zip"):
        return []
    names = []
    try:
        names = [n for n in apk._zip.namelist() if DEX_RE.match(n)]
    except Exception:
        logger.warning("DEX discovery failed", exc_info=True)
    names.sort()
    return names


def extract_dex_bytes(apk: APK, dex_name: str) -> Optional[bytes]:
    """Read raw bytes of a named DEX entry from the APK archive."""
    if not apk or not hasattr(apk, "_zip"):
        return None
    try:
        return apk._zip.read(dex_name)
    except KeyError:
        return None
    except Exception:
        logger.warning("Could not read DEX entry %s", dex_name, exc_info=True)
        return None


def safe_filename(name: str) -> str:
    """Sanitize a filename to be safe for filesystem use."""
    return re.sub(r"[^a-zA-Z0-9._-]", "_", name) or "unnamed"