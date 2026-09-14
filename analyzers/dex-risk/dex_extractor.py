"""
DEX file extractor (Phase 4.1, 4.2).

Discovers and extracts DEX files from an APK in a deterministic order.
Supports classes.dex, classes2.dex, classes3.dex, and any classesN.dex.

Lightweight normalization (documented per spec):
  - DEX files are sorted by filename for deterministic ordering.
  - For fuzzy hashing, DEX bytes are concatenated in sorted order.
  - No destructive normalization — raw bytecode evidence is preserved.

Never loads huge DEX files entirely into memory unless required for hashing.
"""
import logging
import re
import zipfile
from typing import Optional, Union

from androguard.core.apk import APK

logger = logging.getLogger("clonedetector.dexrisk.extractor")

DEX_RE = re.compile(r"^classes(\d+)?\.dex$")
MAX_DEX_SIZE = 100 * 1024 * 1024  # 100 MiB per DEX file safety limit


def _get_zip_source(apk_or_path: Union[APK, str]) -> zipfile.ZipFile:
    """Get a ZipFile object from an APK path or androguard APK object."""
    if isinstance(apk_or_path, str):
        return zipfile.ZipFile(apk_or_path, "r")
    # Try to access the underlying ZIP archive from androguard APK
    try:
        # androguard stores the path in 'filename' attribute
        path = getattr(apk_or_path, "filename", None) or getattr(apk_or_path, "_filename", None)
        if path:
            return zipfile.ZipFile(path, "r")
    except Exception:
        pass
    # Fallback: reopen from the original path if we can't get it
    raise ValueError("Cannot access ZIP archive from APK object")


def discover_dex_files(apk_or_path: Union[APK, str]) -> list[str]:
    """
    Return a deterministic (sorted) list of DEX file names contained in the APK.
    Accepts a parsed androguard APK object or a path string.
    """
    try:
        with _get_zip_source(apk_or_path) as zf:
            names = [n for n in zf.namelist() if DEX_RE.match(n)]
            return sorted(names)
    except Exception:
        logger.warning("DEX discovery failed", exc_info=True)
        return []


def extract_dex_bytes(apk_or_path: Union[APK, str], dex_name: str) -> Optional[bytes]:
    """
    Read the raw bytes of a named DEX entry from the APK archive.
    Accepts a parsed androguard APK object or a path string.

    Returns None if the entry doesn't exist or can't be read.
    Enforces a size limit to prevent memory exhaustion.
    """
    try:
        with _get_zip_source(apk_or_path) as zf:
            info = zf.getinfo(dex_name)
            if info.file_size > MAX_DEX_SIZE:
                logger.warning("DEX file too large (%d bytes), skipping: %s", info.file_size, dex_name)
                return None
            return zf.read(dex_name)
    except KeyError:
        return None
    except Exception:
        logger.warning("Could not read DEX %s", dex_name, exc_info=True)
        return None


def extract_all_dex_bytes(apk_or_path: Union[APK, str]) -> dict:
    """
    Extract all DEX files from an APK, returning:
    {
        "dex_files": ['classes.dex', 'classes2.dex', ...],
        "dex_count": N,
        "bytes": {"classes.dex": b'...', "classes2.dex": b'...', ...},
        "errors": [{"dex": "classes2.dex", "message": "..."}],
        "total_bytes": int,
    }
    """
    dex_names = discover_dex_files(apk_or_path)
    result = {
        "dex_files": dex_names,
        "dex_count": len(dex_names),
        "bytes": {},
        "errors": [],
        "total_bytes": 0,
    }

    for name in dex_names:
        data = extract_dex_bytes(apk_or_path, name)
        if data is None:
            result["errors"].append({
                "dex": name,
                "message": f"Could not extract DEX file: {name}",
            })
        else:
            result["bytes"][name] = data
            result["total_bytes"] += len(data)

    return result


def normalize_dex_bytes(dex_bytes_map: dict) -> bytes:
    """
    Lightweight, explainable normalization for fuzzy hashing.

    Steps:
      1. Sort DEX names for deterministic ordering.
      2. Concatenate raw bytes in sorted order.
      3. No destructive transformation — preserves actual bytecode evidence.

    This normalization makes the hash deterministic across identical APKs
    but does NOT claim obfuscation resistance (per spec rule).
    """
    parts = []
    for name in sorted(dex_bytes_map.keys()):
        data = dex_bytes_map[name]
        if data:
            parts.append(data)
    return b"".join(parts) if parts else b""
