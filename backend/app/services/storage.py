"""
Storage abstraction layer.

Today: STORAGE_BACKEND=local writes to the mounted ./storage volume.
Later: STORAGE_BACKEND=minio (or swap this module for a boto3 S3 client)
without touching any caller code — callers only use save_apk/get_apk_path/
save_report, never raw paths directly.
"""
import hashlib
import os
import shutil
import uuid
from pathlib import Path

from app.core.config import get_settings

settings = get_settings()


class LocalStorage:
    def __init__(self):
        self.apk_dir = Path(settings.STORAGE_APK_DIR)
        self.report_dir = Path(settings.STORAGE_REPORT_DIR)
        self.tmp_dir = Path(settings.STORAGE_TMP_DIR)
        for d in (self.apk_dir, self.report_dir, self.tmp_dir):
            d.mkdir(parents=True, exist_ok=True)

    def job_apk_dir(self, job_id: str) -> Path:
        p = self.apk_dir / str(job_id)
        p.mkdir(parents=True, exist_ok=True)
        return p

    def job_tmp_dir(self, job_id: str) -> Path:
        p = self.tmp_dir / str(job_id)
        p.mkdir(parents=True, exist_ok=True)
        return p

    def job_report_dir(self, job_id: str) -> Path:
        p = self.report_dir / str(job_id)
        p.mkdir(parents=True, exist_ok=True)
        return p

    def save_apk(self, job_id: str, role: str, file_obj, filename: str) -> tuple[str, str, int]:
        """Streams an uploaded APK to disk, returns (path, sha256, size_bytes)."""
        dest = self.job_apk_dir(job_id) / f"{role}_{filename}"
        sha256 = hashlib.sha256()
        size = 0
        with open(dest, "wb") as out:
            while chunk := file_obj.read(1024 * 1024):
                out.write(chunk)
                sha256.update(chunk)
                size += len(chunk)
        return str(dest), sha256.hexdigest(), size

    def cleanup_job_tmp(self, job_id: str):
        """Wipe extracted APK contents after analysis — required by SECURITY.md."""
        p = self.tmp_dir / str(job_id)
        if p.exists():
            shutil.rmtree(p, ignore_errors=True)

    def save_report_file(self, job_id: str, filename: str, data: bytes) -> str:
        dest = self.job_report_dir(job_id) / filename
        with open(dest, "wb") as f:
            f.write(data)
        return str(dest)


def get_storage() -> LocalStorage:
    # Only "local" is implemented for the MVP; STORAGE_BACKEND=minio is a
    # documented future swap point (see docs/cloud-migration.md).
    if settings.STORAGE_BACKEND != "local":
        raise NotImplementedError(
            f"STORAGE_BACKEND={settings.STORAGE_BACKEND!r} not implemented yet in MVP; use 'local'"
        )
    return LocalStorage()
