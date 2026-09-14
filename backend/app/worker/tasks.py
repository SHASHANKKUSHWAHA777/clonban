"""
Background job pipeline (Phase 6, "Background Worker").

Flow: Identity -> Similarity -> DEX/Risk -> Scoring -> Report -> DB
One failed analyzer must not crash the whole job (rule #15) — each stage is
wrapped and falls back to a neutral/zero result with a findings entry
explaining the failure, so the rest of the pipeline still produces a report.
"""
import importlib.util
import logging
import sys
from datetime import datetime
from pathlib import Path

from app.db.session import SessionLocal
from app.models.models import (
    AnalysisJob, JobStatus, IdentityResult, SimilarityResult, DexResult,
    RiskFinding, FinalScore, ApkMetadata, ApkRole,
)
from app.core.config import get_settings
from app.services.storage import get_storage
from app.services.report_service import generate_reports

logger = logging.getLogger("clonedetector.worker")
settings = get_settings()

ANALYZERS_ROOT = Path(__file__).resolve().parents[2] / "analyzers"
SCORING_ROOT = Path(__file__).resolve().parents[2] / "scoring"

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # for `analyzers.*` and `scoring.*`


def _load_module(path: Path, name: str):
    """Loads a module from an explicit file path — needed for analyzers/dex-risk
    (a hyphenated directory name, which can't be a normal Python package)."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_analysis_pipeline(job_id: str):
    db = SessionLocal()
    storage = get_storage()
    try:
        job = db.get(AnalysisJob, job_id)
        if not job:
            logger.error("job %s not found", job_id)
            return

        apk_rows = {a.role.value: a for a in job.apk_metadata}
        original_path = apk_rows["original"].storage_path
        candidate_path = apk_rows["candidate"].storage_path

        identity_module = _load_module(ANALYZERS_ROOT / "identity" / "analyzer.py", "identity_analyzer")
        similarity_module = _load_module(ANALYZERS_ROOT / "similarity" / "analyzer.py", "similarity_analyzer")
        dexrisk_module = _load_module(ANALYZERS_ROOT / "dex-risk" / "analyzer.py", "dexrisk_analyzer")
        scoring_module = _load_module(SCORING_ROOT / "engine.py", "scoring_engine")

        # ---- Identity ----
        _set_status(db, job, JobStatus.ANALYZING_IDENTITY, "analyzing_identity")
        identity_out = _safe_run(
            lambda: identity_module.analyze(original_path, candidate_path),
            fallback={"certificate_score": 0.0, "certificate_match": False, "package_score": 0.0,
                      "manifest_score": 0.0, "permissions_score": 0.0, "findings": [], "apks": {}},
            stage="identity",
        )
        _persist_apk_extras(db, apk_rows, identity_out.get("apks", {}))
        db.add(IdentityResult(
            job_id=job.id,
            certificate_score=identity_out.get("certificate_score"),
            certificate_match=identity_out.get("certificate_match"),
            package_score=identity_out.get("package_score"),
            manifest_score=identity_out.get("manifest_score"),
            permissions_score=identity_out.get("permissions_score"),
            findings=identity_out.get("findings", []),
            raw=identity_out,
        ))
        db.commit()

        # ---- Similarity ----
        _set_status(db, job, JobStatus.ANALYZING_SIMILARITY, "comparing_resources")
        report_dir = str(storage.job_report_dir(str(job.id)))
        similarity_out = _safe_run(
            lambda: similarity_module.analyze(original_path, candidate_path, report_dir),
            fallback={"icon_score": 0.0, "icon_phash_distance": None, "string_score": 0.0,
                      "layout_score": 0.0, "resource_score": 0.0, "diff_image_path": None, "findings": []},
            stage="similarity",
        )
        db.add(SimilarityResult(
            job_id=job.id,
            icon_score=similarity_out.get("icon_score"),
            icon_phash_distance=similarity_out.get("icon_phash_distance"),
            string_score=similarity_out.get("string_score"),
            layout_score=similarity_out.get("layout_score"),
            resource_score=similarity_out.get("resource_score"),
            diff_image_path=similarity_out.get("diff_image_path"),
            findings=similarity_out.get("findings", []),
            raw=similarity_out,
        ))
        db.commit()

        # ---- DEX / Risk ----
        _set_status(db, job, JobStatus.ANALYZING_DEX, "analyzing_dex")
        dex_out = _safe_run(
            lambda: dexrisk_module.analyze(original_path, candidate_path),
            fallback={"dex_score": 0.0, "malware_risk": 0.0, "class_count_original": None,
                      "class_count_candidate": None, "method_count_original": None,
                      "method_count_candidate": None, "ssdeep_score": None,
                      "api_call_similarity": 0.0, "findings": []},
            stage="dex-risk",
        )
        db.add(DexResult(
            job_id=job.id,
            dex_score=dex_out.get("dex_score"),
            malware_risk=dex_out.get("malware_risk"),
            class_count_original=dex_out.get("class_count_original"),
            class_count_candidate=dex_out.get("class_count_candidate"),
            method_count_original=dex_out.get("method_count_original"),
            method_count_candidate=dex_out.get("method_count_candidate"),
            ssdeep_score=dex_out.get("ssdeep_score"),
            api_call_similarity=dex_out.get("api_call_similarity"),
            raw=dex_out,
        ))
        for f in dex_out.get("findings", []):
            db.add(RiskFinding(job_id=job.id, finding_type=f["type"], severity=f["severity"],
                                evidence=f["evidence"], source_apk=f.get("source_apk")))
        for f in identity_out.get("findings", []):
            db.add(RiskFinding(job_id=job.id, finding_type=f["type"], severity=f["severity"],
                                evidence=f["evidence"], source_apk=f.get("source_apk", "both")))
        db.commit()

        # ---- Scoring ----
        _set_status(db, job, JobStatus.SCORING, "calculating_risk")
        scores = scoring_module.compute_scores(identity_out, similarity_out, dex_out, settings.scoring_weights)
        db.add(FinalScore(
            job_id=job.id,
            clone_probability=scores["clone_probability"],
            malware_risk=scores["malware_risk"],
            confidence=scores["confidence"],
            weights_used=scores["weights_used"],
            component_scores=scores["component_scores"],
            verdict_summary=scores["verdict_summary"],
        ))
        db.commit()

        # ---- Report ----
        _set_status(db, job, JobStatus.GENERATING_REPORT, "generating_report")
        db.refresh(job)
        report_paths = generate_reports(job, storage)
        db.add(report_paths)
        db.commit()

        job.status = JobStatus.COMPLETED
        job.progress_step = "completed"
        job.completed_at = datetime.utcnow()
        db.commit()

        storage.cleanup_job_tmp(str(job.id))

    except Exception as e:
        logger.exception("Pipeline failed for job %s", job_id)
        db.rollback()
        job = db.get(AnalysisJob, job_id)
        if job:
            job.status = JobStatus.FAILED
            job.error_message = str(e)
            db.commit()
    finally:
        db.close()


def _safe_run(fn, fallback: dict, stage: str) -> dict:
    try:
        return fn()
    except Exception:
        logger.exception("Stage '%s' failed, falling back to neutral result", stage)
        fallback = dict(fallback)
        fallback.setdefault("findings", [])
        fallback["findings"].append({
            "type": f"{stage.upper()}_STAGE_FAILED", "severity": "medium",
            "evidence": f"The {stage} analyzer raised an exception and was skipped; treat related scores as unavailable, not zero-similarity.",
        })
        return fallback


def _set_status(db, job, status: JobStatus, step: str):
    job.status = status
    job.progress_step = step
    db.commit()


def _persist_apk_extras(db, apk_rows: dict, apks_info: dict):
    for role in ("original", "candidate"):
        info = apks_info.get(role)
        row: ApkMetadata = apk_rows.get(role)
        if not info or not row:
            continue
        row.package_name = info.get("package_name")
        row.app_label = info.get("app_label")
        row.version_name = info.get("version_name")
        row.version_code = str(info.get("version_code")) if info.get("version_code") is not None else None
        row.min_sdk = info.get("min_sdk")
        row.target_sdk = info.get("target_sdk")
        row.cert_sha256 = info.get("cert_sha256")
        row.cert_subject = info.get("cert_subject")
        row.cert_issuer = info.get("cert_issuer")
        row.permissions = info.get("permissions", [])
        row.activities = info.get("activities", [])
        row.services = info.get("services", [])
        row.receivers = info.get("receivers", [])
        row.providers = info.get("providers", [])
        row.is_valid = info.get("is_valid", True)
        row.parse_error = info.get("parse_error")
    db.commit()
