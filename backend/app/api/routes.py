import uuid
import logging

import redis
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.core.config import get_settings
from app.db.session import get_db, engine
from app.models.models import (
    AnalysisJob, ApkMetadata, ApkRole, JobStatus,
    IdentityResult, SimilarityResult, DexResult, RiskFinding, FinalScore, Report,
)
from app.schemas.schemas import (
    AnalyzeJobCreatedResponse, JobStatusResponse, FullAnalysisResult,
    ApkMetadataOut, IdentityResultOut, SimilarityResultOut, DexResultOut,
    RiskFindingOut, FinalScoreOut, ReportOut, HealthResponse,
)
from app.services.storage import get_storage

logger = logging.getLogger("clonedetector.api")
router = APIRouter()
settings = get_settings()

ALLOWED_EXTENSIONS = {".apk"}
MAX_BYTES = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024


def _validate_upload(upload: UploadFile):
    if not upload.filename.lower().endswith(".apk"):
        raise HTTPException(400, f"'{upload.filename}' is not a .apk file")


@router.post("/analyze", response_model=AnalyzeJobCreatedResponse, status_code=202)
async def analyze(
    original: UploadFile = File(..., description="Legitimate / original APK"),
    candidate: UploadFile = File(..., description="Candidate / suspicious APK"),
    db: Session = Depends(get_db),
):
    _validate_upload(original)
    _validate_upload(candidate)

    job = AnalysisJob(status=JobStatus.UPLOADING, progress_step="uploading")
    db.add(job)
    db.commit()
    db.refresh(job)

    storage = get_storage()
    try:
        for role, upload in (("original", original), ("candidate", candidate)):
            path, sha256, size = storage.save_apk(str(job.id), role, upload.file, upload.filename)
            if size == 0:
                raise HTTPException(400, f"{role} APK is empty")
            if size > MAX_BYTES:
                raise HTTPException(413, f"{role} APK exceeds {settings.MAX_UPLOAD_SIZE_MB}MB limit")
            meta = ApkMetadata(
                job_id=job.id,
                role=ApkRole(role),
                original_filename=upload.filename,
                storage_path=path,
                file_sha256=sha256,
                file_size_bytes=size,
            )
            db.add(meta)
        job.status = JobStatus.PENDING
        job.progress_step = "queued"
        db.commit()
    except HTTPException:
        db.delete(job)
        db.commit()
        raise
    except Exception as e:
        logger.exception("Upload failed for job %s", job.id)
        db.delete(job)
        db.commit()
        raise HTTPException(500, f"Upload failed: {e}")

    # Enqueue background analysis — see app/worker for the pipeline.
    r = redis.from_url(settings.REDIS_URL)
    from rq import Queue
    q = Queue("analysis", connection=r, default_timeout=settings.ANALYSIS_TIMEOUT_SECONDS)
    q.enqueue("app.worker.tasks.run_analysis_pipeline", str(job.id))

    return AnalyzeJobCreatedResponse(job_id=job.id, status=job.status.value)


@router.get("/analyze/{job_id}", response_model=FullAnalysisResult)
async def get_analysis(job_id: uuid.UUID, db: Session = Depends(get_db)):
    job = db.get(AnalysisJob, job_id)
    if not job:
        raise HTTPException(404, "job not found")

    return FullAnalysisResult(
        job_id=job.id,
        status=job.status.value,
        error_message=job.error_message,
        apks=[ApkMetadataOut.model_validate(a) for a in job.apk_metadata],
        identity=IdentityResultOut.model_validate(job.identity_result) if job.identity_result else None,
        similarity=SimilarityResultOut.model_validate(job.similarity_result) if job.similarity_result else None,
        dex=DexResultOut.model_validate(job.dex_result) if job.dex_result else None,
        risk_findings=[RiskFindingOut.model_validate(f) for f in job.risk_findings],
        final_score=FinalScoreOut.model_validate(job.final_score) if job.final_score else None,
        report=ReportOut.model_validate(job.report) if job.report else None,
    )


@router.get("/analyze/{job_id}/status", response_model=JobStatusResponse)
async def get_status(job_id: uuid.UUID, db: Session = Depends(get_db)):
    job = db.get(AnalysisJob, job_id)
    if not job:
        raise HTTPException(404, "job not found")
    return JobStatusResponse(
        job_id=job.id,
        status=job.status.value,
        progress_step=job.progress_step,
        error_message=job.error_message,
        created_at=job.created_at,
        updated_at=job.updated_at,
        completed_at=job.completed_at,
    )


@router.get("/reports/{job_id}")
async def get_report_info(job_id: uuid.UUID, db: Session = Depends(get_db)):
    job = db.get(AnalysisJob, job_id)
    if not job:
        raise HTTPException(404, "job not found")
    if not job.report:
        raise HTTPException(404, "report not generated yet")
    return ReportOut.model_validate(job.report)


@router.get("/reports/{job_id}/download")
async def download_report(job_id: uuid.UUID, fmt: str = "pdf", db: Session = Depends(get_db)):
    job = db.get(AnalysisJob, job_id)
    if not job or not job.report:
        raise HTTPException(404, "report not found")
    path_map = {"pdf": job.report.pdf_path, "html": job.report.html_path, "json": job.report.json_path}
    path = path_map.get(fmt)
    if not path:
        raise HTTPException(400, f"unsupported format '{fmt}', use pdf|html|json")
    return FileResponse(path, filename=f"clone-detector-report-{job_id}.{fmt}")


@router.get("/health", response_model=HealthResponse)
async def health():
    db_ok = True
    redis_ok = True
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        db_ok = False
    try:
        redis.from_url(settings.REDIS_URL).ping()
    except Exception:
        redis_ok = False
    return HealthResponse(status="ok" if db_ok and redis_ok else "degraded", database=db_ok, redis=redis_ok)
