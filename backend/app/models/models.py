import uuid
import enum
from datetime import datetime

from sqlalchemy import (
    Column, String, Float, Integer, Boolean, DateTime, ForeignKey, JSON, Enum, Text
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.session import Base


class JobStatus(str, enum.Enum):
    PENDING = "pending"
    UPLOADING = "uploading"
    EXTRACTING = "extracting"
    ANALYZING_IDENTITY = "analyzing_identity"
    ANALYZING_SIMILARITY = "analyzing_similarity"
    ANALYZING_DEX = "analyzing_dex"
    SCORING = "scoring"
    GENERATING_REPORT = "generating_report"
    COMPLETED = "completed"
    FAILED = "failed"


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    status = Column(Enum(JobStatus), default=JobStatus.PENDING, nullable=False)
    progress_step = Column(String(64), nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    apk_metadata = relationship("ApkMetadata", back_populates="job", cascade="all, delete-orphan")
    identity_result = relationship("IdentityResult", back_populates="job", uselist=False, cascade="all, delete-orphan")
    similarity_result = relationship("SimilarityResult", back_populates="job", uselist=False, cascade="all, delete-orphan")
    dex_result = relationship("DexResult", back_populates="job", uselist=False, cascade="all, delete-orphan")
    risk_findings = relationship("RiskFinding", back_populates="job", cascade="all, delete-orphan")
    final_score = relationship("FinalScore", back_populates="job", uselist=False, cascade="all, delete-orphan")
    report = relationship("Report", back_populates="job", uselist=False, cascade="all, delete-orphan")


class ApkRole(str, enum.Enum):
    ORIGINAL = "original"
    CANDIDATE = "candidate"


class ApkMetadata(Base):
    __tablename__ = "apk_metadata"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey("analysis_jobs.id"), nullable=False)
    role = Column(Enum(ApkRole), nullable=False)

    original_filename = Column(String(512))
    storage_path = Column(String(1024))
    file_sha256 = Column(String(64))
    file_size_bytes = Column(Integer)

    package_name = Column(String(512))
    app_label = Column(String(512))
    version_name = Column(String(128))
    version_code = Column(String(64))
    min_sdk = Column(Integer, nullable=True)
    target_sdk = Column(Integer, nullable=True)

    cert_sha256 = Column(String(64), nullable=True)
    cert_subject = Column(String(1024), nullable=True)
    cert_issuer = Column(String(1024), nullable=True)

    permissions = Column(JSON, default=list)
    activities = Column(JSON, default=list)
    services = Column(JSON, default=list)
    receivers = Column(JSON, default=list)
    providers = Column(JSON, default=list)

    icon_path = Column(String(1024), nullable=True)
    is_valid = Column(Boolean, default=True)
    parse_error = Column(Text, nullable=True)

    job = relationship("AnalysisJob", back_populates="apk_metadata")


class IdentityResult(Base):
    __tablename__ = "identity_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey("analysis_jobs.id"), nullable=False, unique=True)

    certificate_score = Column(Float)
    certificate_match = Column(Boolean)
    certificate_status = Column(String(32), nullable=True)  # SAME_SIGNER | DIFFERENT_SIGNER | UNKNOWN
    certificate_identity_score = Column(Float, nullable=True)  # 1.0 | 0.0 | null
    package_score = Column(Float)
    package_similarity = Column(Float, nullable=True)  # [0,1] or null
    package_match_state = Column(String(32), nullable=True)  # EXACT_MATCH | NEAR_MATCH | UNRELATED
    manifest_score = Column(Float)
    permissions_score = Column(Float)
    findings = Column(JSON, default=list)
    manifest_findings = Column(JSON, default=list)
    raw = Column(JSON, default=dict)

    job = relationship("AnalysisJob", back_populates="identity_result")


class SimilarityResult(Base):
    __tablename__ = "similarity_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey("analysis_jobs.id"), nullable=False, unique=True)

    icon_score = Column(Float)
    icon_phash_distance = Column(Integer, nullable=True)
    string_score = Column(Float)
    layout_score = Column(Float)
    resource_score = Column(Float)
    diff_image_path = Column(String(1024), nullable=True)
    findings = Column(JSON, default=list)
    raw = Column(JSON, default=dict)

    job = relationship("AnalysisJob", back_populates="similarity_result")


class DexResult(Base):
    __tablename__ = "dex_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey("analysis_jobs.id"), nullable=False, unique=True)

    dex_score = Column(Float)
    malware_risk = Column(Float)
    malware_risk_score = Column(Integer, nullable=True)  # 0-100 integer
    bytecode_similarity = Column(Float, nullable=True)  # [0,1] or null
    class_count_original = Column(Integer, nullable=True)
    class_count_candidate = Column(Integer, nullable=True)
    method_count_original = Column(Integer, nullable=True)
    method_count_candidate = Column(Integer, nullable=True)
    ssdeep_score = Column(Float, nullable=True)
    api_call_similarity = Column(Float, nullable=True)
    dex_files_baseline = Column(JSON, default=list)
    dex_files_candidate = Column(JSON, default=list)
    dex_count_baseline = Column(Integer, nullable=True)
    dex_count_candidate = Column(Integer, nullable=True)
    errors = Column(JSON, default=list)
    raw = Column(JSON, default=dict)

    job = relationship("AnalysisJob", back_populates="dex_result")


class RiskFinding(Base):
    __tablename__ = "risk_findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey("analysis_jobs.id"), nullable=False)

    finding_type = Column(String(128))
    severity = Column(String(16))  # low | medium | high
    evidence = Column(Text)
    source_apk = Column(String(16), nullable=True)  # original | candidate

    # V3 fields (additive)
    category = Column(String(32), nullable=True)  # PERMISSION | COMPONENT | ...
    contribution = Column(Integer, default=0)  # risk score contribution
    baseline_present = Column(Boolean, nullable=True)
    candidate_present = Column(Boolean, nullable=True)

    job = relationship("AnalysisJob", back_populates="risk_findings")


class FinalScore(Base):
    __tablename__ = "final_scores"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey("analysis_jobs.id"), nullable=False, unique=True)

    clone_probability = Column(Float)
    malware_risk = Column(Float)
    confidence = Column(Float)
    weights_used = Column(JSON, default=dict)
    component_scores = Column(JSON, default=dict)
    verdict_summary = Column(Text, nullable=True)

    job = relationship("AnalysisJob", back_populates="final_score")


class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey("analysis_jobs.id"), nullable=False, unique=True)

    json_path = Column(String(1024), nullable=True)
    html_path = Column(String(1024), nullable=True)
    pdf_path = Column(String(1024), nullable=True)
    generated_at = Column(DateTime, nullable=True)

    job = relationship("AnalysisJob", back_populates="report")
