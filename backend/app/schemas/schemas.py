import uuid
from datetime import datetime
from typing import Optional, Any

from pydantic import BaseModel


class AnalyzeJobCreatedResponse(BaseModel):
    job_id: uuid.UUID
    status: str


class JobStatusResponse(BaseModel):
    job_id: uuid.UUID
    status: str
    progress_step: Optional[str] = None
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None


class ApkMetadataOut(BaseModel):
    role: str
    original_filename: Optional[str]
    file_sha256: Optional[str]
    file_size_bytes: Optional[int]
    package_name: Optional[str]
    app_label: Optional[str]
    version_name: Optional[str]
    version_code: Optional[str]
    min_sdk: Optional[int]
    target_sdk: Optional[int]
    cert_sha256: Optional[str]
    permissions: list[str] = []
    activities: list[str] = []
    services: list[str] = []
    receivers: list[str] = []
    providers: list[str] = []
    icon_path: Optional[str]
    is_valid: bool = True
    parse_error: Optional[str] = None

    class Config:
        from_attributes = True


class IdentityResultOut(BaseModel):
    certificate_score: Optional[float]
    certificate_match: Optional[bool]
    certificate_status: Optional[str] = None  # SAME_SIGNER | DIFFERENT_SIGNER | UNKNOWN
    certificate_identity_score: Optional[float] = None  # 1.0 / 0.0 / null
    package_score: Optional[float]
    package_similarity: Optional[float] = None  # [0,1] or null
    package_match_state: Optional[str] = None  # EXACT_MATCH | NEAR_MATCH | UNRELATED
    manifest_score: Optional[float]
    permissions_score: Optional[float]
    manifest_findings: list[Any] = []
    findings: list[Any] = []
    raw: Optional[dict] = None

    class Config:
        from_attributes = True


class SimilarityResultOut(BaseModel):
    icon_score: Optional[float]
    icon_phash_distance: Optional[int]
    string_score: Optional[float]
    layout_score: Optional[float]
    resource_score: Optional[float]
    diff_image_path: Optional[str]
    findings: list[Any] = []

    class Config:
        from_attributes = True


class DexResultOut(BaseModel):
    dex_score: Optional[float]
    malware_risk: Optional[float]
    malware_risk_score: Optional[int] = None  # 0-100 integer (V3)
    bytecode_similarity: Optional[float] = None  # [0,1] or null (V3)
    class_count_original: Optional[int]
    class_count_candidate: Optional[int]
    method_count_original: Optional[int]
    method_count_candidate: Optional[int]
    ssdeep_score: Optional[float]
    api_call_similarity: Optional[float]
    dex_files_baseline: list[str] = []
    dex_files_candidate: list[str] = []
    dex_count_baseline: Optional[int] = None
    dex_count_candidate: Optional[int] = None
    risk_findings: list[Any] = []
    errors: list[Any] = []
    raw: Optional[dict] = None

    class Config:
        from_attributes = True


class RiskFindingOut(BaseModel):
    finding_type: str
    severity: str
    evidence: str
    source_apk: Optional[str]
    category: Optional[str] = None  # PERMISSION | COMPONENT (V3)
    contribution: Optional[int] = None  # risk score contribution (V3)
    baseline_present: Optional[bool] = None  # V3
    candidate_present: Optional[bool] = None  # V3

    class Config:
        from_attributes = True


class FinalScoreOut(BaseModel):
    clone_probability: Optional[float]
    malware_risk: Optional[float]
    confidence: Optional[float]
    weights_used: dict = {}
    component_scores: dict = {}
    verdict_summary: Optional[str] = None

    class Config:
        from_attributes = True


class ReportOut(BaseModel):
    json_path: Optional[str]
    html_path: Optional[str]
    pdf_path: Optional[str]
    generated_at: Optional[datetime]

    class Config:
        from_attributes = True


class FullAnalysisResult(BaseModel):
    job_id: uuid.UUID
    status: str
    error_message: Optional[str] = None
    apks: list[ApkMetadataOut] = []
    identity: Optional[IdentityResultOut] = None
    similarity: Optional[SimilarityResultOut] = None
    dex: Optional[DexResultOut] = None
    risk_findings: list[RiskFindingOut] = []
    final_score: Optional[FinalScoreOut] = None
    report: Optional[ReportOut] = None


class HealthResponse(BaseModel):
    status: str
    database: bool
    redis: bool
    version: str = "0.1.0-mvp"
