"""
Central configuration. Everything is read from environment variables so the
same code works unchanged when we move from Docker Compose to ECS/Fargate
(env vars just come from Secrets Manager / task definitions instead of .env).
"""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Postgres
    DATABASE_URL: str = "postgresql://clonedetect:clonedetect_dev_password@postgres:5432/clonedetector"

    # Redis
    REDIS_URL: str = "redis://redis:6379/0"

    # Storage
    STORAGE_BACKEND: str = "local"  # "local" | "minio"
    STORAGE_APK_DIR: str = "/storage/apks"
    STORAGE_REPORT_DIR: str = "/storage/reports"
    STORAGE_TMP_DIR: str = "/storage/tmp"

    MINIO_ENDPOINT: str = "minio:9000"
    MINIO_ACCESS_KEY: str = "minioadmin"
    MINIO_SECRET_KEY: str = "minioadmin"
    MINIO_BUCKET: str = "apk-clone-detector"
    MINIO_SECURE: bool = False

    # API
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    MAX_UPLOAD_SIZE_MB: int = 250
    ANALYSIS_TIMEOUT_SECONDS: int = 300
    CORS_ORIGINS: str = "http://localhost:3000"

    # Scoring weights — must sum to ~1.0. Configurable per README instructions.
    WEIGHT_CERTIFICATE: float = 0.12
    WEIGHT_PACKAGE: float = 0.08
    WEIGHT_ICON: float = 0.12
    WEIGHT_STRINGS: float = 0.13
    WEIGHT_LAYOUT: float = 0.10
    WEIGHT_DEX: float = 0.18
    WEIGHT_RESOURCES: float = 0.12
    WEIGHT_MANIFEST: float = 0.08
    WEIGHT_PERMISSIONS: float = 0.07

    LOG_LEVEL: str = "INFO"

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def scoring_weights(self) -> dict[str, float]:
        return {
            "certificate": self.WEIGHT_CERTIFICATE,
            "package": self.WEIGHT_PACKAGE,
            "icon": self.WEIGHT_ICON,
            "strings": self.WEIGHT_STRINGS,
            "layout": self.WEIGHT_LAYOUT,
            "dex": self.WEIGHT_DEX,
            "resources": self.WEIGHT_RESOURCES,
            "manifest": self.WEIGHT_MANIFEST,
            "permissions": self.WEIGHT_PERMISSIONS,
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()
