import os
from typing import List

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "ThreatLens CTI Platform"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

    # Security & JWT
    SECRET_KEY: str = os.getenv("SECRET_KEY", "threatlens-dev-secret-key-change-in-production-2026-strict")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8  # 8 hours
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Database URLs (Defaults to SQLite for local development & unit testing; overridden by env in Docker/Postgres)
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "sqlite:///./threatlens.db"
    )

    @property
    def async_database_url(self) -> str:
        """Returns the async driver URL for SQLAlchemy 2.0 AsyncIO."""
        url = self.DATABASE_URL
        if url.startswith("postgresql://"):
            return url.replace("postgresql://", "postgresql+asyncpg://", 1)
        if url.startswith("sqlite:///") and not url.startswith("sqlite+aiosqlite:///"):
            return url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
        return url

    @property
    def sync_database_url(self) -> str:
        """Returns the synchronous driver URL for migrations and synchronous tooling."""
        url = self.DATABASE_URL
        if url.startswith("postgresql+asyncpg://"):
            return url.replace("postgresql+asyncpg://", "postgresql://", 1)
        if url.startswith("sqlite+aiosqlite:///"):
            return url.replace("sqlite+aiosqlite:///", "sqlite:///", 1)
        return url

    # Redis & Celery
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    CELERY_BROKER_URL: str = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/1")
    CELERY_RESULT_BACKEND: str = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/2")

    # Elasticsearch 8.x
    ELASTICSEARCH_URL: str = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
    ELASTICSEARCH_INDEX_PREFIX: str = "threatlens"

    # CORS
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]

    # Ingestion & Enrichment settings
    EXTERNAL_API_TIMEOUT: int = 15
    CACHE_EXPIRY_SECONDS: int = 86400  # 24 hours

    # Feed API Keys (Optional defaults, will be enriched or mock-fallback if unset)
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    OTX_API_KEY: str = os.getenv("OTX_API_KEY", "")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")

    # Celery Beat Ingestion Schedule Intervals (in seconds)
    FEED_POLL_INTERVAL_URLHAUS: int = 900       # 15 minutes
    FEED_POLL_INTERVAL_THREATFOX: int = 900     # 15 minutes
    FEED_POLL_INTERVAL_FEODO: int = 1800        # 30 minutes

    @model_validator(mode="after")
    def validate_production_security(self) -> "Settings":
        """Enforces strict production security invariants."""
        if self.ENVIRONMENT.lower() in ("production", "prod"):
            if "threatlens-dev-secret-key" in self.SECRET_KEY or len(self.SECRET_KEY) < 32:
                raise ValueError(
                    "Production Security Invariant Violation: SECRET_KEY must be a cryptographically secure random string (minimum 32 characters) provided via environment variables."
                )
            if self.DATABASE_URL.startswith("sqlite"):
                raise ValueError(
                    "Production Security Invariant Violation: SQLite is prohibited in production. A production PostgreSQL 16 cluster must be configured via DATABASE_URL."
                )
        return self

    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
