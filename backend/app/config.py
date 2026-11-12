"""Environment-based configuration. Secrets live in env vars, never in code."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    return default if v is None else v.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    env: str = field(default_factory=lambda: os.environ.get("AZMUTHIX_ENV", "development"))
    database_url: str = field(default_factory=lambda: os.environ.get("DATABASE_URL", "sqlite:///./data/azmuthix.db"))
    secret_key: str = field(default_factory=lambda: os.environ.get("AZMUTHIX_SECRET_KEY", ""))
    evidence_dir: Path = field(default_factory=lambda: Path(os.environ.get("AZMUTHIX_EVIDENCE_DIR", "./data/evidence")))
    max_upload_mb: int = field(default_factory=lambda: int(os.environ.get("AZMUTHIX_MAX_UPLOAD_MB", "25")))
    retention_days: int = field(default_factory=lambda: int(os.environ.get("AZMUTHIX_RETENTION_DAYS", "0")))  # 0 = keep
    cors_origins: list[str] = field(
        default_factory=lambda: [o.strip() for o in os.environ.get("AZMUTHIX_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if o.strip()]
    )
    allow_registration: bool = field(default_factory=lambda: _bool("AZMUTHIX_ALLOW_REGISTRATION", True))
    token_minutes: int = field(default_factory=lambda: int(os.environ.get("AZMUTHIX_TOKEN_MINUTES", "480")))
    # Optional integrations (all server-side only)
    anthropic_api_key: str = field(default_factory=lambda: os.environ.get("ANTHROPIC_API_KEY", ""))
    anthropic_model: str = field(default_factory=lambda: os.environ.get("AZMUTHIX_AI_MODEL", "claude-sonnet-4-5"))
    virustotal_key: str = field(default_factory=lambda: os.environ.get("VIRUSTOTAL_API_KEY", ""))
    abuseipdb_key: str = field(default_factory=lambda: os.environ.get("ABUSEIPDB_API_KEY", ""))
    frontend_dist: Path = field(default_factory=lambda: Path(os.environ.get("AZMUTHIX_FRONTEND_DIST", "../frontend/dist")))

    def __post_init__(self) -> None:
        if not self.secret_key:
            if self.env == "production":
                raise RuntimeError("AZMUTHIX_SECRET_KEY must be set in production")
            # Ephemeral dev key: sessions reset on restart, which is fine locally.
            self.secret_key = secrets.token_urlsafe(48)
        if self.env == "production" and self.database_url.startswith("sqlite") and not _bool("AZMUTHIX_ALLOW_SQLITE_PROD", False):
            raise RuntimeError("Use PostgreSQL in production (set DATABASE_URL), or AZMUTHIX_ALLOW_SQLITE_PROD=1 with a persistent disk")
        if self.database_url.startswith("postgres://"):
            self.database_url = self.database_url.replace("postgres://", "postgresql+psycopg://", 1)
        elif self.database_url.startswith("postgresql://"):
            self.database_url = self.database_url.replace("postgresql://", "postgresql+psycopg://", 1)

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    global _settings
    _settings = None
