"""RiskProof configuration (environment-first, secure defaults)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

#: Non-destructive validation methods RiskProof knows how to perform.
#: Anything not listed here is refused by construction.
DEFAULT_VALIDATION_METHODS = ["tcp_connect", "http_banner", "tls_cert_dates"]

DEFAULT_FIXTURES_DIR = Path(__file__).resolve().parents[2] / "fixtures"


class Settings(BaseSettings):
    """Runtime settings loaded from RISKPROOF_-prefixed environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="RISKPROOF_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    db_path: Path = Path("~/.riskproof/riskproof.db").expanduser()
    offline: bool = False
    fixtures_dir: Path | None = None

    #: Allowlist for validation targets: hostnames, IPs, or CIDR ranges.
    #: Empty means NO target may be validated (fail closed).
    allowed_targets: Annotated[list[str], NoDecode] = Field(default_factory=list)
    approved_validation_methods: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: list(DEFAULT_VALIDATION_METHODS)
    )
    require_approval: bool = True
    dry_run: bool = True

    epss_base_url: str = "https://api.first.org/data/v1/epss"
    kev_feed_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    kev_max_age_hours: float = 24.0
    intel_cache_ttl_hours: float = 12.0
    http_timeout_seconds: float = 15.0

    #: Actor name recorded in the audit trail for automated decisions.
    audit_actor: str = "riskproof-agent"

    @field_validator("allowed_targets", "approved_validation_methods", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @property
    def effective_fixtures_dir(self) -> Path:
        return self.fixtures_dir if self.fixtures_dir is not None else DEFAULT_FIXTURES_DIR

    @property
    def db_path_expanded(self) -> Path:
        return self.db_path.expanduser()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings for long-running server processes."""
    return Settings()


def load_settings() -> Settings:
    """Fresh settings (used by tests and the CLI; reads env each call)."""
    return Settings()
