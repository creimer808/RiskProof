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
DEFAULT_IMPORT_DIR = Path("~/.riskproof/imports")
DEFAULT_ASSET_INVENTORY = Path("~/.riskproof/assets.json")
DEFAULT_REPORTS_DIR = Path("~/.riskproof/reports")


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

    #: Directory `import_nessus` may read `.nessus` files from. The agent only
    #: supplies a bare file name; it can never point the server at another path.
    import_dir: Path | None = None
    max_import_bytes: int = 512 * 1024 * 1024

    #: Operator-maintained asset inventory (criticality, exposure, ownership)
    #: applied to real scan findings. Missing file = no inventory. Never
    #: editable through tool input. See riskproof.ingest.inventory.
    asset_inventory: Path | None = None

    #: Directory where generate_report writes HTML reports. Operator
    #: configuration: tool input can never choose output paths.
    reports_dir: Path | None = None

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

    #: Tenable Vulnerability Management (Tenable.io / Tenable One) REST API.
    #: Credentials are NEVER settings: they are read from TENABLE_ACCESS_KEY /
    #: TENABLE_SECRET_KEY in the server's environment and never logged.
    tenable_base_url: str = "https://cloud.tenable.com"
    tenable_export_timeout_seconds: float = 300.0
    tenable_poll_interval_seconds: float = 3.0

    #: Optional GreyNoise exploitation signal. The API key is NEVER a setting: it
    #: is read from GREYNOISE_API_KEY in the server's environment only.
    greynoise_base_url: str = "https://api.greynoise.io"
    #: Days of scanning activity that count as "exploited now" (today + previous N-1).
    greynoise_window_days: int = Field(default=3, ge=1, le=10)
    #: Max GreyNoise activity requests per investigation run (0 = none).
    greynoise_max_calls_per_run: int = Field(default=100, ge=0, le=1000)

    #: Mass-vanish guard for import reconciliation: skip marking findings
    #: `not_seen` when more than this fraction of in-scope open findings would
    #: be flagged (a sign the export was incomplete, not that all was fixed).
    reconcile_max_missing_fraction: float = Field(default=0.5, ge=0.0, le=1.0)

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
    def effective_import_dir(self) -> Path:
        base = self.import_dir if self.import_dir is not None else DEFAULT_IMPORT_DIR
        return base.expanduser()

    @property
    def effective_asset_inventory(self) -> Path:
        base = self.asset_inventory if self.asset_inventory is not None else DEFAULT_ASSET_INVENTORY
        return base.expanduser()

    @property
    def effective_reports_dir(self) -> Path:
        base = self.reports_dir if self.reports_dir is not None else DEFAULT_REPORTS_DIR
        return base.expanduser()

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
