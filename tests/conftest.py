"""Shared fixtures for RiskProof tests."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from riskproof.config import Settings
from riskproof.services import Services, build_services

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "fixtures"


@pytest.fixture()
def import_dir(tmp_path: Path) -> Path:
    """An operator-controlled import directory holding the SAMPLE .nessus report."""
    directory = tmp_path / "imports"
    directory.mkdir()
    shutil.copy(FIXTURES / "sample_scan.nessus", directory / "sample_scan.nessus")
    return directory


@pytest.fixture()
def settings(tmp_path: Path, import_dir: Path) -> Settings:
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        db_path=tmp_path / "test.db",
        offline=True,
        fixtures_dir=FIXTURES,
        import_dir=import_dir,
        asset_inventory=tmp_path / "assets.json",  # absent: never read the real one
        allowed_targets=["127.0.0.1", "::1", "localhost"],
        approved_validation_methods=["tcp_connect", "http_banner", "tls_cert_dates"],
        dry_run=True,
        require_approval=True,
    )


@pytest.fixture()
def services(settings: Settings) -> Services:
    svc = build_services(settings)
    yield svc
    svc.db.close()
