"""Service container wiring settings, storage, and providers together."""

from __future__ import annotations

from dataclasses import dataclass

from riskproof.config import Settings
from riskproof.providers.epss import EPSSProvider
from riskproof.providers.fixtures_source import FixtureIntelSource
from riskproof.providers.kev import KEVProvider
from riskproof.providers.tenable import TenableBridge
from riskproof.storage.db import Database
from riskproof.storage.repositories import (
    AuditLog,
    FindingRepository,
    IntelCacheRepository,
    InvestigationRepository,
    PendingActionRepository,
)


@dataclass
class Services:
    settings: Settings
    db: Database
    findings: FindingRepository
    investigations: InvestigationRepository
    intel_cache: IntelCacheRepository
    audit: AuditLog
    pending: PendingActionRepository
    epss: EPSSProvider
    kev: KEVProvider
    fixture_intel: FixtureIntelSource
    tenable: TenableBridge


def build_services(settings: Settings) -> Services:
    db = Database(settings.db_path_expanded)
    return Services(
        settings=settings,
        db=db,
        findings=FindingRepository(db),
        investigations=InvestigationRepository(db),
        intel_cache=IntelCacheRepository(db),
        audit=AuditLog(db),
        pending=PendingActionRepository(db),
        epss=EPSSProvider(base_url=settings.epss_base_url, timeout=settings.http_timeout_seconds),
        kev=KEVProvider(
            feed_url=settings.kev_feed_url,
            timeout=settings.http_timeout_seconds,
            cache=IntelCacheRepository(db),
            max_age_hours=settings.kev_max_age_hours,
        ),
        fixture_intel=FixtureIntelSource(settings.effective_fixtures_dir),
        tenable=TenableBridge(),
    )
