"""Tests for Atlas Phase 10 diagnostics."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.atlas.diagnostics import AtlasDiagnostics
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db(tmp_path: Path) -> Database:
    db_path = tmp_path / "atlas_diag.db"
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


def test_diagnostics_constructs(db: Database) -> None:
    diag = AtlasDiagnostics(db)
    assert diag is not None


def test_run_returns_report(db: Database) -> None:
    diag = AtlasDiagnostics(db)
    report = diag.run()
    assert report.passed >= 1
    assert report.failed == 0
    assert report.critical_failure is False


def test_run_to_dict(db: Database) -> None:
    diag = AtlasDiagnostics(db)
    report = diag.run()
    d = report.to_dict()
    assert "checks" in d
    assert "generated_at" in d
    assert d["passed"] >= 1


def test_run_full_includes_release_checks(db: Database) -> None:
    diag = AtlasDiagnostics(db)
    report = diag.run_full()
    # Full run includes the standard suite plus deep release checks.
    names = [c.name for c in report.checks]
    assert "release_aegis_manifest" in names


def test_run_full_to_dict(db: Database) -> None:
    diag = AtlasDiagnostics(db)
    report = diag.run_full()
    d = report.to_dict()
    assert "passed" in d
    assert "failed" in d
    assert "critical_failure" in d
