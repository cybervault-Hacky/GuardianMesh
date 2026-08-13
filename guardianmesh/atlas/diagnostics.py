"""GuardianMesh Atlas Phase 10 diagnostics.

The :class:`AtlasDiagnostics` aggregates the output of the
integrity verifier and the lifecycle validator into a single
diagnostic report. Diagnostics are read-only and never expose
secrets.
"""

from __future__ import annotations

import time

from guardianmesh.atlas.integrity import AtlasIntegrityVerifier
from guardianmesh.atlas.lifecycle import AtlasLifecycleValidator
from guardianmesh.atlas.models import AtlasDiagnosticCheck, AtlasDiagnosticReport
from guardianmesh.atlas.release import AtlasReleaseValidator
from guardianmesh.storage.database import Database


class AtlasDiagnostics:
    """High-level diagnostic aggregator.

    ``run()`` executes the integrity, lifecycle, and release
    checks and returns a single :class:`AtlasDiagnosticReport`.
    ``run_full()`` also performs deeper checks; the doctor
    command uses the lighter ``run()`` for fast feedback.
    """

    def __init__(self, db: Database) -> None:
        self._db = db
        self._integrity = AtlasIntegrityVerifier(db)
        self._lifecycle = AtlasLifecycleValidator(db)
        self._release = AtlasReleaseValidator(db)

    def _time_check(self, check: AtlasDiagnosticCheck) -> AtlasDiagnosticCheck:
        return AtlasDiagnosticCheck(
            name=check.name,
            ok=check.ok,
            subsystem=check.subsystem,
            reason=check.reason,
            duration_ms=0.0,
        )

    def run(self) -> AtlasDiagnosticReport:
        """Run the standard diagnostic suite."""
        checks: list[AtlasDiagnosticCheck] = []
        start = time.perf_counter()
        for c in self._integrity.run_all():
            checks.append(self._time_check(c))
        for c in self._lifecycle.run_all():
            checks.append(self._time_check(c))
        for c in self._release.basic_checks():
            checks.append(self._time_check(c))
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        for c in checks:
            c.duration_ms = elapsed_ms / max(1, len(checks))
        return AtlasDiagnosticReport(checks=checks)

    def run_full(self) -> AtlasDiagnosticReport:
        """Run the deeper diagnostic suite.

        The full suite includes the standard suite plus additional
        release-readiness checks.
        """
        report = self.run()
        for c in self._release.deep_checks():
            report.checks.append(self._time_check(c))
        return report


__all__ = ["AtlasDiagnostics"]
