"""Telemetry processor validating envelope signatures, sequence numbers, and health persistence."""

from __future__ import annotations

import datetime
from typing import Any

from guardianmesh.core.config import GuardianConfig
from guardianmesh.core.errors import (
    DeviceNotTrustedError,
    TelemetryAuthenticationError,
    TelemetryDevicePausedError,
    TelemetryReplayError,
    TelemetrySignatureError,
    TelemetryTimestampError,
    TrustRevokedError,
)
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.storage.audit import AuditEventType, AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.telemetry.models import (
    ConnectivityState,
    DeviceHealthState,
    DeviceHealthSummary,
    TelemetryEnvelope,
    validate_health_payload,
)
from guardianmesh.telemetry.sequence import SequenceManager


class TelemetryProcessor:
    """Processes incoming authenticated telemetry envelopes and persists device health state."""

    def __init__(
        self,
        db: Database,
        config: GuardianConfig,
        trust_manager: TrustManager,
        sequence_manager: SequenceManager | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.db = db
        self.config = config
        self.trust_manager = trust_manager
        self.sequence_manager = sequence_manager or SequenceManager(db)
        self.audit_logger = audit_logger or AuditLogger(db)

    def process_envelope(self, envelope: TelemetryEnvelope, local_identity_id: str) -> DeviceHealthSummary:
        """Authenticate, validate, and store a received telemetry envelope.

        Args:
            envelope: Incoming TelemetryEnvelope.
            local_identity_id: Local identity ID for trust relationship verification.

        Returns:
            Updated DeviceHealthSummary.
        """
        device_id = envelope.device_id

        # 1. Payload validation against strict allowlist
        validate_health_payload(envelope.payload)

        # 2. Authenticate remote device via Phase 2 TrustManager
        try:
            trusted_device = self.trust_manager.verify_device_trust_or_raise(
                local_identity_id=local_identity_id,
                remote_identity_id=device_id,
            )
        except (DeviceNotTrustedError, TrustRevokedError) as e:
            self.audit_logger.record(
                event_type=AuditEventType.TELEMETRY_REJECTED,
                details={"device_id": device_id, "reason": str(e)},
                actor_id=local_identity_id,
                success=False,
            )
            raise TelemetryAuthenticationError(f"Telemetry from untrusted device: {e}") from e

        # 3. Verify cryptographic Ed25519 signature
        if not envelope.verify_signature(trusted_device.remote_public_key_pem):
            self.audit_logger.record(
                event_type=AuditEventType.TELEMETRY_SIGNATURE_REJECTED,
                details={"device_id": device_id, "sequence": envelope.sequence},
                actor_id=local_identity_id,
                success=False,
            )
            raise TelemetrySignatureError(
                f"Cryptographic signature verification failed for telemetry envelope from '{device_id}'."
            )

        # 4. Validate timestamp & clock skew tolerance
        try:
            captured_dt = datetime.datetime.fromisoformat(envelope.captured_at)
            now = datetime.datetime.now(datetime.UTC)

            # Check future skew
            skew_limit = datetime.timedelta(seconds=self.config.timestamp_skew_tolerance_seconds)
            if captured_dt > (now + skew_limit):
                raise TelemetryTimestampError(
                    f"Telemetry timestamp '{envelope.captured_at}' is too far in the future."
                )

            # Check past expiration
            retention_limit = datetime.timedelta(days=self.config.telemetry_retention_days)
            if captured_dt < (now - retention_limit):
                raise TelemetryTimestampError(
                    f"Telemetry timestamp '{envelope.captured_at}' has expired beyond retention window."
                )
        except Exception as e:
            if isinstance(e, TelemetryTimestampError):
                raise
            raise TelemetryTimestampError(f"Invalid timestamp format '{envelope.captured_at}': {e}") from e

        # 5. Check if collection is paused
        if self.is_device_paused(device_id):
            raise TelemetryDevicePausedError(
                f"Telemetry collection is currently paused for device '{device_id}'."
            )

        # 6. Monotonic Sequence Verification & Replay Protection
        try:
            self.sequence_manager.validate_and_advance_incoming_sequence(
                device_id=device_id,
                sequence=envelope.sequence,
            )
        except TelemetryReplayError:
            self.audit_logger.record(
                event_type=AuditEventType.TELEMETRY_REPLAY_REJECTED,
                details={"device_id": device_id, "sequence": envelope.sequence},
                actor_id=local_identity_id,
                success=False,
            )
            raise

        # 7. Derive health state
        health_state = self.derive_health_state(envelope.captured_at, envelope.payload.get("connectivity"))
        payload = envelope.payload
        now_str = datetime.datetime.now(datetime.UTC).isoformat()

        # 8. Persist health snapshot and event history
        with self.db.transaction() as conn:
            raw_chg = payload.get("charging")
            chg_val = 1 if raw_chg is True else (0 if raw_chg is False else None)
            conn.execute(
                """
                INSERT INTO device_health (
                    device_id, health_state, last_heartbeat_at, last_sequence,
                    battery_percent, charging, storage_total_bytes, storage_free_bytes,
                    uptime_seconds, connectivity, platform, agent_version, is_paused, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    health_state = excluded.health_state,
                    last_heartbeat_at = excluded.last_heartbeat_at,
                    last_sequence = excluded.last_sequence,
                    battery_percent = excluded.battery_percent,
                    charging = excluded.charging,
                    storage_total_bytes = excluded.storage_total_bytes,
                    storage_free_bytes = excluded.storage_free_bytes,
                    uptime_seconds = excluded.uptime_seconds,
                    connectivity = excluded.connectivity,
                    platform = excluded.platform,
                    agent_version = excluded.agent_version,
                    updated_at = excluded.updated_at;
                """,
                (
                    device_id,
                    health_state.value,
                    envelope.captured_at,
                    envelope.sequence,
                    payload.get("battery_percent"),
                    chg_val,
                    payload.get("storage_total_bytes"),
                    payload.get("storage_free_bytes"),
                    payload.get("uptime_seconds"),
                    str(payload.get("connectivity", "ONLINE")),
                    payload.get("platform"),
                    str(payload.get("agent_version", "0.3.0")),
                    now_str,
                ),
            )

            conn.execute(
                """
                INSERT INTO telemetry_events (
                    device_id, sequence, captured_at, health_state,
                    battery_percent, charging, storage_free_bytes,
                    storage_total_bytes, uptime_seconds, connectivity, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    device_id,
                    envelope.sequence,
                    envelope.captured_at,
                    health_state.value,
                    payload.get("battery_percent"),
                    chg_val,
                    payload.get("storage_free_bytes"),
                    payload.get("storage_total_bytes"),
                    payload.get("uptime_seconds"),
                    str(payload.get("connectivity", "ONLINE")),
                    now_str,
                ),
            )

        self.audit_logger.record(
            event_type=AuditEventType.TELEMETRY_ACCEPTED,
            details={
                "device_id": device_id,
                "sequence": envelope.sequence,
                "health_state": health_state.value,
            },
            actor_id=local_identity_id,
            success=True,
        )

        health_summary = self.get_device_health(device_id) or DeviceHealthSummary(device_id=device_id)

        # Evaluate Sentinel policies if enabled
        if self.config.policy_evaluation_enabled:
            try:
                from guardianmesh.policy.engine import PolicyEngine

                engine = PolicyEngine(
                    self.db, self.config, self.trust_manager, audit_logger=self.audit_logger
                )
                engine.evaluate_device_health(health_summary, local_identity_id=local_identity_id)
            except Exception:
                pass

        return health_summary

    def derive_health_state(
        self, last_seen_iso: str, connectivity_val: str | None = None
    ) -> DeviceHealthState:
        """Derive health state based on heartbeat timeliness and connectivity."""
        if connectivity_val and connectivity_val.upper() == "OFFLINE":
            return DeviceHealthState.OFFLINE

        try:
            captured_dt = datetime.datetime.fromisoformat(last_seen_iso)
            now = datetime.datetime.now(datetime.UTC)
            elapsed = (now - captured_dt).total_seconds()

            if elapsed <= self.config.health_degraded_threshold_seconds:
                return DeviceHealthState.ONLINE
            elif elapsed <= self.config.health_offline_threshold_seconds:
                return DeviceHealthState.DEGRADED
            return DeviceHealthState.OFFLINE
        except Exception:
            return DeviceHealthState.UNKNOWN

    def get_device_health(self, device_id: str) -> DeviceHealthSummary | None:
        """Fetch current consolidated health summary for a device."""
        row = self.db.fetchone("SELECT * FROM device_health WHERE device_id = ?;", (device_id,))
        if not row:
            return None

        last_seen = row["last_heartbeat_at"]
        last_seen_sec: int | None = None
        try:
            dt = datetime.datetime.fromisoformat(last_seen)
            now = datetime.datetime.now(datetime.UTC)
            last_seen_sec = max(0, int((now - dt).total_seconds()))
        except Exception:
            pass

        return DeviceHealthSummary(
            device_id=row["device_id"],
            health_state=DeviceHealthState.from_str(row["health_state"]),
            last_heartbeat_at=last_seen,
            battery_percent=row["battery_percent"],
            is_charging=bool(row["charging"]) if row["charging"] is not None else None,
            storage_free_bytes=row["storage_free_bytes"],
            storage_total_bytes=row["storage_total_bytes"],
            uptime_seconds=row["uptime_seconds"],
            connectivity=ConnectivityState.from_str(row["connectivity"]),
            platform=row["platform"],
            agent_version=row["agent_version"],
            last_sequence=int(row["last_sequence"]),
            is_paused=bool(row["is_paused"]),
            last_seen_seconds_ago=last_seen_sec,
        )

    def get_health_history(
        self,
        device_id: str,
        limit: int = 50,
        since_utc: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch historical health snapshot events."""
        if since_utc:
            rows = self.db.fetchall(
                """
                SELECT * FROM telemetry_events
                WHERE device_id = ? AND captured_at >= ?
                ORDER BY captured_at DESC
                LIMIT ?;
                """,
                (device_id, since_utc, limit),
            )
        else:
            rows = self.db.fetchall(
                """
                SELECT * FROM telemetry_events
                WHERE device_id = ?
                ORDER BY captured_at DESC
                LIMIT ?;
                """,
                (device_id, limit),
            )

        results: list[dict[str, Any]] = []
        for r in rows:
            results.append(
                {
                    "id": r["id"],
                    "device_id": r["device_id"],
                    "sequence": r["sequence"],
                    "captured_at": r["captured_at"],
                    "health_state": r["health_state"],
                    "battery_percent": r["battery_percent"],
                    "charging": bool(r["charging"]) if r["charging"] is not None else None,
                    "storage_free_bytes": r["storage_free_bytes"],
                    "storage_total_bytes": r["storage_total_bytes"],
                    "uptime_seconds": r["uptime_seconds"],
                    "connectivity": r["connectivity"],
                }
            )
        return results

    def pause_device(self, device_id: str) -> bool:
        """Pause telemetry collection and processing for a device."""
        now = datetime.datetime.now(datetime.UTC).isoformat()
        self.db.execute(
            """
            INSERT INTO device_health (
                device_id, health_state, last_heartbeat_at, last_sequence,
                connectivity, agent_version, is_paused, updated_at
            )
            VALUES (?, 'UNKNOWN', ?, 0, 'UNKNOWN', '0.3.0', 1, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                is_paused = 1,
                updated_at = excluded.updated_at;
            """,
            (device_id, now, now),
        )
        self.audit_logger.record(
            event_type=AuditEventType.TELEMETRY_PAUSED,
            details={"device_id": device_id},
            actor_id=device_id,
            success=True,
        )
        return True

    def resume_device(self, device_id: str) -> bool:
        """Resume telemetry collection and processing for a device."""
        self.db.execute(
            "UPDATE device_health SET is_paused = 0, updated_at = ? WHERE device_id = ?;",
            (datetime.datetime.now(datetime.UTC).isoformat(), device_id),
        )
        self.audit_logger.record(
            event_type=AuditEventType.TELEMETRY_RESUMED,
            details={"device_id": device_id},
            actor_id=device_id,
            success=True,
        )
        return True

    def is_device_paused(self, device_id: str) -> bool:
        """Check if telemetry collection for device is currently paused."""
        row = self.db.fetchone("SELECT is_paused FROM device_health WHERE device_id = ?;", (device_id,))
        if not row:
            return False
        return bool(row["is_paused"])

    def cleanup_retention(self, retention_days: int | None = None) -> int:
        """Delete historical telemetry records older than retention window."""
        days = retention_days or self.config.telemetry_retention_days
        cutoff = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=days)).isoformat()

        with self.db.transaction() as conn:
            cursor = conn.execute("DELETE FROM telemetry_events WHERE captured_at < ?;", (cutoff,))
            deleted_count = cursor.rowcount

        self.audit_logger.record(
            event_type=AuditEventType.TELEMETRY_CLEANUP,
            details={"retention_days": days, "records_purged": deleted_count},
            success=True,
        )
        return deleted_count
