"""Schema migration runner with deterministic version tracking and idempotency."""

from __future__ import annotations

import datetime
import hashlib
from collections.abc import Sequence
from dataclasses import dataclass

from guardianmesh.core.errors import DatabaseMigrationError
from guardianmesh.storage.database import Database


@dataclass
class Migration:
    """A database migration definition."""

    version: int
    name: str
    up_sql: str

    @property
    def checksum(self) -> str:
        """Compute SHA-256 checksum of the migration SQL."""
        return hashlib.sha256(self.up_sql.strip().encode("utf-8")).hexdigest()


# Ordered list of migrations
MIGRATIONS: Sequence[Migration] = [
    Migration(
        version=1,
        name="001_initial_schema",
        up_sql="""
        CREATE TABLE IF NOT EXISTS identities (
            id TEXT PRIMARY KEY,
            role TEXT NOT NULL CHECK(role IN ('PARENT', 'CHILD')),
            public_key_fingerprint TEXT NOT NULL,
            public_key_pem TEXT NOT NULL,
            created_at TEXT NOT NULL,
            label TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            metadata TEXT DEFAULT '{}'
        );

        CREATE INDEX IF NOT EXISTS idx_identities_active ON identities(is_active);

        CREATE TABLE IF NOT EXISTS config_entries (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '{}',
            timestamp TEXT NOT NULL,
            actor_id TEXT,
            success INTEGER NOT NULL DEFAULT 1
        );

        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_events(event_type);
        """,
    ),
    Migration(
        version=2,
        name="002_pairing_schema",
        up_sql="""
        CREATE TABLE IF NOT EXISTS pairing_sessions (
            session_id TEXT PRIMARY KEY,
            parent_identity_id TEXT NOT NULL,
            child_identity_id TEXT,
            verification_method TEXT NOT NULL CHECK(verification_method IN ('EMAIL', 'SMS', 'DEMO')),
            verification_destination TEXT NOT NULL,
            state TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            verified_at TEXT,
            authorized_at TEXT,
            completed_at TEXT,
            attempt_count INTEGER NOT NULL DEFAULT 0,
            max_attempts INTEGER NOT NULL DEFAULT 5,
            resend_count INTEGER NOT NULL DEFAULT 0,
            last_resend_at TEXT,
            otp_verifier TEXT,
            otp_salt TEXT,
            otp_expires_at TEXT,
            auth_nonce TEXT,
            auth_nonce_expires_at TEXT,
            metadata TEXT DEFAULT '{}'
        );

        CREATE INDEX IF NOT EXISTS idx_pairing_state ON pairing_sessions(state);
        CREATE INDEX IF NOT EXISTS idx_pairing_parent ON pairing_sessions(parent_identity_id);
        CREATE INDEX IF NOT EXISTS idx_pairing_child ON pairing_sessions(child_identity_id);

        CREATE TABLE IF NOT EXISTS pairing_nonces (
            nonce TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            child_identity_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_nonces_session ON pairing_nonces(session_id);

        CREATE TABLE IF NOT EXISTS trusted_devices (
            local_identity_id TEXT NOT NULL,
            remote_identity_id TEXT NOT NULL,
            remote_role TEXT NOT NULL CHECK(remote_role IN ('PARENT', 'CHILD')),
            remote_public_key_fingerprint TEXT NOT NULL,
            remote_public_key_pem TEXT NOT NULL,
            label TEXT,
            status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE', 'REVOKED')),
            created_at TEXT NOT NULL,
            last_verified_at TEXT NOT NULL,
            trust_version INTEGER NOT NULL DEFAULT 1,
            pairing_session_id TEXT,
            metadata TEXT DEFAULT '{}',
            PRIMARY KEY (local_identity_id, remote_identity_id)
        );

        CREATE INDEX IF NOT EXISTS idx_trusted_status ON trusted_devices(status);
        CREATE INDEX IF NOT EXISTS idx_trusted_remote ON trusted_devices(remote_identity_id);
        """,
    ),
    Migration(
        version=3,
        name="003_telemetry_schema",
        up_sql="""
        CREATE TABLE IF NOT EXISTS device_health (
            device_id TEXT PRIMARY KEY,
            health_state TEXT NOT NULL CHECK(health_state IN ('ONLINE', 'DEGRADED', 'OFFLINE', 'UNKNOWN')),
            last_heartbeat_at TEXT NOT NULL,
            last_sequence INTEGER NOT NULL DEFAULT 0,
            battery_percent INTEGER,
            charging INTEGER,
            storage_total_bytes INTEGER,
            storage_free_bytes INTEGER,
            uptime_seconds INTEGER,
            connectivity TEXT NOT NULL CHECK(connectivity IN ('ONLINE', 'DEGRADED', 'OFFLINE', 'UNKNOWN')),
            platform TEXT,
            agent_version TEXT NOT NULL,
            is_paused INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_device_health_state ON device_health(health_state);

        CREATE TABLE IF NOT EXISTS telemetry_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            captured_at TEXT NOT NULL,
            health_state TEXT NOT NULL,
            battery_percent INTEGER,
            charging INTEGER,
            storage_free_bytes INTEGER,
            storage_total_bytes INTEGER,
            uptime_seconds INTEGER,
            connectivity TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_telemetry_device_captured ON telemetry_events(device_id, captured_at);
        CREATE INDEX IF NOT EXISTS idx_telemetry_device_seq ON telemetry_events(device_id, sequence);

        CREATE TABLE IF NOT EXISTS device_sequences (
            device_id TEXT PRIMARY KEY,
            last_outgoing_sequence INTEGER NOT NULL DEFAULT 0,
            last_incoming_sequence INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        );
        """,
    ),
    Migration(
        version=4,
        name="004_sentinel_schema",
        up_sql="""
        CREATE TABLE IF NOT EXISTS policies (
            id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            name TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_policies_device ON policies(device_id);

        CREATE TABLE IF NOT EXISTS policy_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            policy_id TEXT NOT NULL,
            rule_type TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            threshold REAL,
            duration_seconds INTEGER,
            severity TEXT NOT NULL CHECK(severity IN ('INFO', 'WARNING', 'CRITICAL')),
            FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_policy_rules_policy ON policy_rules(policy_id);

        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            policy_id TEXT NOT NULL,
            rule_type TEXT NOT NULL,
            severity TEXT NOT NULL CHECK(severity IN ('INFO', 'WARNING', 'CRITICAL')),
            message TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'ACKNOWLEDGED', 'RESOLVED', 'DISMISSED')),
            dedup_key TEXT NOT NULL,
            trigger_value TEXT,
            created_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            acknowledged_at TEXT,
            resolved_at TEXT,
            dismissed_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_alerts_device ON alerts(device_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
        CREATE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts(dedup_key, status);
        CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
        """,
    ),
    Migration(
        version=6,
        name="006_nexus_transport",
        up_sql="""
        CREATE TABLE IF NOT EXISTS transport_sessions (
            session_id TEXT PRIMARY KEY,
            local_identity_id TEXT NOT NULL,
            remote_identity_id TEXT NOT NULL,
            state TEXT NOT NULL,
            transport_type TEXT NOT NULL,
            created_at TEXT NOT NULL,
            established_at TEXT,
            last_heartbeat_at TEXT,
            expires_at TEXT NOT NULL,
            closed_at TEXT,
            reconnect_count INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            metadata TEXT DEFAULT '{}'
        );

        CREATE INDEX IF NOT EXISTS idx_transport_sessions_remote ON transport_sessions(remote_identity_id);
        CREATE INDEX IF NOT EXISTS idx_transport_sessions_state ON transport_sessions(state);
        CREATE INDEX IF NOT EXISTS idx_transport_sessions_created ON transport_sessions(created_at);

        CREATE TABLE IF NOT EXISTS transport_peers (
            device_id TEXT PRIMARY KEY,
            role TEXT NOT NULL CHECK(role IN ('PARENT', 'CHILD')),
            connection_state TEXT NOT NULL DEFAULT 'DISCONNECTED',
            active_session_id TEXT,
            last_seen_at TEXT,
            last_sync_at TEXT,
            last_heartbeat_at TEXT,
            reconnect_count INTEGER NOT NULL DEFAULT 0,
            endpoint TEXT,
            metadata TEXT DEFAULT '{}',
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_transport_peers_state ON transport_peers(connection_state);
        CREATE INDEX IF NOT EXISTS idx_transport_peers_session ON transport_peers(active_session_id);

        CREATE TABLE IF NOT EXISTS transport_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id TEXT NOT NULL UNIQUE,
            session_id TEXT NOT NULL,
            sender_id TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            message_type TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            direction TEXT NOT NULL CHECK(direction IN ('INBOUND', 'OUTBOUND')),
            created_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'ACCEPTED',
            error_reason TEXT,
            payload_digest TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_transport_msg_device ON transport_messages(recipient_id);
        CREATE INDEX IF NOT EXISTS idx_transport_msg_sender ON transport_messages(sender_id);
        CREATE INDEX IF NOT EXISTS idx_transport_msg_session ON transport_messages(session_id);
        CREATE INDEX IF NOT EXISTS idx_transport_msg_seq ON transport_messages(session_id, sequence);
        CREATE INDEX IF NOT EXISTS idx_transport_msg_created ON transport_messages(created_at);
        CREATE INDEX IF NOT EXISTS idx_transport_msg_status ON transport_messages(status);

        CREATE TABLE IF NOT EXISTS transport_sequences (
            session_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            last_inbound_sequence INTEGER NOT NULL DEFAULT 0,
            last_outbound_sequence INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (session_id, device_id)
        );

        CREATE INDEX IF NOT EXISTS idx_transport_seq_device ON transport_sequences(device_id);
        CREATE INDEX IF NOT EXISTS idx_transport_seq_session ON transport_sequences(session_id);
        """,
    ),
]


class MigrationManager:
    """Handles migration execution, verification, and schema version reporting."""

    def __init__(self, migrations: Sequence[Migration] = MIGRATIONS) -> None:
        self.migrations = sorted(migrations, key=lambda m: m.version)

    def init_migration_table(self, db: Database) -> None:
        """Ensure the schema_migrations tracking table exists."""
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL,
                checksum TEXT NOT NULL
            );
            """
        )

    def get_applied_versions(self, db: Database) -> set[int]:
        """Fetch all previously applied migration version numbers."""
        self.init_migration_table(db)
        rows = db.fetchall("SELECT version FROM schema_migrations ORDER BY version ASC;")
        return {row["version"] for row in rows}

    def get_current_version(self, db: Database) -> int:
        """Get the highest applied migration version number."""
        self.init_migration_table(db)
        row = db.fetchone("SELECT MAX(version) AS max_v FROM schema_migrations;")
        if row and row["max_v"] is not None:
            return int(row["max_v"])
        return 0

    def apply_migrations(self, db: Database) -> list[str]:
        """Apply all pending migrations in order.

        Returns:
            List of names of newly applied migrations.
        """
        self.init_migration_table(db)
        applied_versions = self.get_applied_versions(db)
        newly_applied: list[str] = []

        for migration in self.migrations:
            if migration.version in applied_versions:
                continue

            try:
                with db.transaction() as conn:
                    # Execute migration SQL script
                    conn.executescript(migration.up_sql)
                    # Record migration in tracking table
                    now = datetime.datetime.now(datetime.UTC).isoformat()
                    conn.execute(
                        """
                        INSERT INTO schema_migrations (version, name, applied_at, checksum)
                        VALUES (?, ?, ?, ?);
                        """,
                        (migration.version, migration.name, now, migration.checksum),
                    )
                newly_applied.append(migration.name)
            except Exception as e:
                raise DatabaseMigrationError(
                    f"Failed to apply migration {migration.version} ({migration.name}): {e}"
                ) from e

        return newly_applied
