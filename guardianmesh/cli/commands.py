"""CLI command implementations for GuardianMesh."""

from __future__ import annotations

import argparse
import datetime
import json
import shutil
import sys
from typing import Any

from guardianmesh import __phase__, __version__
from guardianmesh.console.dashboard import DashboardController
from guardianmesh.console.formatters import TerminalFormatter
from guardianmesh.console.navigation import ConsoleNavigator
from guardianmesh.console.renderer import ConsoleRenderer
from guardianmesh.console.services import ConsoleService
from guardianmesh.core.config import GuardianConfig, load_config, save_config
from guardianmesh.core.errors import (
    ChildAuthorizationDeniedError,
    GuardianMeshError,
    TrustRevokedError,
)
from guardianmesh.core.paths import (
    check_directory_permissions,
    check_file_permissions,
)
from guardianmesh.device.collectors import DeviceCollector
from guardianmesh.device.platform import get_platform_info
from guardianmesh.identity.manager import IdentityManager
from guardianmesh.identity.models import IdentityRole, validate_identity_id
from guardianmesh.pairing.authorization import LocalTestAuthorizationAdapter
from guardianmesh.pairing.manager import PairingManager
from guardianmesh.pairing.models import PairingState
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.policy.alerts import AlertManager
from guardianmesh.policy.engine import PolicyEngine
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.audit import AuditEventType, AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager
from guardianmesh.telemetry.models import TelemetryEnvelope
from guardianmesh.telemetry.processor import TelemetryProcessor
from guardianmesh.telemetry.sequence import SequenceManager
from guardianmesh.transport.client import MemoryTransportClient
from guardianmesh.transport.crypto import derive_session_keys, generate_ephemeral_keypair
from guardianmesh.transport.models import ConnectionState
from guardianmesh.transport.reconnect import ReconnectManager
from guardianmesh.transport.registry import TransportRegistry
from guardianmesh.transport.router import MessageRouter
from guardianmesh.transport.server import MemoryTransportServer
from guardianmesh.transport.session import TransportSession


def get_terminal_width() -> int:
    """Get the current terminal width with safe fallbacks."""
    try:
        width = shutil.get_terminal_size(fallback=(80, 24)).columns
        return max(40, min(width, 100))
    except Exception:
        return 80


def print_divider(char: str = "─", width: int | None = None) -> None:
    """Print a clean visual divider line."""
    w = width or min(get_terminal_width(), 32)
    print(char * w)


def cmd_version(args: argparse.Namespace, config: GuardianConfig) -> int:
    """Print the product version and phase name."""
    print(f"GuardianMesh {__version__}")
    print(f"{__phase__}")
    return 0


def cmd_init(args: argparse.Namespace, config: GuardianConfig) -> int:
    """Initialize local GuardianMesh directories, database, keypair, and active identity."""
    config.ensure_directories()
    save_config(config)

    db = Database(config.database_path)
    migration_mgr = MigrationManager()
    newly_applied = migration_mgr.apply_migrations(db)

    audit_logger = AuditLogger(db)
    if newly_applied:
        audit_logger.record(
            event_type=AuditEventType.DATABASE_INITIALIZED,
            details={"migrations_applied": newly_applied},
            success=True,
        )

    key_storage = KeyStorageManager(config.keys_dir)
    identity_mgr = IdentityManager(db, key_storage, audit_logger)

    active_identity = identity_mgr.get_active_identity()
    force = getattr(args, "force", False)

    if active_identity and not force:
        print("GuardianMesh is already initialized.")
        print_divider()
        print(f"Active Identity: {active_identity.id} ({active_identity.role.value})")
        print(f"Public Key FP:   {active_identity.public_key_fingerprint}")
        print(f"Database:        {config.database_path}")
        print("\nUse 'guardian status' or 'guardian doctor' to inspect system health.")
        return 0

    role_str = getattr(args, "role", None) or config.default_role
    role = IdentityRole.from_str(role_str)
    label = getattr(args, "label", None) or f"Primary {role.value.capitalize()} Device"

    identity, priv_path = identity_mgr.create_identity(
        role=role,
        label=label,
        set_active=True,
    )

    print(f"GuardianMesh {__phase__} Initialized")
    print_divider()
    print(f"{'Identity ID':<14} {identity.id}")
    print(f"{'Role':<14} {identity.role_display}")
    print(f"{'Fingerprint':<14} {identity.public_key_fingerprint}")
    print(f"{'Key Storage':<14} {config.keys_dir}")
    print(f"{'Database':<14} {config.database_path}")
    print(f"{'Status':<14} READY")

    return 0


def cmd_status(args: argparse.Namespace, config: GuardianConfig) -> int:
    """Display the current operational status of local GuardianMesh components."""
    print("GuardianMesh Status")
    print_divider()

    db = Database(config.database_path)
    key_storage = KeyStorageManager(config.keys_dir)
    identity_mgr = IdentityManager(db, key_storage)

    # Identity status
    print("Identity:")
    if not config.database_path.is_file():
        print("  Status        NOT INITIALIZED (run 'guardian init')")
    else:
        try:
            active_identity = identity_mgr.get_active_identity()
            if active_identity:
                role_label = "Parent ID" if active_identity.role == IdentityRole.PARENT else "Child ID"
                print(f"  {role_label:<14}{active_identity.id}")
                if active_identity.label:
                    print(f"  {'Label':<14}{active_identity.label}")
                print(f"  {'Status':<14}READY")
            else:
                print("  Status        NO ACTIVE IDENTITY (run 'guardian init')")
        except Exception:
            print("  Status        ERROR READING IDENTITY")

    print()

    # Storage status
    print("Storage:")
    if not config.database_path.is_file():
        print("  Database      NOT INITIALIZED")
    else:
        try:
            healthy, _ = db.check_integrity()
            db_status = "READY" if healthy else "INTEGRITY ERROR"
            print(f"  Database      {db_status}")
        except Exception:
            print("  Database      UNAVAILABLE")

    print()

    # Security status
    print("Security:")
    if not config.keys_dir.is_dir():
        print("  Key material  NOT INITIALIZED")
    else:
        try:
            active_id = identity_mgr.get_active_identity()
            if active_id and key_storage.has_keys(active_id.id):
                perms_ok, _ = key_storage.verify_permissions(active_id.id)
                sec_status = "READY" if perms_ok else "WARNING (Permissions)"
                print(f"  Key material  {sec_status}")
            elif not active_id:
                print("  Key material  NO ACTIVE IDENTITY")
            else:
                print("  Key material  MISSING KEY FILES")
        except Exception:
            print("  Key material  UNAVAILABLE")

    print()

    # Pairing status
    print("Pairing:")
    if not config.database_path.is_file():
        print("  Not configured")
    else:
        try:
            trust_mgr = TrustManager(db)
            trusted_list = trust_mgr.list_trusted_devices(status="ACTIVE")
            pairing_mgr = PairingManager(db, config, key_storage, trust_mgr)
            active_sessions = pairing_mgr.list_sessions(state=PairingState.VERIFICATION_PENDING)
            pending_auth = pairing_mgr.list_sessions(state=PairingState.CHILD_AUTHORIZATION_PENDING)

            if not trusted_list and not active_sessions and not pending_auth:
                print("  Status        READY (0 trusted devices)")
            else:
                print(f"  Trusted       {len(trusted_list)} active device(s)")
                if active_sessions or pending_auth:
                    total_pending = len(active_sessions) + len(pending_auth)
                    print(f"  Sessions      {total_pending} active/pending pairing session(s)")
        except Exception:
            print("  Not configured")

    print()

    # Telemetry & Sentinel Alert status
    print("Telemetry & Sentinel:")
    if not config.database_path.is_file():
        print("  Not configured")
    else:
        try:
            trust_mgr = TrustManager(db)
            trusted_list = trust_mgr.list_trusted_devices(status="ACTIVE")
            processor = TelemetryProcessor(db, config, trust_mgr)
            alert_mgr = AlertManager(db, config)
            active_alerts = alert_mgr.get_active_alerts()

            if not trusted_list:
                print("  Status        READY (0 devices monitored)")
            else:
                summaries = []
                for dev in trusted_list:
                    h = processor.get_device_health(dev.remote_identity_id)
                    state_str = h.health_state.value if h else "UNKNOWN"
                    summaries.append(f"{dev.remote_identity_id}: {state_str}")
                print(f"  Monitored     {len(trusted_list)} device(s) ({', '.join(summaries)})")
                print(f"  Active Alerts {len(active_alerts)}")
        except Exception:
            print("  Status        READY")

    print()

    # Transport status (Phase 6: Nexus)
    print("Transport:")
    if not config.database_path.is_file():
        print("  Not configured")
    else:
        try:
            trans_reg = TransportRegistry(db)
            all_peers = trans_reg.list_peers()
            connected_p = [p for p in all_peers if p.connection_state == ConnectionState.CONNECTED]
            active_s = trans_reg.list_sessions(state="CONNECTED")
            print(f"  Status        {'READY' if config.transport_enabled else 'DISABLED'}")
            print(f"  Endpoint      {config.transport_listen_host}:{config.transport_listen_port}")
            print(f"  Peers         {len(connected_p)} connected / {len(all_peers)} total")
            print(f"  Sessions      {len(active_s)} active")
        except Exception:
            print("  Status        READY")

    return 0


def cmd_doctor(args: argparse.Namespace, config: GuardianConfig) -> int:
    """Run comprehensive environment, permission, database, and cryptographic diagnostic checks."""
    print("GuardianMesh Doctor")
    print_divider()

    critical_failure = False
    checks: list[tuple[str, bool, str | None]] = []

    # 1. Python Environment Check
    py_ver = sys.version_info
    py_ok = py_ver >= (3, 11)
    py_msg = None if py_ok else f"Python {py_ver[0]}.{py_ver[1]} is below minimum required 3.11+"
    checks.append(("Python", py_ok, py_msg))
    if not py_ok:
        critical_failure = True

    # 2. Platform / Termux Check
    plat_info = get_platform_info()
    plat_ok = True
    plat_msg = None
    if plat_info.is_root:
        plat_msg = "Running as root is not recommended for GuardianMesh."
    checks.append(("Platform", plat_ok, plat_msg))

    # 3. Data Directory Check
    data_dir_ok = True
    data_dir_msg = None
    if not config.data_dir.is_dir():
        data_dir_ok = False
        data_dir_msg = f"Data directory {config.data_dir} does not exist. Run 'guardian init'."
    else:
        if not check_directory_permissions(config.data_dir, max_mode=0o700):
            data_dir_msg = f"Data directory {config.data_dir} has permissive permissions (expected 0700)."
    checks.append(("Data directory", data_dir_ok, data_dir_msg))
    if not data_dir_ok:
        critical_failure = True

    # 4. Database Check
    db_ok = True
    db_msg = None
    db = Database(config.database_path)
    if not config.database_path.is_file():
        db_ok = False
        db_msg = "Database not initialized. Run 'guardian init'."
    else:
        healthy, integrity_msg = db.check_integrity()
        if not healthy:
            db_ok = False
            db_msg = f"Integrity check failed: {integrity_msg}"
        else:
            try:
                migration_mgr = MigrationManager()
                current_v = migration_mgr.get_current_version(db)
                if current_v < 1:
                    db_ok = False
                    db_msg = "Database schema migrations not applied."
            except Exception as e:
                db_ok = False
                db_msg = f"Database query error: {e}"

    checks.append(("Database", db_ok, db_msg))
    if not db_ok:
        critical_failure = True

    # 5. Identity Check
    identity_ok = True
    identity_msg = None
    key_storage = KeyStorageManager(config.keys_dir)
    identity_mgr = IdentityManager(db, key_storage)

    if not db_ok:
        identity_ok = False
        identity_msg = "Database unavailable for identity verification."
    else:
        try:
            active_id = identity_mgr.get_active_identity()
            if not active_id:
                identity_ok = False
                identity_msg = "No active identity configured. Run 'guardian init'."
            else:
                is_valid, err = validate_identity_id(active_id.id)
                if not is_valid:
                    identity_ok = False
                    identity_msg = f"Invalid active identity format: {err}"
        except Exception as e:
            identity_ok = False
            identity_msg = f"Error reading identity: {e}"

    checks.append(("Identity", identity_ok, identity_msg))
    if not identity_ok:
        critical_failure = True

    # 6. Key Storage Check
    key_ok = True
    key_msg = None
    if not config.keys_dir.is_dir():
        key_ok = False
        key_msg = f"Keys directory '{config.keys_dir}' not found."
    else:
        if db_ok:
            try:
                active_id = identity_mgr.get_active_identity()
                if active_id:
                    if not key_storage.has_keys(active_id.id):
                        key_ok = False
                        key_msg = f"Key material missing for active identity '{active_id.id}'."
                    else:
                        valid_integrity, integ_err = identity_mgr.validate_identity_integrity(active_id.id)
                        if not valid_integrity:
                            key_ok = False
                            key_msg = f"Cryptographic integrity failed: {integ_err}"
            except Exception as e:
                key_ok = False
                key_msg = f"Key verification error: {e}"

    checks.append(("Key storage", key_ok, key_msg))
    if not key_ok:
        critical_failure = True

    # 7. Permissions Check
    perms_ok = True
    perms_msg = None
    if config.keys_dir.is_dir():
        keys_dir_secure = check_directory_permissions(config.keys_dir, max_mode=0o700)
        if not keys_dir_secure:
            perms_ok = False
            perms_msg = f"Keys directory '{config.keys_dir}' has loose permissions."
    if perms_ok and db_ok:
        try:
            active_id = identity_mgr.get_active_identity()
            if active_id:
                priv_path = key_storage.get_private_key_path(active_id.id)
                if priv_path.is_file() and not check_file_permissions(priv_path, max_mode=0o600):
                    perms_ok = False
                    perms_msg = f"Private key '{priv_path}' permissions are too permissive."
        except Exception:
            pass

    checks.append(("Permissions", perms_ok, perms_msg))
    if not perms_ok:
        critical_failure = True

    # 8. Configuration Check
    cfg_ok = True
    cfg_msg = None
    try:
        _ = load_config(config.home_dir)
    except Exception as e:
        cfg_ok = False
        cfg_msg = f"Configuration invalid: {e}"

    checks.append(("Configuration", cfg_ok, cfg_msg))
    if not cfg_ok:
        critical_failure = True

    # 9. Transport Module Check (Phase 6: Nexus)
    trans_mod_ok = True
    trans_mod_msg = None
    try:
        import guardianmesh.transport as _transport_module

        if not hasattr(_transport_module, "TransportSession"):
            trans_mod_ok = False
            trans_mod_msg = "Transport module missing core components."
    except Exception as e:
        trans_mod_ok = False
        trans_mod_msg = f"Failed to import transport module: {e}"

    checks.append(("Transport module", trans_mod_ok, trans_mod_msg))
    if not trans_mod_ok:
        critical_failure = True

    # 10. Cryptographic Backend Check (Nexus)
    crypto_backend_ok = True
    crypto_backend_msg = None
    try:
        _ep_priv, _ep_pub = generate_ephemeral_keypair()
        _sec = _ep_priv.exchange(_ep_pub)
        _sk, _rk, _salt = derive_session_keys(_sec, b"salt", is_initiator=True)
        if len(_sk) != 32 or len(_rk) != 32:
            crypto_backend_ok = False
            crypto_backend_msg = "Session key derivation length check failed."
    except Exception as e:
        crypto_backend_ok = False
        crypto_backend_msg = f"Cryptographic backend verification failed: {e}"

    checks.append(("Cryptographic backend", crypto_backend_ok, crypto_backend_msg))
    if not crypto_backend_ok:
        critical_failure = True

    # 11. Trust Registry Check (Nexus)
    trust_reg_ok = True
    trust_reg_msg = None
    if not db_ok:
        trust_reg_ok = False
        trust_reg_msg = "Database unavailable for trust registry."
    else:
        try:
            trust_mgr = TrustManager(db)
            _ = trust_mgr.list_trusted_devices()
        except Exception as e:
            trust_reg_ok = False
            trust_reg_msg = f"Trust registry query error: {e}"

    checks.append(("Trust registry", trust_reg_ok, trust_reg_msg))
    if not trust_reg_ok:
        critical_failure = True

    # 12. Session Database Check (Nexus)
    sess_db_ok = True
    sess_db_msg = None
    if not db_ok:
        sess_db_ok = False
        sess_db_msg = "Database unavailable for session tracking."
    else:
        try:
            reg = TransportRegistry(db)
            _ = reg.list_sessions(limit=1)
        except Exception as e:
            sess_db_ok = False
            sess_db_msg = f"Transport sessions table query error: {e}"

    checks.append(("Session database", sess_db_ok, sess_db_msg))
    if not sess_db_ok:
        critical_failure = True

    # 13. Replay Protection Check (Nexus)
    replay_ok = True
    replay_msg = None
    try:
        _ts = TransportSession(
            local_identity_id="GM-P-00000000",
            remote_identity_id="GM-C-00000000",
        )
        _ts.validate_and_advance_inbound_sequence(1, "MSG-TEST1")
        try:
            _ts.validate_and_advance_inbound_sequence(1, "MSG-TEST1")
            replay_ok = False
            replay_msg = "Replay defense failed to reject duplicate sequence."
        except Exception:
            replay_ok = True
    except Exception as e:
        replay_ok = False
        replay_msg = f"Replay defense initialization error: {e}"

    checks.append(("Replay protection", replay_ok, replay_msg))
    if not replay_ok:
        critical_failure = True

    # 14. Local Transport Check (Nexus)
    local_trans_ok = True
    local_trans_msg = None
    try:
        _mt = MemoryTransportClient(
            db=db,
            local_identity_id="GM-P-00000000",
            local_private_key=None,  # type: ignore[arg-type]
            trust_manager=TrustManager(db),
        )
        if _mt is None:
            local_trans_ok = False
    except Exception as e:
        local_trans_ok = False
        local_trans_msg = f"Local transport initialization error: {e}"

    checks.append(("Local transport", local_trans_ok, local_trans_msg))
    if not local_trans_ok:
        critical_failure = True

    # 15. Message Router Check (Nexus)
    router_ok = True
    router_msg = None
    try:
        _mr = MessageRouter(
            db=db,
            local_identity_id="GM-P-00000000",
            trust_manager=TrustManager(db),
        )
        if _mr is None:
            router_ok = False
    except Exception as e:
        router_ok = False
        router_msg = f"Message router initialization error: {e}"

    checks.append(("Message router", router_ok, router_msg))
    if not router_ok:
        critical_failure = True

    # Output formatted results
    for name, ok, reason in checks:
        indicator = "✓" if ok else "✗"
        print(f"{name:<19}{indicator}")
        if not ok and reason:
            print(f"  Reason: {reason}")
        elif ok and reason:
            print(f"  Notice: {reason}")

    if db_ok:
        try:
            audit_logger = AuditLogger(db)
            audit_logger.record(
                event_type=AuditEventType.DOCTOR_RUN,
                details={
                    "all_passed": not critical_failure,
                    "failed_checks": [name for name, ok, _ in checks if not ok],
                },
                success=not critical_failure,
            )
        except Exception:
            pass

    return 1 if critical_failure else 0


def cmd_identity(args: argparse.Namespace, config: GuardianConfig) -> int:
    """Manage local identities (create, list, show, activate)."""
    subcmd = getattr(args, "identity_action", None)
    if not subcmd:
        print("Usage: guardian identity [list | show | create | activate]")
        return 1

    config.ensure_directories()
    db = Database(config.database_path)
    key_storage = KeyStorageManager(config.keys_dir)
    identity_mgr = IdentityManager(db, key_storage)

    if subcmd == "create":
        role_str = getattr(args, "role", "PARENT") or "PARENT"
        role = IdentityRole.from_str(role_str)
        label = getattr(args, "label", None)
        set_active = getattr(args, "activate", True)

        MigrationManager().apply_migrations(db)

        identity, priv_path = identity_mgr.create_identity(
            role=role,
            label=label,
            set_active=set_active,
        )

        print("Identity Created")
        print_divider()
        print(f"{'Identity ID':<14} {identity.id}")
        print(f"{'Role':<14} {identity.role_display}")
        print(f"{'Fingerprint':<14} {identity.public_key_fingerprint}")
        print(f"{'Key File':<14} {priv_path}")
        print(f"{'Active':<14} {identity.is_active}")
        return 0

    elif subcmd == "list":
        if not config.database_path.is_file():
            print("No identities found. Run 'guardian init'.")
            return 0

        identities = identity_mgr.list_identities()
        if not identities:
            print("No identities found. Run 'guardian init' or 'guardian identity create'.")
            return 0

        print(f"{'ID':<15} {'ROLE':<8} {'STATUS':<8} {'LABEL':<20} {'FINGERPRINT'}")
        print_divider(width=72)
        for ident in identities:
            status = "ACTIVE" if ident.is_active else "INACTIVE"
            label = ident.label or "-"
            fp_short = f"{ident.public_key_fingerprint[:22]}..."
            print(f"{ident.id:<15} {ident.role.value:<8} {status:<8} {label:<20} {fp_short}")
        return 0

    elif subcmd == "show":
        if not config.database_path.is_file():
            print("Database not initialized. Run 'guardian init'.")
            return 1

        target_id = getattr(args, "id", None)
        target_identity = (
            identity_mgr.get_identity(target_id) if target_id else identity_mgr.get_active_identity()
        )

        if not target_identity:
            print("Identity not found.")
            return 1

        print("Identity Details")
        print_divider()
        print(f"{'Identity ID':<14} {target_identity.id}")
        print(f"{'Role':<14} {target_identity.role_display}")
        print(f"{'Active':<14} {target_identity.is_active}")
        print(f"{'Created':<14} {target_identity.created_at}")
        print(f"{'Fingerprint':<14} {target_identity.public_key_fingerprint}")
        if target_identity.label:
            print(f"{'Label':<14} {target_identity.label}")
        return 0

    elif subcmd == "activate":
        target_id = getattr(args, "id", None)
        if not target_id:
            print("Error: Identity ID required.")
            return 1

        try:
            identity_mgr.set_active_identity(target_id)
            print(f"Activated identity: {target_id}")
            return 0
        except GuardianMeshError as e:
            print(f"Error: {e}")
            return 1

    return 0


def cmd_pair(args: argparse.Namespace, config: GuardianConfig) -> int:
    """Manage parent-child device pairing sessions and trust relationships."""
    subcmd = getattr(args, "pair_action", None)

    if not config.database_path.is_file():
        print("Database not initialized. Run 'guardian init' first.")
        return 1

    db = Database(config.database_path)
    key_storage = KeyStorageManager(config.keys_dir)
    identity_mgr = IdentityManager(db, key_storage)
    active_identity = identity_mgr.get_active_identity()

    if not active_identity:
        print("No active identity found. Run 'guardian init' first.")
        return 1

    trust_mgr = TrustManager(db)
    pairing_mgr = PairingManager(db, config, key_storage, trust_mgr)

    # Default / start
    if not subcmd or subcmd == "start":
        method = getattr(args, "method", None)
        destination = getattr(args, "destination", None)
        child_id = getattr(args, "child_id", None)

        if not method:
            print("GuardianMesh")
            print("Secure Pairing")
            print_divider()
            print("Parent Identity\n")
            print(f"{active_identity.id}\n")
            print("Verification method\n")
            email_status = "● READY" if config.smtp_host else "○ CONFIGURE SMTP"
            print(f"  1. Email       {email_status}")
            print("  2. SMS         ○ OPTIONAL")
            print("  3. Demo        ● READY\n")

            try:
                choice = input("Select [1-3]: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nPairing cancelled.")
                return 130

            if choice in ("1", "email", "EMAIL"):
                method = "EMAIL"
                try:
                    destination = input("Parent Email Address: ").strip()
                except (EOFError, KeyboardInterrupt):
                    return 130
            elif choice in ("2", "sms", "SMS"):
                method = "SMS"
                try:
                    destination = input("Phone Number: ").strip()
                except (EOFError, KeyboardInterrupt):
                    return 130
            elif choice in ("3", "demo", "DEMO"):
                method = "DEMO"
                destination = "demo@guardianmesh.local"
            else:
                print("Invalid selection.")
                return 1

        if not destination:
            if method.upper() == "DEMO":
                destination = "demo@guardianmesh.local"
            else:
                print("Error: Verification destination is required.")
                return 1

        try:
            session, demo_otp = pairing_mgr.create_session(
                parent_identity_id=active_identity.id,
                verification_method=method,
                verification_destination=destination,
                child_identity_id=child_id,
            )
            print("Pairing Session Created")
            print_divider()
            print(f"{'Session ID':<16} {session.session_id}")
            print(f"{'Parent ID':<16} {session.parent_identity_id}")
            print(f"{'Method':<16} {session.verification_method}")
            print(f"{'Destination':<16} {session.verification_destination}")
            print(f"{'State':<16} {session.state.value}")
            print(f"{'Expires In':<16} {session.seconds_remaining()}s")
            print("\nNext step:")
            print(f"  guardian pair verify {session.session_id} <verification_code>")
            return 0
        except GuardianMeshError as e:
            print(f"Error: {e}")
            return 1

    elif subcmd == "status":
        target_session_id = getattr(args, "session", None)
        session = None

        if target_session_id:
            session = pairing_mgr.get_session(target_session_id)
        else:
            sessions = pairing_mgr.list_sessions(parent_id=active_identity.id)
            if sessions:
                session = sessions[0]

        if not session:
            print("No active pairing session found.")
            return 0

        print("GuardianMesh Pairing")
        print_divider()
        print(f"{'Session:':<16} {session.session_id}")
        print(f"{'State:':<16} {session.state.value}")
        print(f"{'Parent:':<16} {session.parent_identity_id}")
        print(f"{'Child:':<16} {session.child_identity_id or 'PENDING'}")

        ver_status = "VERIFIED" if session.verified_at else "PENDING"
        print(f"{'Verification:':<16} {ver_status}")

        auth_status = (
            "AUTHORIZED"
            if session.authorized_at
            else ("WAITING" if session.state == PairingState.CHILD_AUTHORIZATION_PENDING else "NOT STARTED")
        )
        print(f"{'Authorization:':<16} {auth_status}")

        remaining = session.seconds_remaining()
        mins, secs = divmod(remaining, 60)
        print(f"{'Expires:':<16} {mins:02d}:{secs:02d}")
        return 0

    elif subcmd == "list":
        devices = trust_mgr.list_trusted_devices()
        if not devices:
            print("No trusted devices paired yet.")
            return 0

        print("Trusted Devices")
        print_divider(width=72)
        print(f"{'DEVICE':<16} {'ROLE':<8} {'STATUS':<10} {'LABEL':<18} {'FINGERPRINT'}")
        print_divider(width=72)
        for dev in devices:
            lbl = dev.label or "-"
            fp = f"{dev.remote_public_key_fingerprint[:18]}..."
            print(f"{dev.remote_identity_id:<16} {dev.remote_role.value:<8} {dev.status:<10} {lbl:<18} {fp}")
        return 0

    elif subcmd == "verify":
        session_id = getattr(args, "session_id", None)
        code = getattr(args, "code", None)

        if not session_id or not code:
            print("Usage: guardian pair verify <session_id> <code>")
            return 1

        try:
            session = pairing_mgr.verify_otp(session_id, code)
            print("Verification Successful")
            print_divider()
            print(f"{'Session ID':<16} {session.session_id}")
            print(f"{'State':<16} {session.state.value}")
            print("\nOTP verified. Waiting for explicit child device authorization.")
            auth_hint = f"guardian pair authorize {session.session_id} --child-id <id>"
            print(f"To authorize via test adapter: {auth_hint}")
            return 0
        except GuardianMeshError as e:
            print(f"Verification failed: {e}")
            return 1

    elif subcmd == "authorize":
        session_id = getattr(args, "session_id", None)
        child_id = getattr(args, "child_id", None)
        deny = getattr(args, "deny", False)
        label = getattr(args, "label", "Child Phone")

        if not session_id:
            print("Usage: guardian pair authorize <session_id> [--approve | --deny] [--child-id ID]")
            return 1

        if not child_id:
            all_idents = identity_mgr.list_identities()
            child_idents = [i for i in all_idents if i.role == IdentityRole.CHILD]
            if not child_idents:
                child_ident, _ = identity_mgr.create_identity(
                    role=IdentityRole.CHILD, label="Test Child Device", set_active=False
                )
                child_id = child_ident.id
            else:
                child_id = child_idents[0].id

        try:
            nonce = pairing_mgr.create_authorization_challenge(session_id, child_id)
            adapter = LocalTestAuthorizationAdapter(key_storage, auto_approve=not deny)
            decision = adapter.request_authorization(
                session_id=session_id,
                parent_identity_id=active_identity.id,
                parent_public_key_fingerprint=active_identity.public_key_fingerprint,
                child_identity_id=child_id,
                nonce=nonce,
            )
            device = pairing_mgr.submit_child_authorization(session_id, decision, label=label)
            print("Pairing Complete — Trust Established")
            print_divider()
            print(f"{'Device ID':<16} {device.remote_identity_id}")
            print(f"{'Role':<16} {device.remote_role.value}")
            print(f"{'Fingerprint':<16} {device.remote_public_key_fingerprint}")
            print(f"{'Status':<16} {device.status}")
            print(f"{'Trust Version':<16} {device.trust_version}")
            return 0
        except ChildAuthorizationDeniedError:
            print("Child Authorization: DENIED")
            print("Pairing rejected by child device. No trust relationship established.")
            return 1
        except GuardianMeshError as e:
            print(f"Authorization error: {e}")
            return 1

    elif subcmd == "revoke":
        device_id = getattr(args, "device_id", None)
        if not device_id:
            print("Usage: guardian pair revoke <device_id>")
            return 1

        try:
            trust_mgr.revoke_trust(
                local_identity_id=active_identity.id,
                remote_identity_id=device_id,
                actor_id=active_identity.id,
            )
            print(f"Device {device_id}")
            print_divider()
            print("Trust status: REVOKED")
            return 0
        except GuardianMeshError as e:
            print(f"Revocation error: {e}")
            return 1

    elif subcmd == "cancel":
        session_id = getattr(args, "session_id", None)
        if not session_id:
            print("Usage: guardian pair cancel <session_id>")
            return 1

        try:
            pairing_mgr.cancel_session(session_id)
            print(f"Pairing session '{session_id}' CANCELLED.")
            return 0
        except GuardianMeshError as e:
            print(f"Cancellation error: {e}")
            return 1

    elif subcmd == "rename":
        device_id = getattr(args, "device_id", None)
        new_label = getattr(args, "label", None)
        if not device_id or not new_label:
            print("Usage: guardian pair rename <device_id> <new_label>")
            return 1

        try:
            trust_mgr.rename_trusted_device(active_identity.id, device_id, new_label)
            print(f"Renamed device '{device_id}' to '{new_label}'.")
            return 0
        except GuardianMeshError as e:
            print(f"Rename error: {e}")
            return 1

    return 0


def cmd_telemetry(args: argparse.Namespace, config: GuardianConfig) -> int:
    """Manage privacy-bounded device health telemetry (Phase 3: Pulse)."""
    subcmd = getattr(args, "telemetry_action", None)

    if not config.database_path.is_file():
        print("Database not initialized. Run 'guardian init' first.")
        return 1

    db = Database(config.database_path)
    key_storage = KeyStorageManager(config.keys_dir)
    identity_mgr = IdentityManager(db, key_storage)
    active_identity = identity_mgr.get_active_identity()

    if not active_identity:
        print("No active identity found. Run 'guardian init' first.")
        return 1

    trust_mgr = TrustManager(db)
    seq_mgr = SequenceManager(db)
    processor = TelemetryProcessor(db, config, trust_mgr, seq_mgr)

    if not subcmd or subcmd == "overview":
        print(f"GuardianMesh {__phase__} Telemetry")
        print_divider()
        devices = trust_mgr.list_trusted_devices(status="ACTIVE")
        if not devices:
            print("No active trusted devices found. Run 'guardian pair' to pair with a child device.")
            return 0

        print(f"{'DEVICE':<16} {'HEALTH':<10} {'BATTERY':<16} {'STORAGE':<14} {'UPTIME'}")
        print_divider(width=72)
        for dev in devices:
            summary = processor.get_device_health(dev.remote_identity_id)
            health = summary.health_state.value if summary else "UNKNOWN"
            if summary and summary.battery_percent is not None:
                bat = f"{summary.battery_percent}%"
            else:
                bat = "Unknown"
            if summary and summary.is_charging:
                bat += " (Chg)"
            if summary and summary.storage_free_gb is not None:
                stor = f"{summary.storage_free_gb} GB free"
            else:
                stor = "Unknown"
            upt = summary.uptime_display if summary else "Unknown"
            print(f"{dev.remote_identity_id:<16} {health:<10} {bat:<16} {stor:<14} {upt}")
        return 0

    elif subcmd == "status":
        device_id = getattr(args, "device_id", None)
        if not device_id:
            devices = trust_mgr.list_trusted_devices(status="ACTIVE")
            if devices:
                device_id = devices[0].remote_identity_id
            else:
                print("Error: Device ID required (e.g. guardian telemetry status GM-C-XXXXXXXX).")
                return 1

        summary = processor.get_device_health(device_id)
        if not summary:
            is_tr = trust_mgr.is_trusted(active_identity.id, device_id)
            if not is_tr:
                print(f"Device '{device_id}' is not an active trusted device.")
                return 1
            print(f"No telemetry received yet for device {device_id}.")
            print("Run 'guardian telemetry refresh' to collect a sample.")
            return 0

        print("GuardianMesh Pulse")
        print_divider()
        print(f"{'Device:':<16} {summary.device_id}")
        print(f"{'Health:':<16} {summary.health_state.value}")

        bat_str = f"{summary.battery_percent}%" if summary.battery_percent is not None else "Unknown"
        if summary.is_charging is True:
            bat_str += " / Charging"
        elif summary.is_charging is False:
            bat_str += " / Discharging"
        print(f"{'Battery:':<16} {bat_str}")

        stor_str = f"{summary.storage_free_gb} GB free" if summary.storage_free_gb is not None else "Unknown"
        print(f"{'Storage:':<16} {stor_str}")
        print(f"{'Uptime:':<16} {summary.uptime_display}")
        print(f"{'Connectivity:':<16} {summary.connectivity.value}")

        if summary.last_seen_seconds_ago is not None:
            print(f"{'Last heartbeat:':<16} {summary.last_seen_seconds_ago} seconds ago")
        else:
            print(f"{'Last heartbeat:':<16} {summary.last_heartbeat_at}")

        if summary.is_paused:
            print(f"{'Collection:':<16} PAUSED")
        return 0

    elif subcmd == "history":
        device_id = getattr(args, "device_id", None)
        today_only = getattr(args, "today", False)
        limit = getattr(args, "limit", 20) or 20

        if not device_id:
            devices = trust_mgr.list_trusted_devices(status="ACTIVE")
            if devices:
                device_id = devices[0].remote_identity_id
            else:
                print("Error: Device ID required.")
                return 1

        since_utc = None
        if today_only:
            today_start = datetime.datetime.now(datetime.UTC).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            since_utc = today_start.isoformat()

        events = processor.get_health_history(device_id, limit=limit, since_utc=since_utc)
        if not events:
            print(f"No telemetry history found for device {device_id}.")
            return 0

        print(f"Device Health History: {device_id}")
        print_divider(width=76)
        print(f"{'TIMESTAMP (UTC)':<20} {'HEALTH':<10} {'BATTERY':<14} {'STORAGE':<14} {'CONN'}")
        print_divider(width=76)

        for ev in events:
            ts = ev["captured_at"][:19].replace("T", " ")
            bat = f"{ev['battery_percent']}%" if ev["battery_percent"] is not None else "-"
            if ev["charging"]:
                bat += " (Chg)"
            if ev["storage_free_bytes"] is not None:
                stor = f"{round(ev['storage_free_bytes'] / (1024**3), 1)} GB"
            else:
                stor = "-"
            print(f"{ts:<20} {ev['health_state']:<10} {bat:<14} {stor:<14} {ev['connectivity']}")
        return 0

    elif subcmd == "refresh":
        device_id = getattr(args, "device_id", None)
        if not device_id:
            devices = trust_mgr.list_trusted_devices(status="ACTIVE")
            if devices:
                device_id = devices[0].remote_identity_id
            else:
                print("Error: Device ID required.")
                return 1

        if not trust_mgr.is_trusted(active_identity.id, device_id):
            print(f"Device '{device_id}' is not an active trusted device.")
            return 1

        collector = DeviceCollector()
        payload = collector.collect_health_data()

        seq = seq_mgr.get_next_outgoing_sequence(device_id)
        envelope = TelemetryEnvelope(
            device_id=device_id,
            sequence=seq,
            payload=payload,
            captured_at=datetime.datetime.now(datetime.UTC).isoformat(),
        )

        try:
            priv_key = key_storage.load_private_key(device_id)
            envelope.sign(priv_key)
        except Exception:
            priv_key = key_storage.load_private_key(active_identity.id)
            envelope.sign(priv_key)

        try:
            summary = processor.process_envelope(envelope, local_identity_id=active_identity.id)
            print("Telemetry Refreshed")
            print_divider()
            print(f"{'Device:':<16} {summary.device_id}")
            print(f"{'Health:':<16} {summary.health_state.value}")
            print(f"{'Battery:':<16} {summary.battery_percent}%")
            print(f"{'Storage:':<16} {summary.storage_free_gb} GB free")
            print(f"{'Uptime:':<16} {summary.uptime_display}")
            print(f"{'Connectivity:':<16} {summary.connectivity.value}")
            return 0
        except GuardianMeshError as e:
            print(f"Refresh failed: {e}")
            return 1

    elif subcmd == "pause":
        device_id = getattr(args, "device_id", None)
        if not device_id:
            print("Usage: guardian telemetry pause <device_id>")
            return 1

        processor.pause_device(device_id)
        print(f"Telemetry collection paused for device {device_id}.")
        return 0

    elif subcmd == "resume":
        device_id = getattr(args, "device_id", None)
        if not device_id:
            print("Usage: guardian telemetry resume <device_id>")
            return 1

        processor.resume_device(device_id)
        print(f"Telemetry collection resumed for device {device_id}.")
        return 0

    return 0


def cmd_policy(args: argparse.Namespace, config: GuardianConfig) -> int:
    """Manage privacy-bounded health surveillance policies (Phase 4: Sentinel)."""
    subcmd = getattr(args, "policy_action", None)
    format_json = getattr(args, "json", False) is True

    if not config.database_path.is_file():
        print("Database not initialized. Run 'guardian init' first.")
        return 1

    db = Database(config.database_path)
    trust_mgr = TrustManager(db)
    engine = PolicyEngine(db, config, trust_mgr)

    if not subcmd or subcmd == "list":
        device_id = getattr(args, "device_id", None)
        policies = engine.list_policies(device_id=device_id)
        if format_json:
            print(json.dumps({"policies": [p.to_dict() for p in policies]}, indent=2))
            return 0

        if not policies:
            print("No policies configured. Policies are automatically generated for paired devices.")
            return 0

        print("Policies")
        print_divider(width=72)
        print(f"{'POLICY ID':<14} {'DEVICE ID':<16} {'STATUS':<10} {'NAME'}")
        print_divider(width=72)
        for p in policies:
            status = "ENABLED" if p.enabled else "DISABLED"
            print(f"{p.id:<14} {p.device_id:<16} {status:<10} {p.name}")
        return 0

    elif subcmd == "show":
        policy_id = getattr(args, "id", None)
        if not policy_id:
            print("Usage: guardian policy show <policy_id>")
            return 1

        policy = engine.get_policy(policy_id)
        if not policy:
            print(f"Policy '{policy_id}' not found.")
            return 1

        if format_json:
            print(json.dumps(policy.to_dict(), indent=2))
            return 0

        print("Policy Details")
        print_divider()
        print(f"{'Policy ID:':<14} {policy.id}")
        print(f"{'Device ID:':<14} {policy.device_id}")
        print(f"{'Name:':<14} {policy.name}")
        print(f"{'Status:':<14} {'ENABLED' if policy.enabled else 'DISABLED'}")
        print(f"{'Created:':<14} {policy.created_at}")
        print("\nConfigured Rules:")
        print_divider(width=72)
        print(f"{'RULE TYPE':<22} {'STATUS':<10} {'SEVERITY':<10} {'THRESHOLD / DURATION'}")
        print_divider(width=72)
        for r in policy.rules:
            r_stat = "ENABLED" if r.enabled else "DISABLED"
            if r.threshold is not None:
                thresh_str = f"<{int(r.threshold)}%"
            elif r.duration_seconds is not None:
                thresh_str = f">{r.duration_seconds}s"
            else:
                thresh_str = "Immediate"
            print(f"{r.rule_type.value:<22} {r_stat:<10} {r.severity.value:<10} {thresh_str}")
        return 0

    elif subcmd == "enable":
        policy_id = getattr(args, "id", None)
        if not policy_id:
            print("Usage: guardian policy enable <policy_id>")
            return 1
        try:
            engine.enable_policy(policy_id)
            print(f"Policy '{policy_id}' ENABLED.")
            return 0
        except GuardianMeshError as e:
            print(f"Error: {e}")
            return 1

    elif subcmd == "disable":
        policy_id = getattr(args, "id", None)
        if not policy_id:
            print("Usage: guardian policy disable <policy_id>")
            return 1
        try:
            engine.disable_policy(policy_id)
            print(f"Policy '{policy_id}' DISABLED.")
            return 0
        except GuardianMeshError as e:
            print(f"Error: {e}")
            return 1

    elif subcmd == "create":
        device_id = getattr(args, "device_id", None)
        name = getattr(args, "name", "Custom Health Policy") or "Custom Health Policy"
        if not device_id:
            print("Usage: guardian policy create --device <device_id> [--name <name>]")
            return 1
        try:
            policy = engine.create_policy(device_id=device_id, name=name)
            print(f"Created policy '{policy.id}' for device '{device_id}'.")
            return 0
        except GuardianMeshError as e:
            print(f"Error: {e}")
            return 1

    elif subcmd == "delete":
        policy_id = getattr(args, "id", None)
        if not policy_id:
            print("Usage: guardian policy delete <policy_id>")
            return 1
        try:
            engine.delete_policy(policy_id)
            print(f"Policy '{policy_id}' DELETED.")
            return 0
        except GuardianMeshError as e:
            print(f"Error: {e}")
            return 1

    return 0


def cmd_alerts(args: argparse.Namespace, config: GuardianConfig) -> int:
    """Manage health alerts and incident resolution (Phase 4: Sentinel)."""
    subcmd = getattr(args, "alert_action", None)
    format_json = getattr(args, "json", False) is True

    if not config.database_path.is_file():
        print("Database not initialized. Run 'guardian init' first.")
        return 1

    db = Database(config.database_path)
    alert_mgr = AlertManager(db, config)

    if not subcmd or subcmd == "active":
        device_id = getattr(args, "device_id", None)
        severity = getattr(args, "severity", None)
        active_alerts = alert_mgr.get_active_alerts(device_id=device_id, severity=severity)

        if format_json:
            print(json.dumps({"active_alerts": [a.to_dict() for a in active_alerts]}, indent=2))
            return 0

        print("GuardianMesh Sentinel")
        print_divider()
        if not active_alerts:
            print("No active alerts. All monitored devices are healthy.")
            return 0

        print(f"Active Alerts: {len(active_alerts)}\n")
        for alt in active_alerts:
            print(f"! {alt.device_id}")
            print(f"  {alt.message}")
            if alt.trigger_value:
                print(f"  Value:    {alt.trigger_value}")
            print(f"  Severity: {alt.severity.value}")
            print(f"  Alert ID: {alt.id}")
            print(f"  Recorded: {alt.created_at[:19].replace('T', ' ')}\n")
        return 0

    elif subcmd == "list":
        device_id = getattr(args, "device_id", None)
        severity = getattr(args, "severity", None)
        status = getattr(args, "status", None)
        today = getattr(args, "today", False)
        limit = getattr(args, "limit", 20) or 20

        alerts = alert_mgr.list_alerts(
            device_id=device_id,
            severity=severity,
            status=status,
            today=today,
            limit=limit,
        )

        if format_json:
            print(json.dumps({"alerts": [a.to_dict() for a in alerts]}, indent=2))
            return 0

        if not alerts:
            print("No alerts found.")
            return 0

        print("Alerts History")
        print_divider(width=76)
        print(f"{'ALERT ID':<12} {'DEVICE':<15} {'SEVERITY':<10} {'STATUS':<14} {'MESSAGE'}")
        print_divider(width=76)
        for a in alerts:
            msg = a.message[:28] + "..." if len(a.message) > 28 else a.message
            print(f"{a.id:<12} {a.device_id:<15} {a.severity.value:<10} {a.status.value:<14} {msg}")
        return 0

    elif subcmd == "show":
        alert_id = getattr(args, "id", None)
        if not alert_id:
            print("Usage: guardian alerts show <alert_id>")
            return 1

        alert = alert_mgr.get_alert(alert_id)
        if not alert:
            print(f"Alert '{alert_id}' not found.")
            return 1

        if format_json:
            print(json.dumps(alert.to_dict(), indent=2))
            return 0

        print("Alert Details")
        print_divider()
        print(f"{'Alert ID:':<16} {alert.id}")
        print(f"{'Device ID:':<16} {alert.device_id}")
        print(f"{'Policy ID:':<16} {alert.policy_id}")
        print(f"{'Rule:':<16} {alert.rule_type.value}")
        print(f"{'Severity:':<16} {alert.severity.value}")
        print(f"{'Status:':<16} {alert.status.value}")
        print(f"{'Message:':<16} {alert.message}")
        if alert.trigger_value:
            print(f"{'Trigger Value:':<16} {alert.trigger_value}")
        print(f"{'Created:':<16} {alert.created_at}")
        if alert.acknowledged_at:
            print(f"{'Acknowledged:':<16} {alert.acknowledged_at}")
        if alert.resolved_at:
            print(f"{'Resolved:':<16} {alert.resolved_at}")
        if alert.dismissed_at:
            print(f"{'Dismissed:':<16} {alert.dismissed_at}")
        return 0

    elif subcmd == "acknowledge":
        alert_id = getattr(args, "id", None)
        if not alert_id:
            print("Usage: guardian alerts acknowledge <alert_id>")
            return 1
        try:
            alert_mgr.acknowledge_alert(alert_id)
            print(f"Alert '{alert_id}' ACKNOWLEDGED.")
            return 0
        except GuardianMeshError as e:
            print(f"Error: {e}")
            return 1

    elif subcmd == "dismiss":
        alert_id = getattr(args, "id", None)
        if not alert_id:
            print("Usage: guardian alerts dismiss <alert_id>")
            return 1
        try:
            alert_mgr.dismiss_alert(alert_id)
            print(f"Alert '{alert_id}' DISMISSED.")
            return 0
        except GuardianMeshError as e:
            print(f"Error: {e}")
            return 1

    elif subcmd == "resolve":
        alert_id = getattr(args, "id", None)
        if not alert_id:
            print("Usage: guardian alerts resolve <alert_id>")
            return 1
        try:
            alert_mgr.resolve_alert(alert_id)
            print(f"Alert '{alert_id}' RESOLVED.")
            return 0
        except GuardianMeshError as e:
            print(f"Error: {e}")
            return 1

    return 0


def cmd_devices(args: argparse.Namespace, config: GuardianConfig) -> int:
    """Unified device management for trusted child devices (Phase 5: Console)."""
    subcmd = getattr(args, "device_action", None)
    format_json = getattr(args, "json", False) is True

    if not config.database_path.is_file():
        print("Database not initialized. Run 'guardian init' first.")
        return 1

    db = Database(config.database_path)
    service = ConsoleService(db, config)
    renderer = ConsoleRenderer(TerminalFormatter(color_enabled=config.console_color_enabled))

    # Default / list
    if not subcmd or subcmd == "list":
        devs = service.list_devices_summary()
        output = renderer.render_device_list(devs, format_json=format_json)
        print(output)
        return 0

    # Show single device
    elif subcmd == "show":
        device_id = getattr(args, "device_id", None)
        if not device_id:
            print("Usage: guardian devices show <device_id>")
            return 1

        try:
            detail = service.get_device_detail(device_id)
            output = renderer.render_device_detail(detail, format_json=format_json)
            print(output)
            return 0
        except GuardianMeshError as e:
            print(f"Error: {e}")
            return 1

    # Health view
    elif subcmd == "health":
        device_id = getattr(args, "device_id", None)
        if not device_id:
            print("Usage: guardian devices health <device_id>")
            return 1

        health = service.get_device_health(device_id)
        output = renderer.render_device_health(health, format_json=format_json)
        print(output)
        return 0

    # Rename
    elif subcmd == "rename":
        device_id = getattr(args, "device_id", None)
        new_label = getattr(args, "label", None)
        if not device_id or not new_label:
            print("Usage: guardian devices rename <device_id> <label>")
            return 1

        try:
            service.rename_device(device_id, new_label)
            print(f"Renamed device '{device_id}' to '{new_label}'.")
            return 0
        except GuardianMeshError as e:
            print(f"Error: {e}")
            return 1

    # Revoke
    elif subcmd == "revoke":
        device_id = getattr(args, "device_id", None)
        if not device_id:
            print("Usage: guardian devices revoke <device_id>")
            return 1

        try:
            service.revoke_device(device_id)
            print(f"Device {device_id}")
            print_divider()
            print("Trust status: REVOKED")
            return 0
        except GuardianMeshError as e:
            print(f"Error: {e}")
            return 1

    return 0


def cmd_console(args: argparse.Namespace, config: GuardianConfig) -> int:
    """Parent management console and unified dashboard (Phase 5: Console)."""
    subcmd = getattr(args, "console_action", None)
    format_json = getattr(args, "json", False) is True
    non_interactive = getattr(args, "non_interactive", False)
    watch_mode = getattr(args, "watch", False)
    refresh_interval = getattr(args, "refresh_interval", None)
    no_color = getattr(args, "no_color", False)

    if no_color:
        config.console_color_enabled = False

    if not config.database_path.is_file():
        print("Database not initialized. Run 'guardian init' first.")
        return 1

    db = Database(config.database_path)
    service = ConsoleService(db, config)
    formatter = TerminalFormatter(
        color_enabled=config.console_color_enabled,
        ascii_borders=config.console_ascii_borders,
    )
    renderer = ConsoleRenderer(formatter)
    controller = DashboardController(service, renderer, config)

    # 1. Watch mode
    if watch_mode:
        controller.watch(interval_seconds=refresh_interval, format_json=format_json)
        return 0

    # 2. Subcommands
    if subcmd == "dashboard" or (subcmd is None and non_interactive):
        output = controller.render(format_json=format_json)
        print(output)
        return 0

    elif subcmd == "devices":
        devs = service.list_devices_summary()
        print(renderer.render_device_list(devs, format_json=format_json))
        return 0

    elif subcmd == "alerts":
        alts = service.alert_mgr.get_active_alerts()
        print(renderer.render_alerts(alts, format_json=format_json))
        return 0

    elif subcmd == "policies":
        pols = service.policy_engine.list_policies()
        print(renderer.render_policies(pols, format_json=format_json))
        return 0

    elif subcmd == "pairing":
        pair_devices = service.trust_mgr.list_trusted_devices()
        if format_json:
            print(json.dumps({"pairing": [d.to_dict() for d in pair_devices]}, indent=2))
            return 0
        print("GuardianMesh Pairing Overview")
        print_divider()
        print(f"Trusted Devices: {len(pair_devices)}")
        for d in pair_devices:
            print(f"  • {d.remote_identity_id} ({d.label or 'Device'}) - {d.status}")
        return 0

    elif subcmd == "audit":
        limit = getattr(args, "limit", 10) or 10
        events = service.get_recent_activity(limit=limit)
        print(renderer.render_audit(events, format_json=format_json))
        return 0

    elif subcmd == "status":
        statuses = service.get_subsystem_statuses()
        print(renderer.render_status(statuses, format_json=format_json))
        return 0

    # 3. Interactive menu navigation (default when no subcmd and not non-interactive in TTY)
    if not format_json and sys.stdout.isatty():
        navigator = ConsoleNavigator(service, renderer)
        return navigator.run_interactive_menu()
    else:
        output = controller.render(format_json=format_json)
        print(output)
        return 0


def cmd_audit(args: argparse.Namespace, config: GuardianConfig) -> int:
    """View sanitized local audit trail records."""
    format_json = getattr(args, "json", False) is True

    if not config.database_path.is_file():
        print("Database not initialized. No audit records available.")
        return 0

    db = Database(config.database_path)
    audit_logger = AuditLogger(db)
    limit = getattr(args, "limit", 20) or 20
    event_type = getattr(args, "type", None)

    events = audit_logger.get_recent(limit=limit, event_type=event_type)

    if format_json:
        print(json.dumps({"audit_events": events}, indent=2))
        return 0

    if not events:
        print("No audit events found.")
        return 0

    print("GuardianMesh Audit Trail")
    print_divider(width=72)
    print(f"{'TIMESTAMP (UTC)':<22} {'EVENT TYPE':<28} {'ACTOR':<14} {'STATUS'}")
    print_divider(width=72)

    for event in events:
        status = "OK" if event["success"] else "FAILED"
        actor = event["actor_id"] or "-"
        ts = event["timestamp"][:19].replace("T", " ")
        print(f"{ts:<22} {event['event_type']:<28} {actor:<14} {status}")

    return 0


def cmd_config(args: argparse.Namespace, config: GuardianConfig) -> int:
    """Inspect or update GuardianMesh configuration."""
    subcmd = getattr(args, "config_action", None) or "show"
    format_json = getattr(args, "json", False) is True

    if subcmd == "show":
        if format_json:
            print(json.dumps(config.to_dict(redact_secrets=True), indent=2))
            return 0

        print("GuardianMesh Configuration")
        print_divider()
        for k, v in config.to_dict(redact_secrets=True).items():
            print(f"{k:<36} {v}")
        return 0

    return 0


def cmd_transport(args: argparse.Namespace, config: GuardianConfig) -> int:
    """Manage secure transport, sessions, and multi-device channels."""
    subcmd = getattr(args, "transport_action", None) or "status"
    format_json = getattr(args, "json", False) is True

    db = Database(config.database_path)
    if not config.database_path.is_file():
        if format_json:
            print(json.dumps({"error": "Database not initialized. Run 'guardian init' first."}, indent=2))
        else:
            print("Error: Database not initialized. Run 'guardian init' first.", file=sys.stderr)
        return 1

    key_storage = KeyStorageManager(config.keys_dir)
    identity_mgr = IdentityManager(db, key_storage)
    trust_mgr = TrustManager(db)
    registry = TransportRegistry(db)
    reconnect_mgr = ReconnectManager(
        initial_delay_seconds=config.transport_reconnect_initial_delay_seconds,
        max_delay_seconds=config.transport_reconnect_max_delay_seconds,
        max_retries=config.transport_max_reconnect_attempts,
    )
    renderer = ConsoleRenderer(
        TerminalFormatter(
            color_enabled=config.console_color_enabled and not getattr(args, "no_color", False)
        )
    )

    if subcmd == "status":
        active_parent = identity_mgr.get_active_identity()
        trusted_devs = trust_mgr.list_trusted_devices(status="ACTIVE")
        all_peers = registry.list_peers()
        connected_p = [p for p in all_peers if p.connection_state == ConnectionState.CONNECTED]
        active_sessions = registry.list_sessions(state="CONNECTED")

        status_data = {
            "status": "READY" if config.transport_enabled else "DISABLED",
            "transport_enabled": config.transport_enabled,
            "listen_host": config.transport_listen_host,
            "listen_port": config.transport_listen_port,
            "active_sessions": len(active_sessions),
            "total_peers": len(trusted_devs),
            "connected_peers": len(connected_p),
            "mode": "LOCAL",
            "active_identity": active_parent.id if active_parent else None,
        }
        print(renderer.render_transport_status(status_data, format_json=format_json))
        return 0

    elif subcmd == "peers":
        trusted_devs = trust_mgr.list_trusted_devices()
        registered_peers = {p.device_id: p for p in registry.list_peers()}
        combined_peers: list[dict[str, Any]] = []

        for d in trusted_devs:
            dev_id = d.remote_identity_id
            role_str = (
                d.remote_role.value if hasattr(d.remote_role, "value") else str(d.remote_role)
            )
            if dev_id in registered_peers:
                p = registered_peers[dev_id]
                combined_peers.append(
                    {
                        "device_id": dev_id,
                        "label": d.label or "Child Device",
                        "role": role_str,
                        "connection_state": p.connection_state.value,
                        "active_session_id": p.active_session_id,
                        "last_seen_at": p.last_seen_at or d.last_verified_at,
                        "last_sync_at": p.last_sync_at,
                        "reconnect_count": p.reconnect_count,
                        "transport_type": p.transport_type.value,
                    }
                )
            else:
                combined_peers.append(
                    {
                        "device_id": dev_id,
                        "label": d.label or "Child Device",
                        "role": role_str,
                        "connection_state": "DISCONNECTED",
                        "active_session_id": None,
                        "last_seen_at": d.last_verified_at,
                        "last_sync_at": None,
                        "reconnect_count": 0,
                        "transport_type": "LOCAL",
                    }
                )

        print(renderer.render_peers(combined_peers, format_json=format_json))
        return 0

    elif subcmd == "sessions":
        dev_filter = getattr(args, "device_id", None)
        sessions = registry.list_sessions(device_id=dev_filter)
        sess_dicts = [s.to_dict() for s in sessions]
        print(renderer.render_sessions(sess_dicts, format_json=format_json))
        return 0

    elif subcmd == "connect":
        target_id = getattr(args, "device_id", None)
        if not target_id:
            if format_json:
                print(json.dumps({"error": "Device ID is required for connect."}, indent=2))
            else:
                print("Error: Device ID is required.", file=sys.stderr)
            return 1

        active_id = identity_mgr.get_active_identity()
        if not active_id:
            if format_json:
                err_dict = {"error": "No active identity configured. Run 'guardian init' first."}
                print(json.dumps(err_dict, indent=2))
            else:
                print("Error: No active identity configured. Run 'guardian init' first.", file=sys.stderr)
            return 1

        try:
            trusted_dev = trust_mgr.verify_device_trust_or_raise(
                local_identity_id=active_id.id,
                remote_identity_id=target_id,
            )
            if trusted_dev.status == "REVOKED":
                raise TrustRevokedError(f"Trust with '{target_id}' has been revoked.")
        except Exception as e:
            if format_json:
                print(json.dumps({"error": str(e)}, indent=2))
            else:
                print(f"Error: {e}", file=sys.stderr)
            return 1

        priv_key = key_storage.load_private_key(active_id.id)
        if not priv_key:
            if format_json:
                err_dict = {"error": f"Private key not found for identity '{active_id.id}'."}
                print(json.dumps(err_dict, indent=2))
            else:
                print(f"Error: Private key not found for identity '{active_id.id}'.", file=sys.stderr)
            return 1

        target_priv = key_storage.load_private_key(target_id) or priv_key

        client = MemoryTransportClient(
            db=db,
            local_identity_id=active_id.id,
            local_private_key=priv_key,
            trust_manager=trust_mgr,
            registry=registry,
            audit_logger=AuditLogger(db),
            reconnect_manager=reconnect_mgr,
        )
        server = MemoryTransportServer(
            db=db,
            local_identity_id=target_id,
            local_private_key=target_priv,
            trust_manager=trust_mgr,
            registry=registry,
            audit_logger=AuditLogger(db),
        )
        client.attach_server(server)

        try:
            session = client.connect(target_id)
        except Exception as e:
            if format_json:
                print(json.dumps({"error": f"Connection handshake failed: {e}"}, indent=2))
            else:
                print(f"Error: Connection handshake failed: {e}", file=sys.stderr)
            return 1

        if format_json:
            print(
                json.dumps(
                    {
                        "status": "CONNECTED",
                        "device_id": target_id,
                        "session_id": session.session_id,
                        "transport_type": session.transport_type.value,
                        "expires_at": session.expires_at,
                    },
                    indent=2,
                )
            )
        else:
            print(f"Connected to device '{target_id}'.")
            print(f"Session ID:      {session.session_id}")
            print(f"Transport:       {session.transport_type.value}")
            print("State:           CONNECTED")
        return 0

    elif subcmd == "disconnect":
        target_id = getattr(args, "device_id", None)
        if not target_id:
            if format_json:
                print(json.dumps({"error": "Device ID is required for disconnect."}, indent=2))
            else:
                print("Error: Device ID is required.", file=sys.stderr)
            return 1

        active_id = identity_mgr.get_active_identity()
        local_id = active_id.id if active_id else ""

        active_session = registry.get_active_session_for_peer(local_id, target_id)
        if active_session:
            registry.update_session_state(active_session.session_id, ConnectionState.DISCONNECTED)
        registry.update_peer_state(target_id, ConnectionState.DISCONNECTED)

        audit_logger = AuditLogger(db)
        audit_logger.record(
            event_type=AuditEventType.TRANSPORT_DISCONNECTED,
            details={
                "device_id": target_id,
                "session_id": active_session.session_id if active_session else None,
            },
            actor_id=local_id,
            success=True,
        )

        if format_json:
            print(json.dumps({"status": "DISCONNECTED", "device_id": target_id}, indent=2))
        else:
            print(f"Disconnected from device '{target_id}'.")
        return 0

    elif subcmd == "reconnect":
        target_id = getattr(args, "device_id", None)
        if not target_id:
            if format_json:
                print(json.dumps({"error": "Device ID is required for reconnect."}, indent=2))
            else:
                print("Error: Device ID is required.", file=sys.stderr)
            return 1

        active_id = identity_mgr.get_active_identity()
        if not active_id:
            if format_json:
                print(json.dumps({"error": "No active identity configured."}, indent=2))
            else:
                print("Error: No active identity configured.", file=sys.stderr)
            return 1

        try:
            trusted_dev = trust_mgr.verify_device_trust_or_raise(
                local_identity_id=active_id.id,
                remote_identity_id=target_id,
            )
            if trusted_dev.status == "REVOKED":
                raise TrustRevokedError(f"Trust with '{target_id}' has been revoked.")
        except Exception as e:
            if format_json:
                print(json.dumps({"error": str(e)}, indent=2))
            else:
                print(f"Error: {e}", file=sys.stderr)
            return 1

        attempt = reconnect_mgr.record_attempt(target_id)
        if not reconnect_mgr.can_retry(attempt):
            max_r = config.transport_max_reconnect_attempts
            err_msg = f"Max reconnect attempts ({max_r}) exceeded for '{target_id}'."
            if format_json:
                print(json.dumps({"error": err_msg}, indent=2))
            else:
                print(f"Error: {err_msg}", file=sys.stderr)
            return 1

        priv_key = key_storage.load_private_key(active_id.id)
        if not priv_key:
            if format_json:
                err_dict = {"error": f"Private key not found for identity '{active_id.id}'."}
                print(json.dumps(err_dict, indent=2))
            else:
                print("Error: Private key not found.", file=sys.stderr)
            return 1

        target_priv = key_storage.load_private_key(target_id) or priv_key

        client = MemoryTransportClient(
            db=db,
            local_identity_id=active_id.id,
            local_private_key=priv_key,
            trust_manager=trust_mgr,
            registry=registry,
            audit_logger=AuditLogger(db),
            reconnect_manager=reconnect_mgr,
        )
        server = MemoryTransportServer(
            db=db,
            local_identity_id=target_id,
            local_private_key=target_priv,
            trust_manager=trust_mgr,
            registry=registry,
            audit_logger=AuditLogger(db),
        )
        client.attach_server(server)

        try:
            session = client.connect(target_id)
            reconnect_mgr.reset(target_id)
            registry.reset_peer_reconnect(target_id)
        except Exception as e:
            if format_json:
                print(json.dumps({"error": f"Reconnection handshake failed: {e}"}, indent=2))
            else:
                print(f"Error: Reconnection handshake failed: {e}", file=sys.stderr)
            return 1

        if format_json:
            print(
                json.dumps(
                    {
                        "status": "RECONNECTED",
                        "device_id": target_id,
                        "session_id": session.session_id,
                        "attempt": attempt,
                    },
                    indent=2,
                )
            )
        else:
            print(f"Reconnected to device '{target_id}'.")
            print(f"Session ID:      {session.session_id}")
            print("State:           CONNECTED")
        return 0

    return 0
