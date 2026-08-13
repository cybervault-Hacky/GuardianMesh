"""Main entry point for the GuardianMesh command-line interface."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from guardianmesh import __phase__, __version__
from guardianmesh.cli.commands import (
    cmd_alerts,
    cmd_audit,
    cmd_config,
    cmd_console,
    cmd_devices,
    cmd_doctor,
    cmd_identity,
    cmd_init,
    cmd_pair,
    cmd_policy,
    cmd_status,
    cmd_telemetry,
    cmd_transport,
    cmd_version,
    print_divider,
)
from guardianmesh.core.config import load_config
from guardianmesh.core.errors import GuardianMeshError
from guardianmesh.core.logging import setup_logging


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    desc = f"GuardianMesh (Phase 6: {__phase__}) — Consent-based parental device supervision system."
    parser = argparse.ArgumentParser(
        prog="guardian",
        description=desc,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-v",
        "--version",
        action="store_true",
        help="Show version information and exit.",
    )
    parser.add_argument(
        "--home-dir",
        type=Path,
        default=None,
        help="Override the GuardianMesh home directory.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging output.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color formatting.",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    # version
    subparsers.add_parser("version", help="Display GuardianMesh version and phase.")

    # status
    subparsers.add_parser("status", help="Show the operational status of local components.")

    # doctor
    subparsers.add_parser("doctor", help="Run comprehensive diagnostic and security checks.")

    # init
    p_init = subparsers.add_parser("init", help="Initialize local storage, database, keypair, and identity.")
    p_init.add_argument(
        "--role",
        choices=["parent", "child", "PARENT", "CHILD"],
        default="parent",
        help="Initial identity role (default: parent).",
    )
    p_init.add_argument(
        "--label",
        type=str,
        default=None,
        help="User-friendly label for this device identity.",
    )
    p_init.add_argument(
        "--force",
        action="store_true",
        help="Force reinitialization even if an active identity exists.",
    )

    # console (Phase 5)
    p_con = subparsers.add_parser("console", help="Parent console and unified supervision dashboard.")
    p_con.add_argument("--json", action="store_true", help="Machine-readable JSON output format.")
    p_con.add_argument("--non-interactive", action="store_true", help="Disable interactive navigation menu.")
    p_con.add_argument("--watch", action="store_true", help="Continuously refresh dashboard view.")
    p_con.add_argument(
        "--refresh-interval", type=int, default=None, help="Watch mode refresh interval seconds."
    )
    p_con.add_argument("--no-color", action="store_true", help="Disable color styling.")

    con_sub = p_con.add_subparsers(dest="console_action", metavar="<action>")

    p_con_dash = con_sub.add_parser("dashboard", help="Unified parent supervision dashboard.")
    p_con_dash.add_argument("--json", action="store_true", help="JSON output format.")
    p_con_dash.add_argument("--watch", action="store_true", help="Continuously refresh dashboard.")
    p_con_dash.add_argument("--refresh-interval", type=int, default=None, help="Refresh interval in seconds.")

    p_con_dev = con_sub.add_parser("devices", help="List monitored trusted devices.")
    p_con_dev.add_argument("--json", action="store_true", help="JSON output format.")

    p_con_alt = con_sub.add_parser("alerts", help="Active health alerts summary.")
    p_con_alt.add_argument("--json", action="store_true", help="JSON output format.")

    p_con_pol = con_sub.add_parser("policies", help="Device policies overview.")
    p_con_pol.add_argument("--json", action="store_true", help="JSON output format.")

    p_con_pair = con_sub.add_parser("pairing", help="Pairing sessions and trusted devices summary.")
    p_con_pair.add_argument("--json", action="store_true", help="JSON output format.")

    p_con_aud = con_sub.add_parser("audit", help="Recent system and security audit activity.")
    p_con_aud.add_argument("--json", action="store_true", help="JSON output format.")
    p_con_aud.add_argument("--limit", type=int, default=10, help="Maximum activity entries to show.")

    p_con_stat = con_sub.add_parser("status", help="Subsystem health status.")
    p_con_stat.add_argument("--json", action="store_true", help="JSON output format.")

    # devices (Phase 5)
    p_dev = subparsers.add_parser("devices", help="Manage trusted devices and inspect health.")
    p_dev.add_argument("--json", action="store_true", help="Machine-readable JSON output.")

    dev_sub = p_dev.add_subparsers(dest="device_action", metavar="<action>")

    p_dev_list = dev_sub.add_parser("list", help="List all trusted child devices.")
    p_dev_list.add_argument("--json", action="store_true", help="JSON output format.")

    p_dev_show = dev_sub.add_parser("show", help="Show full device details, policy, and alerts.")
    p_dev_show.add_argument("device_id", type=str, help="Device ID (GM-C-XXXXXXXX).")
    p_dev_show.add_argument("--json", action="store_true", help="JSON output format.")

    p_dev_health = dev_sub.add_parser("health", help="Inspect device health metrics.")
    p_dev_health.add_argument("device_id", type=str, help="Device ID.")
    p_dev_health.add_argument("--json", action="store_true", help="JSON output format.")

    p_dev_rename = dev_sub.add_parser("rename", help="Rename device label.")
    p_dev_rename.add_argument("device_id", type=str, help="Device ID.")
    p_dev_rename.add_argument("label", type=str, help="New device label.")

    p_dev_revoke = dev_sub.add_parser("revoke", help="Revoke device trust relationship.")
    p_dev_revoke.add_argument("device_id", type=str, help="Device ID to revoke.")

    # transport (Phase 6: Nexus)
    p_trans = subparsers.add_parser(
        "transport", help="Manage secure device transport and synchronized channels (Nexus)."
    )
    p_trans.add_argument("--json", action="store_true", help="Machine-readable JSON output.")
    trans_sub = p_trans.add_subparsers(dest="transport_action", metavar="<action>")

    p_trans_stat = trans_sub.add_parser("status", help="Show transport subsystem and channel status.")
    p_trans_stat.add_argument("--json", action="store_true", help="JSON output format.")

    p_trans_peers = trans_sub.add_parser(
        "peers", help="List registered transport peers and connection states."
    )
    p_trans_peers.add_argument("--json", action="store_true", help="JSON output format.")

    p_trans_sess = trans_sub.add_parser(
        "sessions", help="List active and historical transport sessions."
    )
    p_trans_sess.add_argument(
        "--device", dest="device_id", type=str, default=None, help="Filter by device ID."
    )
    p_trans_sess.add_argument("--json", action="store_true", help="JSON output format.")

    p_trans_conn = trans_sub.add_parser(
        "connect", help="Establish secure transport channel with a trusted device."
    )
    p_trans_conn.add_argument(
        "device_id", type=str, help="Target device ID (GM-C-XXXXXXXX or GM-P-XXXXXXXX)."
    )
    p_trans_conn.add_argument("--json", action="store_true", help="JSON output format.")

    p_trans_disc = trans_sub.add_parser(
        "disconnect", help="Terminate active transport channel with a device."
    )
    p_trans_disc.add_argument("device_id", type=str, help="Target device ID.")
    p_trans_disc.add_argument("--json", action="store_true", help="JSON output format.")

    p_trans_reconn = trans_sub.add_parser(
        "reconnect", help="Reconnect transport channel with a trusted device."
    )
    p_trans_reconn.add_argument("device_id", type=str, help="Target device ID.")
    p_trans_reconn.add_argument("--json", action="store_true", help="JSON output format.")

    # identity
    p_ident = subparsers.add_parser("identity", help="Manage cryptographic device identities.")
    ident_sub = p_ident.add_subparsers(dest="identity_action", metavar="<action>")

    ident_sub.add_parser("list", help="List all local identities.")
    ident_show = ident_sub.add_parser("show", help="Show details of active or specified identity.")
    ident_show.add_argument("id", nargs="?", default=None, help="Identity ID to inspect.")

    ident_create = ident_sub.add_parser("create", help="Generate a new cryptographic identity.")
    ident_create.add_argument(
        "--role",
        choices=["parent", "child", "PARENT", "CHILD"],
        default="parent",
        help="Identity role.",
    )
    ident_create.add_argument("--label", type=str, default=None, help="Optional label.")
    ident_create.add_argument(
        "--no-activate",
        dest="activate",
        action="store_false",
        help="Do not set as active identity.",
    )

    ident_activate = ident_sub.add_parser("activate", help="Set active identity.")
    ident_activate.add_argument("id", type=str, help="Identity ID to activate.")

    # pair (Phase 2)
    p_pair = subparsers.add_parser("pair", help="Manage secure parent-child device pairing and trust.")
    p_pair.add_argument(
        "--method",
        choices=["email", "sms", "demo", "EMAIL", "SMS", "DEMO"],
        default=None,
        help="Verification delivery method.",
    )
    p_pair.add_argument(
        "--destination",
        type=str,
        default=None,
        help="Verification destination (email or phone).",
    )
    p_pair.add_argument(
        "--child-id",
        type=str,
        default=None,
        help="Target child identity ID (GM-C-XXXXXXXX).",
    )

    pair_sub = p_pair.add_subparsers(dest="pair_action", metavar="<action>")

    p_pair_status = pair_sub.add_parser("status", help="Show status of active pairing session.")
    p_pair_status.add_argument("--session", type=str, default=None, help="Specific session ID to query.")

    pair_sub.add_parser("list", help="List all trusted devices and their status.")

    p_pair_verify = pair_sub.add_parser("verify", help="Submit OTP verification code.")
    p_pair_verify.add_argument("session_id", type=str, help="Pairing session ID.")
    p_pair_verify.add_argument("code", type=str, help="6-digit verification code.")

    p_pair_auth = pair_sub.add_parser("authorize", help="Submit child-side authorization decision.")
    p_pair_auth.add_argument("session_id", type=str, help="Pairing session ID.")
    p_pair_auth.add_argument("--child-id", type=str, default=None, help="Child identity ID.")
    p_pair_auth.add_argument("--deny", action="store_true", help="Explicitly deny authorization.")
    p_pair_auth.add_argument("--label", type=str, default="Child Device", help="Device label.")

    p_pair_revoke = pair_sub.add_parser("revoke", help="Revoke trust relationship with a device.")
    p_pair_revoke.add_argument("device_id", type=str, help="Remote device ID to revoke.")

    p_pair_cancel = pair_sub.add_parser("cancel", help="Cancel a pending pairing session.")
    p_pair_cancel.add_argument("session_id", type=str, help="Pairing session ID to cancel.")

    p_pair_rename = pair_sub.add_parser("rename", help="Rename a trusted device label.")
    p_pair_rename.add_argument("device_id", type=str, help="Device ID to rename.")
    p_pair_rename.add_argument("label", type=str, help="New device label.")

    # telemetry (Phase 3: Pulse)
    p_tel = subparsers.add_parser("telemetry", help="Manage privacy-bounded device health telemetry (Pulse).")
    tel_sub = p_tel.add_subparsers(dest="telemetry_action", metavar="<action>")

    p_tel_status = tel_sub.add_parser("status", help="Show device health snapshot.")
    p_tel_status.add_argument("device_id", nargs="?", default=None, help="Device ID (GM-C-XXXXXXXX).")

    p_tel_hist = tel_sub.add_parser("history", help="View health telemetry event history.")
    p_tel_hist.add_argument("device_id", nargs="?", default=None, help="Device ID.")
    p_tel_hist.add_argument("--today", action="store_true", help="Filter for today only.")
    p_tel_hist.add_argument("--limit", type=int, default=20, help="Max records to show.")

    p_tel_ref = tel_sub.add_parser("refresh", help="Trigger on-demand health snapshot refresh.")
    p_tel_ref.add_argument("device_id", nargs="?", default=None, help="Device ID.")

    p_tel_pause = tel_sub.add_parser("pause", help="Pause telemetry collection for a device.")
    p_tel_pause.add_argument("device_id", type=str, help="Device ID.")

    p_tel_resume = tel_sub.add_parser("resume", help="Resume telemetry collection for a device.")
    p_tel_resume.add_argument("device_id", type=str, help="Device ID.")

    # policy (Phase 4: Sentinel)
    p_pol = subparsers.add_parser("policy", help="Manage health surveillance policies (Sentinel).")
    p_pol.add_argument("--json", action="store_true", help="JSON output format.")
    pol_sub = p_pol.add_subparsers(dest="policy_action", metavar="<action>")

    p_pol_list = pol_sub.add_parser("list", help="List all policies.")
    p_pol_list.add_argument("--device", dest="device_id", type=str, default=None, help="Filter by device ID.")
    p_pol_list.add_argument("--json", action="store_true", help="JSON output format.")

    p_pol_show = pol_sub.add_parser("show", help="Show policy rules and configuration.")
    p_pol_show.add_argument("id", type=str, help="Policy ID.")
    p_pol_show.add_argument("--json", action="store_true", help="JSON output format.")

    p_pol_enable = pol_sub.add_parser("enable", help="Enable a policy.")
    p_pol_enable.add_argument("id", type=str, help="Policy ID.")

    p_pol_disable = pol_sub.add_parser("disable", help="Disable a policy.")
    p_pol_disable.add_argument("id", type=str, help="Policy ID.")

    p_pol_create = pol_sub.add_parser("create", help="Create a policy for a device.")
    p_pol_create.add_argument("--device", dest="device_id", type=str, required=True, help="Target device ID.")
    p_pol_create.add_argument("--name", type=str, default="Default Health Policy", help="Policy name.")

    p_pol_del = pol_sub.add_parser("delete", help="Delete a policy.")
    p_pol_del.add_argument("id", type=str, help="Policy ID.")

    # alerts (Phase 4: Sentinel)
    p_alt = subparsers.add_parser("alerts", help="View and manage device health alerts (Sentinel).")
    p_alt.add_argument("--json", action="store_true", help="JSON output format.")
    alt_sub = p_alt.add_subparsers(dest="alert_action", metavar="<action>")

    p_alt_active = alt_sub.add_parser("active", help="Show all active alerts.")
    p_alt_active.add_argument(
        "--device", dest="device_id", type=str, default=None, help="Filter by device ID."
    )
    p_alt_active.add_argument("--severity", type=str, default=None, help="Filter by severity.")
    p_alt_active.add_argument("--json", action="store_true", help="JSON output format.")

    p_alt_list = alt_sub.add_parser("list", help="List alerts history.")
    p_alt_list.add_argument("--device", dest="device_id", type=str, default=None, help="Filter by device ID.")
    p_alt_list.add_argument("--severity", type=str, default=None, help="Filter by severity.")
    p_alt_list.add_argument("--status", type=str, default=None, help="Filter by alert status.")
    p_alt_list.add_argument("--today", action="store_true", help="Filter for today only.")
    p_alt_list.add_argument("--limit", type=int, default=20, help="Max records to return.")
    p_alt_list.add_argument("--json", action="store_true", help="JSON output format.")

    p_alt_show = alt_sub.add_parser("show", help="Show details of an alert.")
    p_alt_show.add_argument("id", type=str, help="Alert ID.")
    p_alt_show.add_argument("--json", action="store_true", help="JSON output format.")

    p_alt_ack = alt_sub.add_parser("acknowledge", help="Acknowledge an active alert.")
    p_alt_ack.add_argument("id", type=str, help="Alert ID.")

    p_alt_dis = alt_sub.add_parser("dismiss", help="Dismiss an alert.")
    p_alt_dis.add_argument("id", type=str, help="Alert ID.")

    p_alt_res = alt_sub.add_parser("resolve", help="Resolve an alert.")
    p_alt_res.add_argument("id", type=str, help="Alert ID.")

    # audit
    p_audit = subparsers.add_parser("audit", help="Inspect sanitized local security audit events.")
    p_audit.add_argument("--json", action="store_true", help="JSON output format.")
    audit_sub = p_audit.add_subparsers(dest="audit_action", metavar="<action>")
    audit_list = audit_sub.add_parser("list", help="List recent audit records.")
    audit_list.add_argument("--limit", type=int, default=20, help="Maximum number of events to show.")
    audit_list.add_argument("--type", type=str, default=None, help="Filter by audit event type.")
    audit_list.add_argument("--json", action="store_true", help="JSON output format.")

    # config
    p_cfg = subparsers.add_parser("config", help="View or modify configuration parameters.")
    p_cfg.add_argument("--json", action="store_true", help="JSON output format.")
    cfg_sub = p_cfg.add_subparsers(dest="config_action", metavar="<action>")
    p_cfg_show = cfg_sub.add_parser("show", help="Display all active configuration values.")
    p_cfg_show.add_argument("--json", action="store_true", help="JSON output format.")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # Route subcommands
    try:
        if args.version or args.command == "version":
            return cmd_version(args, None)  # type: ignore

        if args.command is None:
            print(f"GuardianMesh {__version__} ({__phase__})")
            print("Consent-based parental device supervision system.")
            print_divider()
            print("Available Commands:")
            print("  guardian version   Display version and phase information")
            print("  guardian doctor    Run environment, security, and storage diagnostics")
            print("  guardian status    Show current operational component status")
            print("  guardian console   Parent console and unified supervision dashboard")
            print("  guardian devices   Manage trusted devices and health inspections")
            print("  guardian alerts    View and manage device health alerts")
            print("  guardian policy    Manage health surveillance policies")
            print("  guardian pair      Manage secure parent-child device pairing and trust")
            print("  guardian telemetry Inspect privacy-bounded device health telemetry")
            print("  guardian transport Manage secure device transport and synchronized channels")
            print("  guardian identity  Manage cryptographic device identities")
            print("  guardian init      Initialize local repository, database, and identity")
            print("  guardian audit     Inspect sanitized local audit logs")
            print("  guardian config    View active system configuration")
            print("\nRun 'guardian <command> --help' for command-specific options.")
            return 0

        config = load_config(args.home_dir)
        if args.debug:
            config.log_level = "DEBUG"
            setup_logging(level="DEBUG", log_file=config.log_file_path, console_output=True)
        else:
            setup_logging(level=config.log_level, log_file=config.log_file_path, console_output=False)

        if args.command == "status":
            return cmd_status(args, config)
        elif args.command == "doctor":
            return cmd_doctor(args, config)
        elif args.command == "init":
            return cmd_init(args, config)
        elif args.command == "identity":
            if not getattr(args, "identity_action", None):
                args.identity_action = "list"
            return cmd_identity(args, config)
        elif args.command == "pair":
            return cmd_pair(args, config)
        elif args.command == "telemetry":
            return cmd_telemetry(args, config)
        elif args.command == "policy":
            return cmd_policy(args, config)
        elif args.command == "alerts":
            return cmd_alerts(args, config)
        elif args.command == "devices":
            return cmd_devices(args, config)
        elif args.command == "transport":
            if not getattr(args, "transport_action", None):
                args.transport_action = "status"
            return cmd_transport(args, config)
        elif args.command == "console":
            return cmd_console(args, config)
        elif args.command == "audit":
            if not getattr(args, "audit_action", None):
                args.audit_action = "list"
            return cmd_audit(args, config)
        elif args.command == "config":
            if not getattr(args, "config_action", None):
                args.config_action = "show"
            return cmd_config(args, config)
        else:
            parser.print_help()
            return 0
    except GuardianMeshError as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.debug:
            import traceback

            traceback.print_exc()
        return 1
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        return 130
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        if args.debug:
            import traceback

            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
