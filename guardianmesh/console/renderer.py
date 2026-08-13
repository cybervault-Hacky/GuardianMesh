"""Terminal and JSON rendering views for GuardianMesh Console (Phase 5)."""

from __future__ import annotations

import json
from typing import Any

from guardianmesh import __phase__, __version__
from guardianmesh.console.formatters import TerminalFormatter
from guardianmesh.console.models import DashboardSnapshot, DeviceView
from guardianmesh.policy.models import Alert, Policy
from guardianmesh.telemetry.models import DeviceHealthSummary


class ConsoleRenderer:
    """Renders Console models into terminal typography or machine-readable JSON."""

    def __init__(self, formatter: TerminalFormatter | None = None) -> None:
        self.fmt = formatter or TerminalFormatter()

    def render_dashboard(self, snapshot: DashboardSnapshot, format_json: bool = False) -> str:
        """Render the unified parent supervision dashboard."""
        if format_json:
            return json.dumps(snapshot.to_dict(), indent=2)

        lines: list[str] = [
            self.fmt.colorize("GuardianMesh", "cyan", bold=True),
            self.fmt.double_rule(),
            f"Console v{__version__} ({__phase__})\n",
            self.fmt.colorize("DEVICES", "white", bold=True),
            self.fmt.rule(),
            f"Trusted       {snapshot.device_count}",
            f"Online        {self.fmt.colorize(str(snapshot.online_count), 'green')}",
            (
                f"Degraded      {self.fmt.colorize(str(snapshot.degraded_count), 'yellow')}"
                if snapshot.degraded_count > 0
                else "Degraded      0"
            ),
            (
                f"Offline       {self.fmt.colorize(str(snapshot.offline_count), 'red')}\n"
                if snapshot.offline_count > 0
                else "Offline       0\n"
            ),
            self.fmt.colorize("HEALTH", "white", bold=True),
            self.fmt.rule(),
            f"Battery       {snapshot.summary_health.get('battery', 'Unknown')}",
            f"Storage       {snapshot.summary_health.get('storage', 'Unknown')}",
            f"Connectivity  {snapshot.summary_health.get('connectivity', 'Unknown')}\n",
            self.fmt.colorize("ALERTS", "white", bold=True),
            self.fmt.rule(),
            (
                f"Critical      {self.fmt.colorize(str(snapshot.critical_alert_count), 'red')}"
                if snapshot.critical_alert_count > 0
                else "Critical      0"
            ),
            (
                f"Warning       {self.fmt.colorize(str(snapshot.warning_alert_count), 'yellow')}"
                if snapshot.warning_alert_count > 0
                else "Warning       0"
            ),
            f"Active        {snapshot.active_alert_count}\n",
            self.fmt.colorize("RECENT ACTIVITY", "white", bold=True),
            self.fmt.rule(),
        ]

        if not snapshot.recent_activity:
            lines.append("No recent activity recorded.")
        else:
            for act in snapshot.recent_activity:
                time_str = act.get("time", "")
                desc = act.get("description", "")
                lines.append(f"{time_str:<6} {desc}")

        lines.append(self.fmt.rule())
        return "\n".join(lines)

    def render_device_list(self, devices: list[dict[str, Any]], format_json: bool = False) -> str:
        """Render formatted device list table."""
        if format_json:
            return json.dumps({"devices": devices}, indent=2)

        if not devices:
            return "No trusted devices paired yet. Run 'guardian pair' to pair with a child device."

        headers = ["ID", "LABEL", "ROLE", "HEALTH", "TRUST"]
        rows: list[list[str]] = []
        for d in devices:
            st = d["health_state"]
            health_color = "green" if st == "ONLINE" else ("yellow" if st == "DEGRADED" else "red")
            colored_health = self.fmt.colorize(st, health_color) if self.fmt.color_enabled else st
            rows.append(
                [
                    d["device_id"],
                    d.get("label") or "Child Device",
                    d.get("role", "CHILD"),
                    colored_health,
                    d.get("trust_status", "TRUSTED"),
                ]
            )

        title = self.fmt.colorize("GuardianMesh Devices", bold=True)
        table = self.fmt.format_table(headers, rows)
        return f"{title}\n{table}"

    def render_device_detail(self, detail: DeviceView, format_json: bool = False) -> str:
        """Render single device detail card."""
        if format_json:
            return json.dumps(detail.to_dict(), indent=2)

        lines: list[str] = [
            self.fmt.colorize("Device Details", bold=True),
            self.fmt.rule(),
            f"{'ID:':<16} {detail.device_id}",
            f"{'Label:':<16} {detail.label or 'Child Device'}",
            f"{'Role:':<16} {detail.role}",
            f"{'Trust:':<16} {detail.trust_status}",
            f"{'Fingerprint:':<16} {detail.fingerprint}\n",
            self.fmt.colorize("Health Status", bold=True),
            self.fmt.rule(),
        ]

        if detail.health:
            h = detail.health
            bat_str = f"{h.battery_percent}%" if h.battery_percent is not None else "Unknown"
            if h.is_charging:
                bat_str += " (Charging)"
            stor_str = f"{h.storage_free_gb} GB free" if h.storage_free_gb is not None else "Unknown"

            lines.extend(
                [
                    f"{'State:':<16} {h.health_state.value}",
                    f"{'Battery:':<16} {bat_str}",
                    f"{'Storage:':<16} {stor_str}",
                    f"{'Uptime:':<16} {h.uptime_display}",
                    f"{'Connectivity:':<16} {h.connectivity.value}",
                    f"{'Last heartbeat:':<16} {self.fmt.format_relative_time(h.last_heartbeat_at)}",
                ]
            )
        else:
            lines.append("No health telemetry recorded yet.")

        sync_str = (
            self.fmt.format_relative_time(detail.last_sync_at)
            if detail.last_sync_at
            else "Never"
        )
        hb_str = (
            self.fmt.format_relative_time(detail.last_heartbeat_at)
            if detail.last_heartbeat_at
            else "Never"
        )

        # Transport & Secure Channel status
        lines.extend(
            [
                f"\n{self.fmt.colorize('Transport & Channel', bold=True)}",
                self.fmt.rule(),
                f"{'Connection:':<16} {detail.connection_state}",
                f"{'Transport:':<16} {detail.transport_type}",
                f"{'Session:':<16} {detail.active_session_id or 'None'}",
                f"{'Last sync:':<16} {sync_str}",
                f"{'Last heartbeat:':<16} {hb_str}",
                f"{'Reconnects:':<16} {detail.reconnect_count}",
            ]
        )

        if detail.active_alerts:
            lines.append(f"\n{self.fmt.colorize('Active Alerts:', 'yellow', bold=True)}")
            for a in detail.active_alerts:
                lines.append(f"  ! [{a.severity.value}] {a.message}")

        return "\n".join(lines)

    def render_device_health(self, health: DeviceHealthSummary | None, format_json: bool = False) -> str:
        """Render dedicated device health telemetry card."""
        if format_json:
            return json.dumps(health.storage_free_bytes if health else {}, indent=2) if health else "{}"

        if not health:
            return "No health telemetry recorded for this device."

        bat_str = f"{health.battery_percent}%" if health.battery_percent is not None else "Unknown"
        if health.is_charging is True:
            bat_str += " / Charging"
        elif health.is_charging is False:
            bat_str += " / Discharging"

        stor_str = f"{health.storage_free_gb} GB free" if health.storage_free_gb is not None else "Unknown"

        lines = [
            self.fmt.colorize("Device Health", bold=True),
            self.fmt.rule(),
            f"{'Device:':<16} {health.device_id}",
            f"{'Health State:':<16} {health.health_state.value}",
            f"{'Battery:':<16} {bat_str}",
            f"{'Storage Free:':<16} {stor_str}",
            f"{'Uptime:':<16} {health.uptime_display}",
            f"{'Connectivity:':<16} {health.connectivity.value}",
            f"{'Sequence:':<16} {health.last_sequence}",
            f"{'Agent Version:':<16} {health.agent_version}",
            f"{'Last Heartbeat:':<16} {self.fmt.format_relative_time(health.last_heartbeat_at)}",
        ]
        return "\n".join(lines)

    def render_alerts(self, alerts: list[Alert], format_json: bool = False) -> str:
        """Render alerts list view."""
        if format_json:
            return json.dumps({"alerts": [a.to_dict() for a in alerts]}, indent=2)

        if not alerts:
            return "No alerts found."

        headers = ["ALERT ID", "DEVICE", "SEVERITY", "STATUS", "MESSAGE"]
        rows = [
            [
                a.id,
                a.device_id,
                a.severity.value,
                a.status.value,
                a.message[:28] + "..." if len(a.message) > 28 else a.message,
            ]
            for a in alerts
        ]
        title = self.fmt.colorize("Sentinel Alerts", bold=True)
        table = self.fmt.format_table(headers, rows)
        return f"{title}\n{table}"

    def render_policies(self, policies: list[Policy], format_json: bool = False) -> str:
        """Render policy list view."""
        if format_json:
            return json.dumps({"policies": [p.to_dict() for p in policies]}, indent=2)

        if not policies:
            return "No policies configured."

        headers = ["POLICY ID", "DEVICE ID", "STATUS", "RULES", "NAME"]
        rows = [
            [
                p.id,
                p.device_id,
                "ENABLED" if p.enabled else "DISABLED",
                str(len(p.rules)),
                p.name,
            ]
            for p in policies
        ]
        title = self.fmt.colorize("Policies", bold=True)
        table = self.fmt.format_table(headers, rows)
        return f"{title}\n{table}"

    def render_audit(self, events: list[dict[str, Any]], format_json: bool = False) -> str:
        """Render audit activity records."""
        if format_json:
            return json.dumps({"audit_events": events}, indent=2)

        if not events:
            return "No recent activity recorded."

        headers = ["TIME", "EVENT TYPE", "DESCRIPTION"]
        rows = [
            [
                e.get("time", ""),
                e.get("event_type", ""),
                e.get("description", ""),
            ]
            for e in events
        ]
        title = self.fmt.colorize("Recent Activity", bold=True)
        table = self.fmt.format_table(headers, rows)
        return f"{title}\n{table}"

    def render_status(self, statuses: dict[str, str], format_json: bool = False) -> str:
        """Render subsystem health table."""
        if format_json:
            return json.dumps({"subsystems": statuses}, indent=2)

        lines = [
            self.fmt.colorize("GuardianMesh System Status", bold=True),
            self.fmt.rule(),
        ]
        for name, stat in statuses.items():
            color = "green" if stat == "READY" else ("yellow" if stat == "DISABLED" else "red")
            colored_stat = self.fmt.colorize(stat, color) if self.fmt.color_enabled else stat
            lines.append(f"{name:<18} {colored_stat}")
        return "\n".join(lines)

    def render_transport_status(self, data: dict[str, Any], format_json: bool = False) -> str:
        """Render transport subsystem summary."""
        if format_json:
            return json.dumps(data, indent=2)

        lines = [
            self.fmt.colorize("GuardianMesh Transport Status", bold=True),
            self.fmt.rule(),
            f"{'Subsystem:':<18} {data.get('status', 'READY')}",
            f"{'Listen Endpoint:':<18} {data.get('listen_host', '0.0.0.0')}:{data.get('listen_port', 8443)}",
            f"{'Active Sessions:':<18} {data.get('active_sessions', 0)}",
            f"{'Connected Peers:':<18} {data.get('connected_peers', 0)} / {data.get('total_peers', 0)}",
            f"{'Default Mode:':<18} {data.get('mode', 'LOCAL')}",
        ]
        return "\n".join(lines)

    def render_peers(self, peers: list[dict[str, Any]], format_json: bool = False) -> str:
        """Render transport peers table."""
        if format_json:
            return json.dumps({"peers": peers}, indent=2)

        if not peers:
            return "No transport peers registered yet."

        headers = ["DEVICE ID", "ROLE", "STATE", "SESSION", "LAST SEEN", "RECONNECTS"]
        rows = [
            [
                p.get("device_id", ""),
                p.get("role", "CHILD"),
                p.get("connection_state", "DISCONNECTED"),
                p.get("active_session_id") or "None",
                self.fmt.format_relative_time(p.get("last_seen_at")) if p.get("last_seen_at") else "Never",
                str(p.get("reconnect_count", 0)),
            ]
            for p in peers
        ]
        title = self.fmt.colorize("Transport Peers", bold=True)
        table = self.fmt.format_table(headers, rows)
        return f"{title}\n{table}"

    def render_sessions(self, sessions: list[dict[str, Any]], format_json: bool = False) -> str:
        """Render transport sessions table."""
        if format_json:
            return json.dumps({"sessions": sessions}, indent=2)

        if not sessions:
            return "No transport sessions recorded."

        headers = ["SESSION ID", "REMOTE DEVICE", "STATE", "TYPE", "ESTABLISHED", "EXPIRES"]
        rows = []
        for s in sessions:
            est_str = (
                self.fmt.format_relative_time(s.get("established_at"))
                if s.get("established_at")
                else "Pending"
            )
            exp_str = (
                self.fmt.format_relative_time(s.get("expires_at"))
                if s.get("expires_at")
                else "Unknown"
            )
            rows.append(
                [
                    s.get("session_id", ""),
                    s.get("remote_identity_id", ""),
                    s.get("state", "DISCONNECTED"),
                    s.get("transport_type", "LOCAL"),
                    est_str,
                    exp_str,
                ]
            )
        title = self.fmt.colorize("Transport Sessions", bold=True)
        table = self.fmt.format_table(headers, rows)
        return f"{title}\n{table}"
