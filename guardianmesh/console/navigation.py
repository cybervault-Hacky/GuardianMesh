"""Interactive console menu navigation for Terminal and Termux environments."""

from __future__ import annotations

from guardianmesh.console.renderer import ConsoleRenderer
from guardianmesh.console.services import ConsoleService


class ConsoleNavigator:
    """Interactive text menu router for GuardianMesh Console."""

    def __init__(
        self,
        service: ConsoleService,
        renderer: ConsoleRenderer | None = None,
    ) -> None:
        self.service = service
        self.renderer = renderer or ConsoleRenderer()

    def run_interactive_menu(self) -> int:
        """Display interactive navigation menu until user exits."""
        while True:
            print()
            print(self.renderer.fmt.colorize("GuardianMesh Console", "cyan", bold=True))
            print(self.renderer.fmt.rule())
            print("  1. Dashboard Overview")
            print("  2. Monitored Devices")
            print("  3. Sentinel Alerts")
            print("  4. Surveillance Policies")
            print("  5. Pairing Sessions")
            print("  6. Audit History")
            print("  7. System Status")
            print("  8. Exit Console")
            print()

            try:
                choice = input("Select [1-8]: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nExiting console.")
                return 0

            print()
            if choice == "1":
                snap = self.service.get_dashboard_snapshot()
                print(self.renderer.render_dashboard(snap))
            elif choice == "2":
                devs = self.service.list_devices_summary()
                print(self.renderer.render_device_list(devs))
            elif choice == "3":
                alts = self.service.alert_mgr.get_active_alerts()
                print(self.renderer.render_alerts(alts))
            elif choice == "4":
                pols = self.service.policy_engine.list_policies()
                print(self.renderer.render_policies(pols))
            elif choice == "5":
                trusted_list = self.service.trust_mgr.list_trusted_devices()
                print(f"Trusted Devices ({len(trusted_list)} active/total)")
                for d in trusted_list:
                    print(f"  • {d.remote_identity_id} ({d.label or 'Device'}) - {d.status}")
            elif choice == "6":
                events = self.service.get_recent_activity(10)
                print(self.renderer.render_audit(events))
            elif choice == "7":
                statuses = self.service.get_subsystem_statuses()
                print(self.renderer.render_status(statuses))
            elif choice in ("8", "q", "exit", "quit"):
                print("Exiting console.")
                return 0
            else:
                print("Invalid selection. Please choose a valid option (1-8).")
