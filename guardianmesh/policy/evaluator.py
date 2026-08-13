"""Deterministic rule evaluator for device health telemetry (Phase 4: Sentinel)."""

from __future__ import annotations

from guardianmesh.policy.models import AlertSeverity, PolicyRule, RuleType
from guardianmesh.telemetry.models import ConnectivityState, DeviceHealthState, DeviceHealthSummary


class RuleEvaluator:
    """Evaluates privacy-bounded technical health rules against device health snapshots deterministically."""

    @staticmethod
    def evaluate_rule(
        rule: PolicyRule, summary: DeviceHealthSummary
    ) -> tuple[bool, str | None, AlertSeverity | None]:
        """Evaluate a single rule against a device health summary.

        Returns:
            Tuple of (is_triggered, trigger_message, severity).
        """
        if not rule.enabled:
            return False, None, None

        # 1. LOW_BATTERY
        if rule.rule_type == RuleType.LOW_BATTERY:
            if summary.battery_percent is None:
                return False, None, None

            threshold = rule.threshold if rule.threshold is not None else 20.0
            if summary.battery_percent < threshold:
                msg = f"Battery level is low: {summary.battery_percent}% (threshold: <{int(threshold)}%)"
                return True, msg, rule.severity
            return False, None, None

        # 2. LOW_STORAGE
        elif rule.rule_type == RuleType.LOW_STORAGE:
            if (
                summary.storage_free_bytes is None
                or summary.storage_total_bytes is None
                or summary.storage_total_bytes <= 0
            ):
                return False, None, None

            threshold = rule.threshold if rule.threshold is not None else 10.0
            free_pct = (summary.storage_free_bytes / summary.storage_total_bytes) * 100.0

            if free_pct < threshold:
                gb_free = summary.storage_free_gb if summary.storage_free_gb is not None else "Unknown"
                thresh_int = int(threshold)
                pct_str = f"{round(free_pct, 1)}%"
                msg = f"Storage space is low: {pct_str} free ({gb_free} GB, threshold: <{thresh_int}%)"
                return True, msg, rule.severity
            return False, None, None

        # 3. OFFLINE
        elif rule.rule_type == RuleType.OFFLINE:
            if (
                summary.health_state == DeviceHealthState.OFFLINE
                or summary.connectivity == ConnectivityState.OFFLINE
            ):
                msg = "Device is currently OFFLINE"
                return True, msg, rule.severity
            return False, None, None

        # 4. DEGRADED_CONNECTION
        elif rule.rule_type == RuleType.DEGRADED_CONNECTION:
            if (
                summary.health_state == DeviceHealthState.DEGRADED
                or summary.connectivity == ConnectivityState.DEGRADED
            ):
                msg = "Device connection health is DEGRADED"
                return True, msg, rule.severity
            return False, None, None

        # 5. HEARTBEAT_DELAYED
        elif rule.rule_type == RuleType.HEARTBEAT_DELAYED:
            if summary.last_seen_seconds_ago is None:
                return False, None, None

            limit_sec = rule.duration_seconds if rule.duration_seconds is not None else 60
            if summary.last_seen_seconds_ago > limit_sec:
                msg = (
                    f"Device heartbeat delayed: {summary.last_seen_seconds_ago}s elapsed "
                    f"(threshold: >{limit_sec}s)"
                )
                return True, msg, rule.severity
            return False, None, None

        # 6. HEALTH_UNKNOWN
        elif rule.rule_type == RuleType.HEALTH_UNKNOWN:
            if summary.health_state == DeviceHealthState.UNKNOWN:
                msg = "Device health state is UNKNOWN"
                return True, msg, rule.severity
            return False, None, None

        return False, None, None
