"""Bounded exponential backoff and reconnection rate limiter."""

from __future__ import annotations

import random


class ReconnectManager:
    """Controls connection retries with bounded exponential backoff and jitter."""

    def __init__(
        self,
        initial_delay_seconds: float = 1.0,
        max_delay_seconds: float = 30.0,
        backoff_factor: float = 2.0,
        max_retries: int = 5,
        enable_jitter: bool = False,
    ) -> None:
        self.initial_delay = initial_delay_seconds
        self.max_delay = max_delay_seconds
        self.backoff_factor = backoff_factor
        self.max_retries = max_retries
        self.enable_jitter = enable_jitter
        self._attempts: dict[str, int] = {}

    def get_delay(self, attempt: int) -> float:
        """Calculate retry delay for a given attempt index (1-based)."""
        if attempt <= 0:
            return self.initial_delay

        delay = min(
            self.max_delay,
            self.initial_delay * (self.backoff_factor ** max(0, attempt - 1)),
        )
        if self.enable_jitter:
            delay += random.uniform(0, 0.5 * delay)
        return round(delay, 2)

    def can_retry(self, attempt: int) -> bool:
        """Check if further retry attempts are permitted."""
        return attempt <= self.max_retries

    def record_attempt(self, device_id: str) -> int:
        """Record and return new attempt count for a target device."""
        current = self._attempts.get(device_id, 0) + 1
        self._attempts[device_id] = current
        return current

    def get_attempt_count(self, device_id: str) -> int:
        """Get current attempt count for a target device."""
        return self._attempts.get(device_id, 0)

    def reset(self, device_id: str) -> None:
        """Reset attempt counter upon successful connection establishment."""
        self._attempts.pop(device_id, None)
