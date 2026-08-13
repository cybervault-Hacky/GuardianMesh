"""Tests verifying strict privacy boundaries and refusal of surveillance data in Nexus transport."""

from __future__ import annotations

import pytest

from guardianmesh.core.errors import (
    TransportMessageError,
    TransportPayloadError,
)
from guardianmesh.transport.models import (
    MessageType,
    TransportEnvelope,
)

FORBIDDEN_SURVEILLANCE_FIELDS = [
    "messages",
    "sms",
    "contacts",
    "photos",
    "files",
    "browser_history",
    "keyboard_input",
    "keystrokes",
    "clipboard",
    "clipboard_data",
    "microphone",
    "mic_stream",
    "camera",
    "camera_stream",
    "location",
    "location_history",
    "gps",
    "screen",
    "screen_stream",
    "app_usage",
    "notifications",
    "passwords",
    "command",
    "shell",
    "exec",
    "eval",
]


@pytest.mark.parametrize("forbidden_field", FORBIDDEN_SURVEILLANCE_FIELDS)
def test_nexus_strictly_rejects_surveillance_fields(forbidden_field: str) -> None:
    """Prove Nexus message envelopes immediately reject all personal, covert, or surveillance fields."""
    env = TransportEnvelope(
        protocol_version="1.0",
        message_id="MSG-112233445566",
        session_id="SES-112233445566",
        sender_id="GM-P-83A1F72C",
        recipient_id="GM-C-19A84E72",
        message_type=MessageType.TELEMETRY,
        sequence=1,
        payload={forbidden_field: "prohibited_content"},
    )
    with pytest.raises(TransportPayloadError):
        env.validate()


def test_nexus_protocol_rejects_unauthorized_message_types() -> None:
    """Prove Nexus rejects any attempt to define surveillance or remote-control message types."""
    unauthorized_types = [
        "SCREEN_CAPTURE",
        "AUDIO_RECORD",
        "EXECUTE_COMMAND",
        "LOCATION_POLL",
        "READ_SMS",
        "GET_CONTACTS",
        "REMOTE_SHELL",
    ]

    for unauth in unauthorized_types:
        with pytest.raises(TransportMessageError):
            MessageType.from_str(unauth)
