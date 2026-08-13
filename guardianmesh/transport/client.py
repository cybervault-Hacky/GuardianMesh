"""Transport client interfaces and concrete local, memory, and network implementations."""

from __future__ import annotations

import abc
import queue
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519

from guardianmesh.core.errors import (
    DeviceNotTrustedError,
    TransportConnectionClosedError,
    TransportError,
    TransportRevokedError,
    TrustRevokedError,
)
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.storage.audit import AuditEventType, AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.transport.crypto import (
    create_session_init,
    derive_session_keys,
    ephemeral_public_to_bytes,
    generate_ephemeral_keypair,
    verify_session_ack,
)
from guardianmesh.transport.framing import read_frame, write_frame
from guardianmesh.transport.models import (
    ConnectionState,
    EncryptedTransportFrame,
    PeerInfo,
    TransportEnvelope,
    TransportType,
)
from guardianmesh.transport.reconnect import ReconnectManager
from guardianmesh.transport.registry import TransportRegistry
from guardianmesh.transport.session import TransportSession


class Transport(abc.ABC):
    """Abstract contract for two-way message transport."""

    @abc.abstractmethod
    def send_envelope(self, envelope: TransportEnvelope) -> bool:
        """Transmit an envelope over the transport channel."""
        raise NotImplementedError

    @abc.abstractmethod
    def receive_envelope(self, timeout: float | None = None) -> TransportEnvelope | None:
        """Receive the next available envelope from the transport channel."""
        raise NotImplementedError

    @abc.abstractmethod
    def close(self) -> None:
        """Terminate the transport connection."""
        raise NotImplementedError


class SecureTransport(Transport):
    """Secure encrypted transport possessing an active authenticated session."""

    @property
    @abc.abstractmethod
    def session(self) -> TransportSession | None:
        """Active session representation."""
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def is_connected(self) -> bool:
        """Whether the secure channel is active and connected."""
        raise NotImplementedError


class TransportClient(abc.ABC):
    """Client contract for establishing transport sessions with remote peers."""

    @abc.abstractmethod
    def connect(self, remote_device_id: str, timeout: float = 10.0) -> TransportSession:
        """Establish an authenticated transport session with a remote device."""
        raise NotImplementedError

    @abc.abstractmethod
    def disconnect(self, remote_device_id: str | None = None) -> None:
        """Terminate transport session."""
        raise NotImplementedError


class MemoryTransportClient(TransportClient, SecureTransport):
    """In-memory secure transport client for local multi-process or testing environments."""

    def __init__(
        self,
        db: Database,
        local_identity_id: str,
        local_private_key: ed25519.Ed25519PrivateKey,
        trust_manager: TrustManager,
        registry: TransportRegistry | None = None,
        audit_logger: AuditLogger | None = None,
        reconnect_manager: ReconnectManager | None = None,
    ) -> None:
        self.db = db
        self.local_identity_id = local_identity_id
        self.local_private_key = local_private_key
        self.trust_manager = trust_manager
        self.registry = registry or TransportRegistry(db)
        self.audit_logger = audit_logger or AuditLogger(db)
        self.reconnect_mgr = reconnect_manager or ReconnectManager()

        self._session: TransportSession | None = None
        self.inbox: queue.Queue[EncryptedTransportFrame] = queue.Queue()
        self.outbox: queue.Queue[EncryptedTransportFrame] = queue.Queue()
        self._target_server: Any = None

    @property
    def session(self) -> TransportSession | None:
        return self._session

    @property
    def is_connected(self) -> bool:
        return bool(self._session and self._session.is_active)

    def attach_server(self, server: Any) -> None:
        """Connect client inboxes and outboxes to a MemoryTransportServer."""
        self._target_server = server

    def connect(self, remote_device_id: str, timeout: float = 10.0) -> TransportSession:
        """Execute mutual Ed25519 authentication and X25519 Diffie-Hellman session key agreement."""
        # 1. Verify Trust Registry
        try:
            trusted_dev = self.trust_manager.verify_device_trust_or_raise(
                local_identity_id=self.local_identity_id,
                remote_identity_id=remote_device_id,
            )
            if trusted_dev.status == "REVOKED":
                raise TrustRevokedError(f"Device '{remote_device_id}' is revoked.")
        except (DeviceNotTrustedError, TrustRevokedError) as e:
            self.audit_logger.record(
                event_type=AuditEventType.TRANSPORT_REVOKED,
                details={"remote_id": remote_device_id, "reason": str(e)},
                actor_id=self.local_identity_id,
                success=False,
            )
            raise TransportRevokedError(f"Cannot connect to untrusted or revoked device: {e}") from e

        if not self._target_server:
            raise TransportError("MemoryTransportClient is not attached to a target server.")

        # 2. Ephemeral Keypair & SESSION_INIT
        eph_priv, eph_pub = generate_ephemeral_keypair()
        init_envelope, client_nonce = create_session_init(
            sender_id=self.local_identity_id,
            recipient_id=remote_device_id,
            sender_private_key=self.local_private_key,
            ephemeral_public_key=eph_pub,
        )

        # 3. Server Handshake Processing
        ack_envelope = self._target_server.handle_handshake_init(init_envelope)

        # 4. Verify Server SESSION_ACK
        server_eph_pub, session_id, server_nonce = verify_session_ack(
            envelope=ack_envelope,
            server_public_key_pem=trusted_dev.remote_public_key_pem,
            expected_client_eph_bytes=ephemeral_public_to_bytes(eph_pub),
            expected_client_nonce=client_nonce,
        )

        # 5. Derive Session Keys (HKDF-SHA256)
        shared_secret = eph_priv.exchange(server_eph_pub)
        salt = f"{client_nonce}:{server_nonce}".encode()
        send_key, recv_key, session_salt = derive_session_keys(
            shared_secret=shared_secret,
            salt=salt,
            is_initiator=True,
        )

        # 6. Construct Active Session
        session = TransportSession(
            session_id=session_id,
            local_identity_id=self.local_identity_id,
            remote_identity_id=remote_device_id,
            send_key=send_key,
            recv_key=recv_key,
            session_salt=session_salt,
            transport_type=TransportType.MEMORY,
            state=ConnectionState.CONNECTED,
            expires_at=ack_envelope.expires_at,
        )

        self._session = session
        self.registry.record_session(session)
        role_str = (
            trusted_dev.remote_role.value
            if hasattr(trusted_dev.remote_role, "value")
            else str(trusted_dev.remote_role)
        )
        self.registry.record_peer(
            PeerInfo(
                device_id=remote_device_id,
                role=role_str,
                connection_state=ConnectionState.CONNECTED,
                active_session_id=session_id,
                transport_type=TransportType.MEMORY,
            )
        )
        self.reconnect_mgr.reset(remote_device_id)

        self.audit_logger.record(
            event_type=AuditEventType.TRANSPORT_SESSION_CREATED,
            details={
                "session_id": session_id,
                "remote_id": remote_device_id,
                "transport_type": "MEMORY",
            },
            actor_id=self.local_identity_id,
            success=True,
        )
        return session

    def send_envelope(self, envelope: TransportEnvelope) -> bool:
        """Encrypt and dispatch envelope to server inbox."""
        if not self._session or not self._session.is_active:
            raise TransportConnectionClosedError("Transport session is not connected.")
        if not self._target_server:
            raise TransportConnectionClosedError("Server connection is not established.")

        frame = self._session.encrypt_envelope(envelope)
        self._target_server.inbox.put(frame)
        return True

    def receive_envelope(self, timeout: float | None = None) -> TransportEnvelope | None:
        """Receive and decrypt next frame from inbox."""
        if not self._session or not self._session.is_active:
            return None
        try:
            frame = self.inbox.get(timeout=timeout)
            return self._session.decrypt_frame(frame)
        except queue.Empty:
            return None

    def disconnect(self, remote_device_id: str | None = None) -> None:
        """Close active session and notify peer."""
        if self._session:
            sid = self._session.session_id
            rid = self._session.remote_identity_id
            self._session.close(reason="Client disconnected")
            self.registry.update_session_state(sid, ConnectionState.DISCONNECTED)
            self.registry.update_peer_state(rid, ConnectionState.DISCONNECTED)
            self.audit_logger.record(
                event_type=AuditEventType.TRANSPORT_DISCONNECTED,
                details={"session_id": sid, "remote_id": rid},
                actor_id=self.local_identity_id,
                success=True,
            )
            self._session = None

    def close(self) -> None:
        self.disconnect()


class LocalSocketTransportClient(TransportClient, SecureTransport):
    """Local UNIX domain socket or TCP loopback transport client for local IPC."""

    def __init__(
        self,
        db: Database,
        local_identity_id: str,
        local_private_key: ed25519.Ed25519PrivateKey,
        trust_manager: TrustManager,
        socket_path: Path | str | None = None,
        host: str = "127.0.0.1",
        port: int = 8443,
        use_unix_socket: bool = False,
        registry: TransportRegistry | None = None,
        audit_logger: AuditLogger | None = None,
        reconnect_manager: ReconnectManager | None = None,
    ) -> None:
        self.db = db
        self.local_identity_id = local_identity_id
        self.local_private_key = local_private_key
        self.trust_manager = trust_manager
        self.socket_path = socket_path
        self.host = host
        self.port = port
        self.use_unix_socket = use_unix_socket
        self.registry = registry or TransportRegistry(db)
        self.audit_logger = audit_logger or AuditLogger(db)
        self.reconnect_mgr = reconnect_manager or ReconnectManager()

        self._session: TransportSession | None = None
        self._sock: socket.socket | None = None

    @property
    def session(self) -> TransportSession | None:
        return self._session

    @property
    def is_connected(self) -> bool:
        return bool(self._session and self._session.is_active and self._sock)

    def connect(self, remote_device_id: str, timeout: float = 10.0) -> TransportSession:
        """Establish local socket connection and perform authenticated handshake."""
        trusted_dev = self.trust_manager.verify_device_trust_or_raise(
            local_identity_id=self.local_identity_id,
            remote_identity_id=remote_device_id,
        )
        if trusted_dev.status == "REVOKED":
            raise TransportRevokedError(f"Device '{remote_device_id}' is revoked.")

        # Create socket
        try:
            if self.use_unix_socket and self.socket_path:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect(str(self.socket_path))
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((self.host, self.port))
            self._sock = sock
        except OSError as e:
            raise TransportError(f"Failed to connect to local transport socket: {e}") from e

        # Handshake initiation
        eph_priv, eph_pub = generate_ephemeral_keypair()
        init_env, client_nonce = create_session_init(
            sender_id=self.local_identity_id,
            recipient_id=remote_device_id,
            sender_private_key=self.local_private_key,
            ephemeral_public_key=eph_pub,
        )

        # Write SESSION_INIT frame
        write_frame(sock, init_env.to_canonical_bytes())

        # Read SESSION_ACK frame
        ack_bytes = read_frame(sock, timeout=timeout)
        ack_env = TransportEnvelope.from_json(ack_bytes.decode("utf-8"))

        server_eph_pub, session_id, server_nonce = verify_session_ack(
            envelope=ack_env,
            server_public_key_pem=trusted_dev.remote_public_key_pem,
            expected_client_eph_bytes=ephemeral_public_to_bytes(eph_pub),
            expected_client_nonce=client_nonce,
        )

        shared_secret = eph_priv.exchange(server_eph_pub)
        salt = f"{client_nonce}:{server_nonce}".encode()
        send_key, recv_key, session_salt = derive_session_keys(
            shared_secret=shared_secret,
            salt=salt,
            is_initiator=True,
        )

        session = TransportSession(
            session_id=session_id,
            local_identity_id=self.local_identity_id,
            remote_identity_id=remote_device_id,
            send_key=send_key,
            recv_key=recv_key,
            session_salt=session_salt,
            transport_type=TransportType.LOCAL,
            state=ConnectionState.CONNECTED,
            expires_at=ack_env.expires_at,
        )

        self._session = session
        self.registry.record_session(session)
        role_str = (
            trusted_dev.remote_role.value
            if hasattr(trusted_dev.remote_role, "value")
            else str(trusted_dev.remote_role)
        )
        self.registry.record_peer(
            PeerInfo(
                device_id=remote_device_id,
                role=role_str,
                connection_state=ConnectionState.CONNECTED,
                active_session_id=session_id,
                transport_type=TransportType.LOCAL,
                endpoint=str(self.socket_path) if self.use_unix_socket else f"{self.host}:{self.port}",
            )
        )
        self.reconnect_mgr.reset(remote_device_id)

        self.audit_logger.record(
            event_type=AuditEventType.TRANSPORT_SESSION_CREATED,
            details={"session_id": session_id, "remote_id": remote_device_id, "transport": "LOCAL"},
            actor_id=self.local_identity_id,
            success=True,
        )
        return session

    def send_envelope(self, envelope: TransportEnvelope) -> bool:
        """Encrypt envelope and transmit over socket."""
        if not self._session or not self._sock:
            raise TransportConnectionClosedError("Socket transport is not connected.")
        frame = self._session.encrypt_envelope(envelope)
        write_frame(self._sock, frame.to_canonical_bytes())
        return True

    def receive_envelope(self, timeout: float | None = None) -> TransportEnvelope | None:
        """Read encrypted frame from socket and decrypt."""
        if not self._session or not self._sock:
            return None
        try:
            raw_frame_bytes = read_frame(self._sock, timeout=timeout)
            frame = EncryptedTransportFrame.from_json(raw_frame_bytes.decode("utf-8"))
            return self._session.decrypt_frame(frame)
        except Exception:
            return None

    def disconnect(self, remote_device_id: str | None = None) -> None:
        """Close socket and terminate session."""
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

        if self._session:
            sid = self._session.session_id
            rid = self._session.remote_identity_id
            self._session.close(reason="Socket closed")
            self.registry.update_session_state(sid, ConnectionState.DISCONNECTED)
            self.registry.update_peer_state(rid, ConnectionState.DISCONNECTED)
            self._session = None

    def close(self) -> None:
        self.disconnect()


class FutureNetworkTransport(Transport):
    """Protocol interface placeholder for future production Internet relay transport."""

    def send_envelope(self, envelope: TransportEnvelope) -> bool:
        raise NotImplementedError(
            "Production Internet relay transport is scheduled for future phases. "
            "Use LocalSocketTransport or MemoryTransport for local and development environments."
        )

    def receive_envelope(self, timeout: float | None = None) -> TransportEnvelope | None:
        raise NotImplementedError("Production Internet relay transport is scheduled for future phases.")

    def close(self) -> None:
        pass


@dataclass
class RelayMessage:
    """Relay encapsulation preserving end-to-end payload confidentiality."""

    relay_version: str = "1.0"
    recipient_device_id: str = ""
    sender_device_id: str = ""
    encrypted_frame: EncryptedTransportFrame = field(default_factory=EncryptedTransportFrame)


class RelayTransport(abc.ABC):
    """Abstract interface for future zero-knowledge encrypted relay transport."""

    @abc.abstractmethod
    def forward_relay_message(self, message: RelayMessage) -> bool:
        """Forward an encrypted relay message without inspecting plaintext content."""
        raise NotImplementedError
