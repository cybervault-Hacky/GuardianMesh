"""Transport server implementations for memory, local socket, and network transports."""

from __future__ import annotations

import abc
import queue
import socket
import threading
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519

from guardianmesh.core.errors import (
    DeviceNotTrustedError,
    TransportConnectionClosedError,
    TransportRevokedError,
    TrustRevokedError,
)
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.storage.audit import AuditEventType, AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.transport.crypto import (
    create_session_ack,
    derive_session_keys,
    ephemeral_public_to_bytes,
    generate_ephemeral_keypair,
    verify_session_init,
)
from guardianmesh.transport.framing import read_frame, write_frame
from guardianmesh.transport.models import (
    ConnectionState,
    EncryptedTransportFrame,
    PeerInfo,
    TransportEnvelope,
    TransportType,
    generate_session_id,
)
from guardianmesh.transport.registry import TransportRegistry
from guardianmesh.transport.router import MessageRouter
from guardianmesh.transport.session import TransportSession


class TransportServer(abc.ABC):
    """Abstract contract for transport servers receiving inbound connections."""

    @abc.abstractmethod
    def start(self) -> None:
        """Start listening for incoming connections."""
        raise NotImplementedError

    @abc.abstractmethod
    def stop(self) -> None:
        """Stop server and disconnect active sessions."""
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def is_running(self) -> bool:
        """Whether the server is actively listening."""
        raise NotImplementedError


class MemoryTransportServer(TransportServer):
    """In-memory transport server for local testing and component synchronization."""

    def __init__(
        self,
        db: Database,
        local_identity_id: str,
        local_private_key: ed25519.Ed25519PrivateKey,
        trust_manager: TrustManager,
        router: MessageRouter | None = None,
        registry: TransportRegistry | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.db = db
        self.local_identity_id = local_identity_id
        self.local_private_key = local_private_key
        self.trust_manager = trust_manager
        self.registry = registry or TransportRegistry(db)
        self.audit_logger = audit_logger or AuditLogger(db)
        self.router = router or MessageRouter(
            db, local_identity_id, trust_manager, registry=self.registry, audit_logger=self.audit_logger
        )

        self.inbox: queue.Queue[EncryptedTransportFrame] = queue.Queue()
        self._sessions: dict[str, TransportSession] = {}
        self._is_running = True

    @property
    def is_running(self) -> bool:
        return self._is_running

    def start(self) -> None:
        self._is_running = True

    def stop(self) -> None:
        self._is_running = False
        for s in list(self._sessions.values()):
            s.close(reason="Server stopped")
            self.registry.update_session_state(s.session_id, ConnectionState.DISCONNECTED)
        self._sessions.clear()

    def handle_handshake_init(self, init_envelope: TransportEnvelope) -> TransportEnvelope:
        """Process incoming SESSION_INIT, perform mutual trust verification, and return SESSION_ACK."""
        sender_id = init_envelope.sender_id

        # 1. Verify Trust Registry
        try:
            trusted_dev = self.trust_manager.verify_device_trust_or_raise(
                local_identity_id=self.local_identity_id,
                remote_identity_id=sender_id,
            )
            if trusted_dev.status == "REVOKED":
                raise TrustRevokedError(f"Device '{sender_id}' is revoked.")
        except (DeviceNotTrustedError, TrustRevokedError) as e:
            self.audit_logger.record(
                event_type=AuditEventType.TRANSPORT_REVOKED,
                details={"remote_id": sender_id, "reason": str(e)},
                actor_id=self.local_identity_id,
                success=False,
            )
            raise TransportRevokedError(f"Inbound handshake from untrusted/revoked peer: {e}") from e

        # 2. Verify SESSION_INIT Signature & Ephemeral Key
        client_eph_pub, client_nonce = verify_session_init(
            envelope=init_envelope,
            sender_public_key_pem=trusted_dev.remote_public_key_pem,
        )

        # 3. Generate Server Ephemeral Keypair & SESSION_ACK
        session_id = generate_session_id()
        server_eph_priv, server_eph_pub = generate_ephemeral_keypair()
        ack_envelope, server_nonce = create_session_ack(
            sender_id=self.local_identity_id,
            recipient_id=sender_id,
            session_id=session_id,
            sender_private_key=self.local_private_key,
            ephemeral_public_key=server_eph_pub,
            client_ephemeral_bytes=ephemeral_public_to_bytes(client_eph_pub),
            client_nonce=client_nonce,
        )

        # 4. Derive Symmetric Session Keys (HKDF-SHA256)
        shared_secret = server_eph_priv.exchange(client_eph_pub)
        salt = f"{client_nonce}:{server_nonce}".encode()
        send_key, recv_key, session_salt = derive_session_keys(
            shared_secret=shared_secret,
            salt=salt,
            is_initiator=False,
        )

        # 5. Store Session
        session = TransportSession(
            session_id=session_id,
            local_identity_id=self.local_identity_id,
            remote_identity_id=sender_id,
            send_key=send_key,
            recv_key=recv_key,
            session_salt=session_salt,
            transport_type=TransportType.MEMORY,
            state=ConnectionState.CONNECTED,
            expires_at=ack_envelope.expires_at,
        )

        self._sessions[session_id] = session
        self.registry.record_session(session)
        role_str = (
            trusted_dev.remote_role.value
            if hasattr(trusted_dev.remote_role, "value")
            else str(trusted_dev.remote_role)
        )
        self.registry.record_peer(
            PeerInfo(
                device_id=sender_id,
                role=role_str,
                connection_state=ConnectionState.CONNECTED,
                active_session_id=session_id,
                transport_type=TransportType.MEMORY,
            )
        )

        self.audit_logger.record(
            event_type=AuditEventType.TRANSPORT_AUTHENTICATED,
            details={
                "session_id": session_id,
                "remote_id": sender_id,
                "transport_type": "MEMORY",
            },
            actor_id=self.local_identity_id,
            success=True,
        )
        return ack_envelope

    def process_next_frame(self, timeout: float | None = None) -> Any:
        """Read next frame from inbox, decrypt, and route."""
        try:
            frame = self.inbox.get(timeout=timeout)
        except queue.Empty:
            return None

        session = self._sessions.get(frame.session_id)
        if not session or not session.is_active:
            raise TransportConnectionClosedError(f"No active session found for ID '{frame.session_id}'.")

        envelope = session.decrypt_frame(frame)
        return self.router.route(envelope, session)

    def process_all_pending(self) -> list[Any]:
        """Process all queued incoming frames."""
        results: list[Any] = []
        while not self.inbox.empty():
            res = self.process_next_frame(timeout=0.01)
            if res is not None:
                results.append(res)
        return results

    def get_session(self, session_id: str) -> TransportSession | None:
        return self._sessions.get(session_id)


class LocalSocketTransportServer(TransportServer):
    """Local socket server accepting connections over UNIX domain socket or localhost TCP."""

    def __init__(
        self,
        db: Database,
        local_identity_id: str,
        local_private_key: ed25519.Ed25519PrivateKey,
        trust_manager: TrustManager,
        socket_path: Path | str | None = None,
        host: str = "0.0.0.0",
        port: int = 8443,
        use_unix_socket: bool = False,
        router: MessageRouter | None = None,
        registry: TransportRegistry | None = None,
        audit_logger: AuditLogger | None = None,
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
        self.router = router or MessageRouter(
            db, local_identity_id, trust_manager, registry=self.registry, audit_logger=self.audit_logger
        )

        self._server_sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._is_running = False
        self._sessions: dict[str, TransportSession] = {}

    @property
    def is_running(self) -> bool:
        return self._is_running

    def start(self) -> None:
        """Bind socket and start background listening thread."""
        if self._is_running:
            return

        if self.use_unix_socket and self.socket_path:
            p = Path(self.socket_path)
            if p.exists():
                p.unlink()
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(str(p))
            try:
                p.chmod(0o600)
            except OSError:
                pass
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))

        sock.listen(5)
        self._server_sock = sock
        self._is_running = True

        self._thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._thread.start()

    def _listen_loop(self) -> None:
        """Background loop accepting incoming client connections."""
        while self._is_running and self._server_sock:
            try:
                self._server_sock.settimeout(1.0)
                client_sock, _ = self._server_sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break

            client_thread = threading.Thread(
                target=self._handle_client,
                args=(client_sock,),
                daemon=True,
            )
            client_thread.start()

    def _handle_client(self, sock: socket.socket) -> None:
        """Perform handshake with connected client and process frames until disconnect."""
        session: TransportSession | None = None
        try:
            # 1. Read SESSION_INIT
            init_bytes = read_frame(sock, timeout=10.0)
            init_env = TransportEnvelope.from_json(init_bytes.decode("utf-8"))
            sender_id = init_env.sender_id

            # 2. Verify Trust
            trusted_dev = self.trust_manager.verify_device_trust_or_raise(
                local_identity_id=self.local_identity_id,
                remote_identity_id=sender_id,
            )
            if trusted_dev.status == "REVOKED":
                raise TransportRevokedError(f"Device '{sender_id}' is revoked.")

            client_eph_pub, client_nonce = verify_session_init(
                envelope=init_env,
                sender_public_key_pem=trusted_dev.remote_public_key_pem,
            )

            # 3. Generate ACK
            session_id = generate_session_id()
            server_eph_priv, server_eph_pub = generate_ephemeral_keypair()
            ack_env, server_nonce = create_session_ack(
                sender_id=self.local_identity_id,
                recipient_id=sender_id,
                session_id=session_id,
                sender_private_key=self.local_private_key,
                ephemeral_public_key=server_eph_pub,
                client_ephemeral_bytes=ephemeral_public_to_bytes(client_eph_pub),
                client_nonce=client_nonce,
            )

            write_frame(sock, ack_env.to_canonical_bytes())

            # 4. Derive Keys
            shared_secret = server_eph_priv.exchange(client_eph_pub)
            salt = f"{client_nonce}:{server_nonce}".encode()
            send_key, recv_key, session_salt = derive_session_keys(
                shared_secret=shared_secret,
                salt=salt,
                is_initiator=False,
            )

            session = TransportSession(
                session_id=session_id,
                local_identity_id=self.local_identity_id,
                remote_identity_id=sender_id,
                send_key=send_key,
                recv_key=recv_key,
                session_salt=session_salt,
                transport_type=TransportType.LOCAL,
                state=ConnectionState.CONNECTED,
                expires_at=ack_env.expires_at,
            )
            self._sessions[session_id] = session
            self.registry.record_session(session)
            role_str = (
                trusted_dev.remote_role.value
                if hasattr(trusted_dev.remote_role, "value")
                else str(trusted_dev.remote_role)
            )
            self.registry.record_peer(
                PeerInfo(
                    device_id=sender_id,
                    role=role_str,
                    connection_state=ConnectionState.CONNECTED,
                    active_session_id=session_id,
                    transport_type=TransportType.LOCAL,
                )
            )

            # 5. Frame Processing Loop
            while self._is_running and session.is_active:
                try:
                    frame_bytes = read_frame(sock, timeout=30.0)
                    frame = EncryptedTransportFrame.from_json(frame_bytes.decode("utf-8"))
                    envelope = session.decrypt_frame(frame)
                    result = self.router.route(envelope, session)

                    # If route produced a response envelope (e.g. PONG), send it back
                    if isinstance(result, TransportEnvelope):
                        resp_frame = session.encrypt_envelope(result)
                        write_frame(sock, resp_frame.to_canonical_bytes())
                except TransportConnectionClosedError:
                    break
                except TimeoutError:
                    continue

        except Exception as e:
            if session:
                session.close(reason=str(e))
        finally:
            try:
                sock.close()
            except Exception:
                pass
            if session:
                self.registry.update_session_state(session.session_id, ConnectionState.DISCONNECTED)
                self.registry.update_peer_state(session.remote_identity_id, ConnectionState.DISCONNECTED)

    def stop(self) -> None:
        """Stop server listening socket."""
        self._is_running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
            self._server_sock = None

        if self.use_unix_socket and self.socket_path:
            try:
                Path(self.socket_path).unlink(missing_ok=True)
            except Exception:
                pass

        for s in list(self._sessions.values()):
            s.close(reason="Server stopped")
        self._sessions.clear()
