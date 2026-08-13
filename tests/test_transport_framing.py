"""Tests for length-prefixed streaming transport framing."""

from __future__ import annotations

import asyncio
import socket

import pytest

from guardianmesh.core.errors import (
    TransportConnectionClosedError,
    TransportFramingError,
    TransportOversizedMessageError,
    TransportTimeoutError,
)
from guardianmesh.transport.framing import (
    async_read_frame,
    async_write_frame,
    encode_frame,
    read_frame,
    write_frame,
)


def test_frame_encoding_and_length_header() -> None:
    """Test 4-byte length header encoding."""
    data = b"Hello GuardianMesh Nexus"
    framed = encode_frame(data)
    assert len(framed) == len(data) + 4
    # Length prefix: 24 bytes in big-endian
    assert framed[:4] == b"\x00\x00\x00\x18"
    assert framed[4:] == data

    # Oversized payload
    with pytest.raises(TransportOversizedMessageError):
        encode_frame(b"x" * 100, max_size=50)


def test_sync_socket_write_and_read_frame() -> None:
    """Test frame transmission over synchronous socket pair."""
    server_sock, client_sock = socket.socketpair()
    try:
        payload = b'{"message_type":"HEARTBEAT","sequence":1}'
        write_frame(client_sock, payload)

        received = read_frame(server_sock, timeout=2.0)
        assert received == payload

        # Empty frame
        write_frame(client_sock, b"")
        received_empty = read_frame(server_sock, timeout=2.0)
        assert received_empty == b""
    finally:
        server_sock.close()
        client_sock.close()


def test_sync_socket_closed_and_incomplete_errors() -> None:
    """Test handling of closed sockets, EOF, and truncated frames."""
    server_sock, client_sock = socket.socketpair()
    client_sock.close()

    # Read from closed socket
    with pytest.raises(TransportConnectionClosedError):
        read_frame(server_sock, timeout=1.0)
    server_sock.close()

    # Truncated body
    s1, s2 = socket.socketpair()
    try:
        s2.sendall(b"\x00\x00\x00\x10" + b"short")
        s2.close()
        with pytest.raises(TransportFramingError):
            read_frame(s1, timeout=1.0)
    finally:
        s1.close()


def test_sync_socket_timeout() -> None:
    """Test socket read timeout raises TransportTimeoutError."""
    server_sock, client_sock = socket.socketpair()
    try:
        with pytest.raises(TransportTimeoutError):
            read_frame(server_sock, timeout=0.1)
    finally:
        server_sock.close()
        client_sock.close()


def test_sync_socket_oversized_inbound_frame() -> None:
    """Test oversized frame header rejection."""
    server_sock, client_sock = socket.socketpair()
    try:
        # Header specifies 1000 bytes, limit is 50
        client_sock.sendall(b"\x00\x00\x03\xe8")
        with pytest.raises(TransportOversizedMessageError):
            read_frame(server_sock, max_size=50, timeout=1.0)
    finally:
        server_sock.close()
        client_sock.close()


def test_async_read_and_write_frame() -> None:
    """Test asynchronous frame encoding and reading over asyncio streams."""
    async def _run() -> None:
        received_data: list[bytes] = []

        async def _handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            data = await async_read_frame(reader, timeout=2.0)
            received_data.append(data)
            await async_write_frame(writer, b"ACK:" + data)
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(_handle_client, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            payload = b"Async GuardianMesh Stream"
            await async_write_frame(writer, payload)

            resp = await async_read_frame(reader, timeout=2.0)
            assert resp == b"ACK:" + payload
            assert received_data == [payload]

            writer.close()
            await writer.wait_closed()

    asyncio.run(_run())
