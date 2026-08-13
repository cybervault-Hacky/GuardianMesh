"""Length-prefixed binary framing for streaming socket and pipe transports."""

from __future__ import annotations

import asyncio
import socket
import struct

from guardianmesh.core.errors import (
    TransportConnectionClosedError,
    TransportFramingError,
    TransportOversizedMessageError,
    TransportTimeoutError,
)

HEADER_FORMAT = "!I"  # 4-byte unsigned integer (big-endian)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
DEFAULT_MAX_FRAME_SIZE = 65536  # 64 KB


def encode_frame(data: bytes, max_size: int = DEFAULT_MAX_FRAME_SIZE) -> bytes:
    """Encode binary payload with a 4-byte big-endian length prefix.

    Args:
        data: Raw payload bytes to frame.
        max_size: Maximum allowed payload size.

    Returns:
        Framed bytes with length header.
    """
    length = len(data)
    if length > max_size:
        raise TransportOversizedMessageError(
            f"Frame payload size ({length} bytes) exceeds maximum limit of {max_size} bytes."
        )
    return struct.pack(HEADER_FORMAT, length) + data


def read_exact(
    sock: socket.socket,
    num_bytes: int,
    timeout: float | None = None,
) -> bytes:
    """Read an exact number of bytes from a synchronous socket.

    Args:
        sock: Connected socket.
        num_bytes: Number of bytes to read.
        timeout: Optional read timeout.

    Returns:
        Exact bytes buffer.
    """
    if timeout is not None:
        sock.settimeout(timeout)

    buf = bytearray()
    while len(buf) < num_bytes:
        try:
            chunk = sock.recv(num_bytes - len(buf))
            if not chunk:
                if len(buf) == 0:
                    raise TransportConnectionClosedError("Connection closed by remote peer.")
                raise TransportFramingError(
                    f"Unexpected EOF while reading frame (expected {num_bytes} bytes, got {len(buf)})."
                )
            buf.extend(chunk)
        except TimeoutError as e:
            raise TransportTimeoutError(f"Socket read timed out after {timeout} seconds.") from e
        except OSError as e:
            raise TransportConnectionClosedError(f"Socket error while reading: {e}") from e

    return bytes(buf)


def read_frame(
    sock: socket.socket,
    max_size: int = DEFAULT_MAX_FRAME_SIZE,
    timeout: float | None = None,
) -> bytes:
    """Read a single length-prefixed frame from a synchronous socket.

    Args:
        sock: Connected socket.
        max_size: Maximum allowed frame size.
        timeout: Optional read timeout.

    Returns:
        Decoded payload bytes.
    """
    header_bytes = read_exact(sock, HEADER_SIZE, timeout=timeout)
    (length,) = struct.unpack(HEADER_FORMAT, header_bytes)

    if length > max_size:
        raise TransportOversizedMessageError(
            f"Inbound frame header specified {length} bytes, exceeding limit of {max_size}."
        )
    if length == 0:
        return b""

    return read_exact(sock, length, timeout=timeout)


def write_frame(
    sock: socket.socket,
    data: bytes,
    max_size: int = DEFAULT_MAX_FRAME_SIZE,
) -> None:
    """Write a length-prefixed frame to a synchronous socket.

    Args:
        sock: Connected socket.
        data: Payload bytes to send.
        max_size: Maximum permitted size.
    """
    framed = encode_frame(data, max_size=max_size)
    try:
        sock.sendall(framed)
    except OSError as e:
        raise TransportConnectionClosedError(f"Failed to write frame to socket: {e}") from e


async def async_read_frame(
    reader: asyncio.StreamReader,
    max_size: int = DEFAULT_MAX_FRAME_SIZE,
    timeout: float | None = None,
) -> bytes:
    """Read a length-prefixed frame from an asyncio StreamReader.

    Args:
        reader: Async StreamReader.
        max_size: Maximum allowed payload size.
        timeout: Optional timeout in seconds.

    Returns:
        Decoded payload bytes.
    """
    try:
        read_coro = reader.readexactly(HEADER_SIZE)
        header_bytes = (
            await asyncio.wait_for(read_coro, timeout=timeout) if timeout else await read_coro
        )
    except asyncio.IncompleteReadError as e:
        if len(e.partial) == 0:
            raise TransportConnectionClosedError("Connection closed by remote peer.") from e
        raise TransportFramingError(f"Incomplete frame header ({len(e.partial)} bytes).") from e
    except TimeoutError as e:
        raise TransportTimeoutError(f"Async read timed out after {timeout} seconds.") from e

    (length,) = struct.unpack(HEADER_FORMAT, header_bytes)
    if length > max_size:
        raise TransportOversizedMessageError(
            f"Inbound frame length {length} exceeds maximum limit of {max_size}."
        )
    if length == 0:
        return b""

    try:
        body_coro = reader.readexactly(length)
        return await asyncio.wait_for(body_coro, timeout=timeout) if timeout else await body_coro
    except asyncio.IncompleteReadError as e:
        raise TransportFramingError(
            f"Incomplete frame body: expected {length} bytes, received {len(e.partial)}."
        ) from e
    except TimeoutError as e:
        raise TransportTimeoutError(f"Async frame body read timed out after {timeout} seconds.") from e


async def async_write_frame(
    writer: asyncio.StreamWriter,
    data: bytes,
    max_size: int = DEFAULT_MAX_FRAME_SIZE,
) -> None:
    """Write a length-prefixed frame to an asyncio StreamWriter.

    Args:
        writer: Async StreamWriter.
        data: Payload bytes to transmit.
        max_size: Maximum permitted size.
    """
    framed = encode_frame(data, max_size=max_size)
    writer.write(framed)
    await writer.drain()
