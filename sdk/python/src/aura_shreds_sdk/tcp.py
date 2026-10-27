"""Reaching the node: TCP.

The aura-shreds node serves subscribers over TCP. Nothing here checks a certificate, because there
is none: the node authenticates itself with your key during the handshake. See
:mod:`aura_shreds_sdk.auth` for why that is not the weakening it looks like.
"""

from __future__ import annotations

import asyncio
from typing import Protocol

from .failures import TransportError

__all__ = ["TransportError", "Wire", "connect_tcp"]


class Wire(Protocol):
    """A byte pipe to the node.

    Deliberately small: the client does all the framing, so a consumer wanting a transport this
    package does not ship — a proxy, a replay file, a test double — implements these three methods.
    """

    async def read(self, limit: int = 65536) -> bytes:
        """Return up to ``limit`` bytes, or ``b""`` once the peer is done."""
        ...

    async def write(self, data: bytes) -> None:
        """Write bytes."""
        ...

    async def close(self) -> None:
        """Close the connection."""
        ...


class _TcpWire:
    """A plain TCP connection. No certificate, and therefore no binding."""

    __slots__ = ("_reader", "_writer")

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer

    async def read(self, limit: int = 65536) -> bytes:
        return await self._reader.read(limit)

    async def write(self, data: bytes) -> None:
        self._writer.write(data)
        await self._writer.drain()

    async def close(self) -> None:
        try:
            self._writer.close()
            await self._writer.wait_closed()
        except (OSError, asyncio.CancelledError):
            pass


async def connect_tcp(host: str, port: int, timeout: float = 10.0) -> Wire:
    """Open a TCP connection to the node."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except TimeoutError as exc:
        raise TransportError(f"connecting to {host}:{port} over TCP timed out") from exc
    except OSError as exc:
        raise TransportError(f"connecting to {host}:{port} over TCP failed: {exc}") from exc
    return _TcpWire(reader, writer)
