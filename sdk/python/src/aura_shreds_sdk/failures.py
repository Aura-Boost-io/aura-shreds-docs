"""Failure types for the subscriber protocol."""

from __future__ import annotations

__all__ = ["ProtocolError", "ServerError", "TransportError"]


class ProtocolError(Exception):
    """Anything the protocol could not be read as."""


class ServerError(Exception):
    """The node refused the connection, or closed it with a reason."""

    def __init__(self, code: int, detail: str) -> None:
        super().__init__(f"refused by node [{code}]: {detail}")
        self.code = code
        self.detail = detail


class TransportError(Exception):
    """The connection could not be established, or failed while open."""
