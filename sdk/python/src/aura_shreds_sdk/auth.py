"""Authenticating without disclosing the key.

A key is one value that serves as both name and credential, so a handshake that sends it would put
a working credential on the wire on every connect. Instead each side computes an HMAC over a
transcript both can reconstruct::

    subscriber -> node   reference = SHA-256(domain | key), subscriber nonce
    node       -> subscriber   node nonce, HMAC(key, node domain | transcript)
    subscriber checks it, then answers with HMAC(key, client domain | transcript)

The node proves first, so an impostor is abandoned having learned nothing.

TCP presents no certificate, so the transcript's binding is the all-zero sentinel. The key still
never travels; what plain TCP gives up is relay detection, which is why it suits a subscriber on a
network it trusts.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

__all__ = [
    "DIGEST_LEN",
    "NO_BINDING",
    "Transcript",
    "client_proof",
    "fresh_nonce",
    "key_ref",
    "server_proof",
    "short_ref",
    "verify_server",
]

_REFERENCE_DOMAIN = b"aura-shreds/key-ref/v1"
_NODE_DOMAIN = b"aura-shreds/server-proof/v1"
_SUBSCRIBER_DOMAIN = b"aura-shreds/client-proof/v1"

#: Bytes in a key reference, a nonce, a binding and a proof — all SHA-256 sized.
DIGEST_LEN = 32

#: The binding sentinel for a transport with no session material: plain TCP.
NO_BINDING = bytes(DIGEST_LEN)


def key_ref(key: bytes) -> bytes:
    """A non-reversible stand-in for a key, safe to log or quote.

    SHA-256 of the key under a domain separator. The greeting carries it; the node uses it to find
    which key to prove against.
    """
    return hashlib.sha256(_REFERENCE_DOMAIN + key).digest()


def short_ref(reference: bytes) -> str:
    """Enough hex to tell two keys apart in a log line."""
    return reference.hex()[:16]


def binding_of(certificate_der: bytes) -> bytes:
    """Bind a proof to a presented certificate."""
    return hashlib.sha256(certificate_der).digest()


@dataclass(frozen=True, slots=True)
class Transcript:
    """The material both sides hash to produce their proofs."""

    #: Reference of the key being claimed.
    key_ref: bytes
    #: Chosen by the subscriber.
    client_nonce: bytes
    #: Chosen by the node.
    server_nonce: bytes
    #: Session material, or the zero sentinel over TCP.
    binding: bytes


def _mac(transcript: Transcript, key: bytes, domain: bytes) -> bytes:
    mac = hmac.new(key, digestmod=hashlib.sha256)
    mac.update(domain)
    mac.update(transcript.key_ref)
    mac.update(transcript.client_nonce)
    mac.update(transcript.server_nonce)
    mac.update(transcript.binding)
    return mac.digest()


def server_proof(transcript: Transcript, key: bytes) -> bytes:
    """What the node must produce to authenticate itself."""
    return _mac(transcript, key, _NODE_DOMAIN)


def client_proof(transcript: Transcript, key: bytes) -> bytes:
    """What the subscriber must produce to authenticate itself."""
    return _mac(transcript, key, _SUBSCRIBER_DOMAIN)


def verify_server(transcript: Transcript, key: bytes, presented: bytes) -> bool:
    """Whether ``presented`` matches the node's expected proof.

    Compared in constant time: an early exit would grade a forger's guess byte by byte.
    """
    expected = server_proof(transcript, key)
    # compare_digest is constant time and tolerates a length mismatch, which a peer controls.
    return hmac.compare_digest(expected, presented)


def fresh_nonce() -> bytes:
    """A fresh nonce for one exchange.

    From the operating system's generator: uniqueness is not enough. A predictable nonce would let
    an attacker obtain a proof over a transcript chosen in advance.
    """
    return os.urandom(DIGEST_LEN)
