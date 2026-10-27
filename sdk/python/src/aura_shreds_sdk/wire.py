"""The frame layer and the control messages of the aura-shreds protocol.

Byte layout only, kept apart from the session logic so a consumer driving the protocol some other
way — a proxy, a replay tool, a test double — can use the parsing without the socket.

Offsets are fixed and every section is 8-byte aligned, which is why fields are read by pointing at
them rather than by walking length prefixes.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from enum import IntEnum, StrEnum

from .failures import ProtocolError

__all__ = [
    "ALL_STREAMS",
    "HELLO_ACK_LEN",
    "FRAME_HEADER_LEN",
    "MAX_FRAME_PAYLOAD",
    "MAX_PRE_AUTH_BYTES",
    "PROTOCOL_VERSION",
    "Challenge",
    "Codec",
    "CodecBit",
    "FilterAck",
    "FrameHeader",
    "FrameKind",
    "Hello",
    "HelloAck",
    "Lag",
    "NamedFilter",
    "Refusal",
    "Stream",
    "Verification",
    "parse_challenge",
    "parse_filter_ack",
    "parse_frame_header",
    "parse_hello_ack",
    "parse_lag",
    "parse_refusal",
    "build_frame",
    "encode_hello",
    "encode_prove",
    "encode_filter_set",
]

#: Protocol version this build speaks.
PROTOCOL_VERSION = 1

#: Bytes in a frame header.
FRAME_HEADER_LEN = 16

#: Ceiling on any frame payload.
MAX_FRAME_PAYLOAD = 16 << 20

#: Ceiling on a control message read before the node has authenticated itself.
#:
#: The length field belongs to the peer, and at this stage of the exchange it has proved nothing —
#: so the ceiling is what any legitimate message of this kind can be, not the global frame ceiling.
#: Judged by :data:`MAX_FRAME_PAYLOAD` instead, any address you dial could cost you sixteen
#: megabytes for the price of a header.
MAX_PRE_AUTH_BYTES = 64 * 1024


class FrameKind(IntEnum):
    """What a frame carries."""

    #: Produced when reading a kind byte this build does not know.
    UNRECOGNIZED = 0
    TRANSACTION = 1
    ENTRY = 2
    SLOT_START = 3
    SLOT_END = 4
    DUPLICATE = 5
    RAW_SHRED = 6
    LAG = 7
    SOURCE_STATS = 8
    HELLO = 9
    HELLO_ACK = 10
    FILTER_ACK = 11
    ERROR = 12
    PING = 13
    PONG = 14
    SET_FILTER = 15
    #: The node's nonce and its proof that it holds the key.
    CHALLENGE = 16
    #: The subscriber's proof that it holds the key.
    PROVE = 17


class Stream(IntEnum):
    """Streams a subscriber may ask for. The node grants the intersection with the key's allowance."""

    TRANSACTIONS = 1 << 0
    ENTRIES = 1 << 1
    SLOT_EVENTS = 1 << 2
    DUPLICATES = 1 << 3
    #: Every shred verbatim, before the node verifies or decodes anything.
    RAW_SHREDS = 1 << 4
    #: Reserved on the wire; no producer exists.
    SOURCE_STATS = 1 << 5
    VOTES = 1 << 6


#: Every stream that is actually published.
ALL_STREAMS = (
    Stream.TRANSACTIONS
    | Stream.ENTRIES
    | Stream.SLOT_EVENTS
    | Stream.DUPLICATES
    | Stream.RAW_SHREDS
    | Stream.VOTES
)


class Codec(IntEnum):
    """Compression codecs. The value is what travels in the frame flags."""

    PLAIN = 0
    LZ4 = 1
    ZSTD = 2


class CodecBit(IntEnum):
    """Bits offered in a greeting, one per codec this build can inflate."""

    NONE = 1 << 0
    LZ4 = 1 << 1
    ZSTD = 1 << 2


class Verification(StrEnum):
    """How much the node could vouch for a transaction or entry."""

    #: The leader's signature over the set's merkle root checked out.
    VERIFIED = "verified"
    #: The node runs with verification switched off.
    DISABLED = "disabled"
    #: No leader is known for the slot.
    UNKNOWN_LEADER = "unknown-leader"
    #: The leader schedule is behind.
    STALE_SCHEDULE = "stale-schedule"


@dataclass(frozen=True, slots=True)
class FrameHeader:
    """A decoded frame header."""

    #: Payload bytes following the header.
    len: int
    #: What the payload is, as far as this build recognises it.
    kind: FrameKind
    #: The kind byte exactly as it arrived, so an unrecognized frame keeps its identity.
    raw_kind: int
    #: Whether the payload is compressed.
    compressed: bool
    #: Codec the payload was compressed with.
    codec: Codec
    #: Which of this connection's named filters the frame matched, as a bitmask.
    matched: int
    #: Per-connection sequence number. A gap is exactly what was dropped.
    seq: int


def parse_frame_header(buf: bytes, at: int = 0) -> FrameHeader:
    """Parse a frame header.

    An unrecognised kind is not an error: a client built before a frame type existed must skip it,
    not drop the connection, or adding one would break every deployed subscriber.
    """
    if len(buf) - at < FRAME_HEADER_LEN:
        raise ProtocolError(f"frame header needs {FRAME_HEADER_LEN} bytes, have {len(buf) - at}")
    length, raw_kind, flags, matched, seq = struct.unpack_from("<IBBHQ", buf, at)
    if length > MAX_FRAME_PAYLOAD:
        raise ProtocolError(f"frame declares {length} payload bytes, limit is {MAX_FRAME_PAYLOAD}")
    kind = FrameKind(raw_kind) if 1 <= raw_kind <= 17 else FrameKind.UNRECOGNIZED
    return FrameHeader(
        len=length,
        kind=kind,
        raw_kind=raw_kind,
        compressed=(flags & 0b100) != 0,
        codec=Codec(flags & 0b11),
        matched=matched,
        seq=seq,
    )


def build_frame(kind: FrameKind, seq: int, payload: bytes, matched: int = 0) -> bytes:
    """Build a frame with ``payload`` as its body."""
    return struct.pack("<IBBHQ", len(payload), int(kind), 0, matched, seq) + payload


@dataclass(frozen=True, slots=True)
class Hello:
    """What a subscriber offers when it connects.

    **Carries no credential.** The key is named by a one-way reference and proved afterwards. A
    captured greeting is worth nothing.
    """

    streams: int
    codecs: int
    #: Which key is claimed, without disclosing it. 32 bytes.
    key_ref: bytes
    #: Fresh per connection, so a captured node proof cannot be replayed at this subscriber.
    client_nonce: bytes
    #: A filter document to install before the stream starts, if any.
    filter: str | None = None


def encode_hello(hello: Hello) -> bytes:
    """Encode a greeting.

    The reference and the nonce are fixed width, so the greeting has no variable-length credential
    fields — there is no credential in it to be variable. The filter trails them, length-prefixed
    with a ``u32`` because a filter naming two thousand accounts is far past 64 KiB.
    """
    out = bytearray(72)
    struct.pack_into("<HIBB", out, 0, PROTOCOL_VERSION, hello.streams, hello.codecs, 0)
    out[8:40] = hello.key_ref
    out[40:72] = hello.client_nonce
    if hello.filter is not None:
        # Byte length, not character count: the field is UTF-8.
        encoded = hello.filter.encode("utf-8")
        out += struct.pack("<I", len(encoded)) + encoded
    return bytes(out)


@dataclass(frozen=True, slots=True)
class Challenge:
    """The node's nonce and its proof that it holds the key.

    Sent before the subscriber has proved anything. Checking it is what tells you the peer is the
    node rather than something sitting in front of it.
    """

    server_nonce: bytes
    proof: bytes


def parse_challenge(buf: bytes) -> Challenge:
    """Parse a challenge."""
    if len(buf) < 64:
        raise ProtocolError("challenge truncated")
    return Challenge(server_nonce=bytes(buf[0:32]), proof=bytes(buf[32:64]))


def encode_prove(proof: bytes) -> bytes:
    """Encode the subscriber's proof that it holds the key."""
    return bytes(proof)


@dataclass(frozen=True, slots=True)
class HelloAck:
    """What the node settled."""

    protocol_version: int
    session_id: int
    #: Streams actually granted — the intersection of what was asked and what the key permits.
    granted: int
    codec: Codec
    #: How often the node pings an idle connection.
    keepalive_ms: int


#: Encoded width. No dictionary id field: this protocol has none.
HELLO_ACK_LEN = 18


def parse_hello_ack(buf: bytes) -> HelloAck:
    """Parse an acknowledgement."""
    if len(buf) < HELLO_ACK_LEN:
        raise ProtocolError(f"hello ack needs {HELLO_ACK_LEN} bytes, have {len(buf)}")
    version, granted, session, codec = struct.unpack_from("<HIQB", buf, 0)
    # Byte 15 is reserved.
    (keepalive,) = struct.unpack_from("<H", buf, 16)
    return HelloAck(
        protocol_version=version,
        granted=granted,
        session_id=session,
        codec=Codec(codec),
        keepalive_ms=keepalive,
    )


@dataclass(frozen=True, slots=True)
class Refusal:
    """The node refused, or is closing the connection."""

    code: int
    detail: str


def parse_refusal(buf: bytes) -> Refusal:
    """Parse a refusal."""
    if len(buf) < 4:
        raise ProtocolError("refusal truncated")
    code, length = struct.unpack_from("<HH", buf, 0)
    detail = bytes(buf[4 : 4 + length]).decode("utf-8", errors="replace")
    return Refusal(code=code, detail=detail)


@dataclass(frozen=True, slots=True)
class Lag:
    """Frames this connection missed, and where the stream resumes."""

    dropped: int
    resume_seq: int


def parse_lag(buf: bytes) -> Lag:
    """Parse a lag report."""
    if len(buf) < 16:
        raise ProtocolError("lag report truncated")
    dropped, resume = struct.unpack_from("<QQ", buf, 0)
    return Lag(dropped=dropped, resume_seq=resume)


@dataclass(frozen=True, slots=True)
class FilterAck:
    """The node's verdict on a submitted filter."""

    accepted: bool
    cost: int
    detail: str


def parse_filter_ack(buf: bytes) -> FilterAck:
    """Parse a filter verdict."""
    if len(buf) < 8:
        raise ProtocolError("filter verdict truncated")
    accepted = buf[0] != 0
    # Byte 1 is reserved.
    (cost,) = struct.unpack_from("<I", buf, 2)
    (length,) = struct.unpack_from("<H", buf, 6)
    detail = bytes(buf[8 : 8 + length]).decode("utf-8", errors="replace")
    return FilterAck(accepted=accepted, cost=cost, detail=detail)


@dataclass(frozen=True, slots=True)
class NamedFilter:
    """One filter, with the name the subscriber chose for it.

    The spec is anything JSON-encodable the node's schema accepts — a mapping for a clause such as
    ``{"is_vote": {"value": False}}``, or a bare string for a unit variant such as ``"all"``.
    """

    #: The filter itself.
    spec: object
    #: What you call it. Comes back in a refusal so you know which one was at fault.
    name: str | None = None


def encode_filter_set(filters: list[NamedFilter]) -> bytes:
    """Encode a filter submission. The frame length delimits it, so the JSON needs no prefix.

    The whole set replaces whatever the connection carried, and is accepted or refused together — a
    connection is never left holding part of what was asked for.
    """
    body = {
        "filters": [
            {"name": f.name, "spec": f.spec} if f.name is not None else {"spec": f.spec}
            for f in filters
        ]
    }
    return json.dumps(body, separators=(",", ":")).encode("utf-8")
