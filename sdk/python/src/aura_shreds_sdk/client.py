"""The subscriber client: connect, prove possession of your key, then read events.

The whole exchange::

    you  -> node   greeting: streams, codecs, a one-way reference to your key, your nonce
    node -> you    its nonce and HMAC(key, "server" | transcript)
    you            check it — a peer that cannot produce this does not hold your key
    you  -> node   HMAC(key, "client" | transcript)
    node -> you    what it granted, then frames until one side stops

Your key never crosses the wire. See :mod:`aura_shreds_sdk.auth`.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from compression import zstd
from dataclasses import dataclass
from typing import Union

from .auth import (
    NO_BINDING,
    Transcript,
    client_proof,
    fresh_nonce,
    key_ref,
    verify_server,
)
from .failures import ProtocolError, ServerError, TransportError
from .records import (
    Duplicate,
    Entry,
    RawShred,
    SlotEnd,
    SlotStart,
    parse_duplicate,
    parse_entry,
    parse_raw_shred,
    parse_slot_end,
    parse_slot_start,
)
from .tcp import Wire, connect_tcp
from .tx import Transaction
from .wire import (
    ALL_STREAMS,
    FRAME_HEADER_LEN,
    MAX_FRAME_PAYLOAD,
    MAX_PRE_AUTH_BYTES,
    PROTOCOL_VERSION,
    Codec,
    CodecBit,
    FrameKind,
    Hello,
    NamedFilter,
    build_frame,
    encode_filter_set,
    encode_hello,
    encode_prove,
    parse_challenge,
    parse_filter_ack,
    parse_frame_header,
    parse_hello_ack,
    parse_lag,
    parse_refusal,
)

__all__ = [
    "Client",
    "DuplicateEvent",
    "EntryEvent",
    "Event",
    "FilterAckEvent",
    "LagEvent",
    "PingEvent",
    "PongEvent",
    "RawShredEvent",
    "SlotEndEvent",
    "SlotStartEvent",
    "TransactionEvent",
    "UnknownEvent",
]

DEFAULT_CONNECT_TIMEOUT = 10.0


# -------------------------------------------------------------------------------------------------
# Events
# -------------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TransactionEvent:
    """A decoded transaction."""

    seq: int
    transaction: Transaction
    #: Which of this connection's named filters the transaction matched, as a bitmask.
    #:
    #: Zero when the connection named no filters. A transaction matching several filters arrives
    #: once, with every match recorded.
    matched: int
    type: str = "transaction"


@dataclass(frozen=True, slots=True)
class EntryEvent:
    seq: int
    entry: Entry
    type: str = "entry"


@dataclass(frozen=True, slots=True)
class SlotStartEvent:
    seq: int
    slot: SlotStart
    type: str = "slot-start"


@dataclass(frozen=True, slots=True)
class SlotEndEvent:
    seq: int
    slot: SlotEnd
    type: str = "slot-end"


@dataclass(frozen=True, slots=True)
class DuplicateEvent:
    seq: int
    duplicate: Duplicate
    type: str = "duplicate"


@dataclass(frozen=True, slots=True)
class RawShredEvent:
    """A shred republished exactly as it arrived. Needs the ``RAW_SHREDS`` stream.

    Delivered before the node verified or decoded anything, so nothing on it is claimed to be
    leader-signed — see :class:`aura_shreds_sdk.records.RawShred`.
    """

    seq: int
    shred: RawShred
    type: str = "raw-shred"


@dataclass(frozen=True, slots=True)
class LagEvent:
    seq: int
    lag: object
    type: str = "lag"


@dataclass(frozen=True, slots=True)
class FilterAckEvent:
    seq: int
    ack: object
    type: str = "filter-ack"


@dataclass(frozen=True, slots=True)
class PingEvent:
    seq: int
    type: str = "ping"


@dataclass(frozen=True, slots=True)
class PongEvent:
    seq: int
    type: str = "pong"


@dataclass(frozen=True, slots=True)
class UnknownEvent:
    """A frame kind this build does not know.

    Carried rather than dropped, so a newer node does not break an older subscriber.
    """

    seq: int
    kind: int
    payload: bytes
    type: str = "unknown"


Event = Union[
    TransactionEvent,
    EntryEvent,
    SlotStartEvent,
    SlotEndEvent,
    DuplicateEvent,
    RawShredEvent,
    LagEvent,
    FilterAckEvent,
    PingEvent,
    PongEvent,
    UnknownEvent,
]


# -------------------------------------------------------------------------------------------------
# Client
# -------------------------------------------------------------------------------------------------


class _Inbox:
    """Bytes read from the socket that do not yet form a whole frame.

    Whole frames are consumed from the front; whatever trails is moved up, so the steady-state
    allocation is one buffer instead of growth without bound behind a slow consumer.
    """

    __slots__ = ("_storage", "_filled")

    def __init__(self) -> None:
        self._storage = bytearray()
        self._filled = 0

    @property
    def held(self) -> int:
        """Bytes currently held."""
        return self._filled

    def view(self) -> memoryview:
        """The held bytes."""
        return memoryview(self._storage)[: self._filled]

    def take(self, count: int) -> bytes:
        """Consume ``count`` leading bytes."""
        out = bytes(self._storage[:count])
        del self._storage[:count]
        self._filled -= count
        return out

    def absorb(self, chunk: bytes) -> None:
        """Add one read chunk to the held bytes."""
        self._filled += len(chunk)
        self._storage.extend(chunk)

    async def pull(self, wire: Wire, need: int) -> int:
        """Read from the transport until at least ``need`` bytes are held.

        Returns the number of bytes read, so the caller can keep its own counters.
        """
        read = 0
        while self._filled < need:
            chunk = await wire.read(65536)
            if not chunk:
                raise TransportError("the node closed the connection")
            self._filled += len(chunk)
            self._storage.extend(chunk)
            read += len(chunk)
        return read


class Client:
    """A live subscription to a node.

    Construct with :meth:`connect`, then iterate::

        client = await Client.connect(host="ams.auraboost.wtf", port=9000, secret=secret)
        async for event in client:
            if event.type == "transaction":
                print(event.transaction.slot, event.transaction.signature.hex())
    """

    __slots__ = (
        "_inbox",
        "_closed",
        "_max_message_bytes",
        "_wire",
        "granted",
        "keepalive_ms",
        "message_bytes",
        "session_id",
        "wire_bytes",
    )

    def __init__(self) -> None:
        self._inbox = _Inbox()
        self._closed = False
        self._max_message_bytes = MAX_FRAME_PAYLOAD
        self._wire: Wire | None = None
        #: Streams actually granted — the intersection of what was asked and what the key permits.
        self.granted = 0
        self.keepalive_ms = 0
        self.session_id = 0
        #: Bytes read off the transport, before decompression.
        self.wire_bytes = 0
        #: Bytes after decompression. Against :attr:`wire_bytes`, this is the achieved ratio.
        self.message_bytes = 0

    # -- connecting ---------------------------------------------------------------------------

    @staticmethod
    async def connect(
        *,
        host: str,
        port: int,
        secret: str | bytes,
        streams: int = ALL_STREAMS,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        max_message_bytes: int = MAX_FRAME_PAYLOAD,
        filters: list[NamedFilter] | None = None,
    ) -> Client:
        """Open a subscription.

        ``host`` and ``port`` are the node's address — public, and the only thing besides your
        secret that you need. There is nothing else to configure.
        """
        if not host or port == 0:
            raise ProtocolError(
                "no node address was given. Pass host and port; this SDK ships none, so one build "
                "serves every node"
            )

        key = secret.encode() if isinstance(secret, str) else bytes(secret)

        self = Client()
        self._max_message_bytes = max_message_bytes
        self._wire = await connect_tcp(host, port, connect_timeout)

        try:
            await self._handshake(key, streams, filters, connect_timeout)
        except BaseException:
            await self.close()
            raise
        return self

    async def _handshake(
        self,
        key: bytes,
        streams: int,
        filters: list[NamedFilter] | None,
        timeout: float,
    ) -> None:
        assert self._wire is not None
        wire = self._wire
        reference = key_ref(key)
        client_nonce = fresh_nonce()

        greeting = Hello(
            streams=streams,
            codecs=CodecBit.ZSTD,
            key_ref=reference,
            client_nonce=client_nonce,
            filter=encode_filter_set(filters).decode() if filters else None,
        )
        await wire.write(build_frame(FrameKind.HELLO, 0, encode_hello(greeting)))

        deadline = asyncio.get_running_loop().time() + timeout

        challenge_body = await self._await_frame(
            FrameKind.CHALLENGE, MAX_PRE_AUTH_BYTES, deadline
        )
        if isinstance(challenge_body, RefusalBody):
            raise ServerError(challenge_body.code, challenge_body.detail)
        challenge = parse_challenge(challenge_body)

        transcript = Transcript(
            key_ref=reference,
            client_nonce=client_nonce,
            server_nonce=challenge.server_nonce,
            # Plain TCP presents no certificate, so there is nothing to bind a proof to. The key
            # still never crosses the wire.
            binding=NO_BINDING,
        )
        if not verify_server(transcript, key, challenge.proof):
            raise ProtocolError(
                "the node did not prove it holds this key; the connection is not to the node it "
                "claims to be"
            )
        await wire.write(
            build_frame(FrameKind.PROVE, 0, encode_prove(client_proof(transcript, key)))
        )

        ack_body = await self._await_frame(FrameKind.HELLO_ACK, MAX_PRE_AUTH_BYTES, deadline)
        if isinstance(ack_body, RefusalBody):
            raise ServerError(ack_body.code, ack_body.detail)
        ack = parse_hello_ack(ack_body)
        if ack.protocol_version != PROTOCOL_VERSION:
            raise ProtocolError(
                f"the node speaks protocol version {ack.protocol_version}, this build speaks "
                f"{PROTOCOL_VERSION}"
            )
        if ack.codec != Codec.ZSTD:
            raise ProtocolError(
                f"the node negotiated {Codec(ack.codec).name}, but this client requires zstd; the "
                "node has zstd disabled"
            )

        self.session_id = ack.session_id
        self.granted = ack.granted
        self.keepalive_ms = ack.keepalive_ms

    async def _await_frame(
        self,
        expected: FrameKind,
        limit: int,
        deadline: float,
    ) -> bytes | RefusalBody:
        """Wait for one handshake frame, bounded by ``deadline``.

        Returns the payload bytes, or the node's refusal. The node has proved nothing yet, so
        nothing here trusts the stream's own limits.
        """
        assert self._wire is not None
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TransportError("the handshake did not complete in time")
            if self._inbox.held >= FRAME_HEADER_LEN:
                header = parse_frame_header(self._inbox.view())
                if header.len > limit:
                    raise ProtocolError(
                        f"the node declared a {header.len}-byte handshake frame; the allowance is "
                        f"{limit}"
                    )
                if self._inbox.held >= FRAME_HEADER_LEN + header.len:
                    payload = self._inbox.take(FRAME_HEADER_LEN + header.len)[FRAME_HEADER_LEN:]
                    if header.kind == FrameKind.ERROR:
                        refusal = parse_refusal(payload)
                        return RefusalBody(refusal.code, refusal.detail)
                    if header.kind != expected:
                        raise ProtocolError(
                            f"expected {expected.name} during the handshake, got {header.kind.name}"
                        )
                    return payload
            try:
                chunk = await asyncio.wait_for(self._wire.read(65536), remaining)
            except TimeoutError as exc:
                raise TransportError("the handshake did not complete in time") from exc
            if not chunk:
                raise TransportError("the node closed the connection during the handshake")
            self.wire_bytes += len(chunk)
            self._inbox.absorb(chunk)
    # -- reading ------------------------------------------------------------------------------

    async def _read_frame_header(self):
        assert self._wire is not None
        while True:
            if self._inbox.held >= FRAME_HEADER_LEN:
                header = parse_frame_header(self._inbox.view())
                if header.len > self._max_message_bytes:
                    raise ProtocolError(
                        f"the node declared a {header.len}-byte frame; this connection's limit is "
                        f"{self._max_message_bytes}"
                    )
                if self._inbox.held >= FRAME_HEADER_LEN + header.len:
                    self._inbox.take(FRAME_HEADER_LEN)
                    return header
            chunk = await self._wire.read(65536)
            if not chunk:
                raise TransportError("the node closed the connection")
            self.wire_bytes += len(chunk)
            self._inbox.absorb(chunk)

    def _inflate(self, payload: bytes, codec: Codec) -> bytes:
        if codec != Codec.ZSTD:
            raise ProtocolError(
                f"the node compressed with {Codec(codec).name}, which this client cannot decode"
            )
        try:
            return zstd.decompress(payload)
        except zstd.ZstdError as exc:
            raise ProtocolError(f"the frame did not decompress: {exc}") from exc

    async def next_event(self) -> Event:
        """Read one event, waiting for it if necessary."""
        assert self._wire is not None
        while True:
            header = await self._read_frame_header()
            payload = self._inbox.take(header.len)
            body = self._inflate(payload, header.codec) if header.compressed else payload
            self.message_bytes += len(body)
            seq = header.seq

            match header.kind:
                case FrameKind.TRANSACTION:
                    return TransactionEvent(
                        seq=seq, transaction=Transaction.read(body), matched=header.matched
                    )
                case FrameKind.ENTRY:
                    return EntryEvent(seq=seq, entry=parse_entry(body))
                case FrameKind.SLOT_START:
                    return SlotStartEvent(seq=seq, slot=parse_slot_start(body))
                case FrameKind.SLOT_END:
                    return SlotEndEvent(seq=seq, slot=parse_slot_end(body))
                case FrameKind.DUPLICATE:
                    return DuplicateEvent(seq=seq, duplicate=parse_duplicate(body))
                case FrameKind.RAW_SHRED:
                    return RawShredEvent(seq=seq, shred=parse_raw_shred(body))
                case FrameKind.LAG:
                    return LagEvent(seq=seq, lag=parse_lag(body))
                case FrameKind.FILTER_ACK:
                    return FilterAckEvent(seq=seq, ack=parse_filter_ack(body))
                case FrameKind.PING:
                    # Answered here so a consumer that is slow to poll is not dropped for idling.
                    await self._wire.write(build_frame(FrameKind.PONG, 0, b""))
                    return PingEvent(seq=seq)
                case FrameKind.PONG:
                    return PongEvent(seq=seq)
                case FrameKind.ERROR:
                    refusal = parse_refusal(body)
                    raise ServerError(refusal.code, refusal.detail)
                case _:
                    return UnknownEvent(seq=seq, kind=header.raw_kind, payload=body)

    def __aiter__(self):
        return self._iterate()

    async def _iterate(self):
        try:
            while not self._closed:
                yield await self.next_event()
        except (TransportError, ServerError):
            if not self._closed:
                raise

    # -- control ------------------------------------------------------------------------------

    async def set_filter(self, spec: object) -> None:
        """Submit one unnamed filter, replacing whatever this connection carried."""
        await self.set_filters([NamedFilter(spec=spec)])

    async def set_filters(self, filters: list[NamedFilter]) -> None:
        """Replace this connection's filter set.

        The whole set replaces whatever the connection carried, and is accepted or refused together
        — a connection is never left holding part of what was asked for. The verdict arrives as a
        :class:`FilterAckEvent`.
        """
        assert self._wire is not None
        await self._wire.write(build_frame(FrameKind.SET_FILTER, 0, encode_filter_set(filters)))

    async def ping(self) -> None:
        """Ask the node to answer, so a silent connection can be told from a dead one."""
        assert self._wire is not None
        await self._wire.write(build_frame(FrameKind.PING, 0, b""))

    async def close(self) -> None:
        """Close the connection. Idempotent."""
        if self._closed:
            return
        self._closed = True
        if self._wire is not None:
            await self._wire.close()

    async def __aenter__(self) -> Client:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()


class RefusalBody:
    """Marker for a refusal received where a handshake frame was expected."""

    __slots__ = ("code", "detail")

    def __init__(self, code: int, detail: str) -> None:
        self.code = code
        self.detail = detail
