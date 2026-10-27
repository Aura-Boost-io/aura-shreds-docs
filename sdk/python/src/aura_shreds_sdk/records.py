"""Frames other than transactions: slot boundaries, entries and equivocation reports.

Each is a fixed-size little-endian record with no variable tail, so reading one is a bounds check
plus a handful of loads.

# Why entries carry no transaction bytes

An entry's transactions already travel on the transaction stream, each carrying the ``entry_index``
that puts it back in its entry. Repeating the bytes here would double the bandwidth of a subscriber
taking both streams to say nothing new. What the entry frame adds is the structure around them: the
PoH hash, the hash count, and how many transactions the entry claimed — which is what lets a
subscriber notice one is missing.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .failures import ProtocolError
from .wire import Verification

__all__ = [
    "DUPLICATE_LEN",
    "ENTRY_LEN",
    "RAW_SHRED_HEADER_LEN",
    "SLOT_END_LEN",
    "SLOT_START_LEN",
    "Duplicate",
    "Entry",
    "RawShred",
    "SlotEnd",
    "SlotStart",
    "parse_duplicate",
    "parse_entry",
    "parse_raw_shred",
    "parse_slot_end",
    "parse_slot_start",
]


def _need(data: bytes, size: int, what: str) -> None:
    if len(data) < size:
        raise ProtocolError(f"{what} needs {size} bytes, have {len(data)}")


def _verdict(byte: int) -> Verification:
    match byte:
        case 0:
            return Verification.VERIFIED
        case 2:
            return Verification.UNKNOWN_LEADER
        case 3:
            return Verification.STALE_SCHEDULE
        case _:
            return Verification.DISABLED


#: Encoded width of a slot start.
SLOT_START_LEN = 64
#: Encoded width of a slot end.
SLOT_END_LEN = 48
#: Encoded width of an entry.
ENTRY_LEN = 88
#: Encoded width of a duplicate report.
DUPLICATE_LEN = 160
#: Bytes before a raw shred's payload.
RAW_SHRED_HEADER_LEN = 32


@dataclass(frozen=True, slots=True)
class SlotStart:
    """The first shred of a slot arrived."""

    #: The slot that appeared.
    slot: int
    #: Present once a shred declaring the parent has arrived.
    parent_slot: int | None
    #: The slot's leader, when the schedule knew one.
    leader: bytes | None
    #: When the first shred arrived, on the node's monotonic clock.
    rx_ts_ns: int
    #: Which ingress source delivered it.
    source: int
    #: Shred version carried by the first shred.
    shred_version: int


def parse_slot_start(data: bytes) -> SlotStart:
    """Parse a slot start."""
    _need(data, SLOT_START_LEN, "slot start")
    flags = data[60]
    (slot,) = struct.unpack_from("<Q", data, 0)
    (parent,) = struct.unpack_from("<Q", data, 8)
    (rx_ts,) = struct.unpack_from("<Q", data, 48)
    source, shred_version = struct.unpack_from("<HH", data, 56)
    return SlotStart(
        slot=slot,
        parent_slot=parent if flags & 1 else None,
        leader=bytes(data[16:48]) if flags & 2 else None,
        rx_ts_ns=rx_ts,
        source=source,
        shred_version=shred_version,
    )


@dataclass(frozen=True, slots=True)
class SlotEnd:
    """A slot finished, either completed or given up on."""

    #: The slot that ended.
    slot: int
    #: Parent of ``slot``.
    parent_slot: int
    #: Data shreds observed or recovered.
    data_shreds: int
    #: FEC sets that completed.
    fec_sets: int
    #: Sets that had to be reconstructed from parity.
    recovered_sets: int
    #: Shreds never obtained, so their entries were never emitted.
    missing_shreds: int
    #: When the slot was retired, on the node's monotonic clock.
    end_ts_ns: int
    #: Whether the slot was seen whole. False means shreds were lost.
    complete: bool


def parse_slot_end(data: bytes) -> SlotEnd:
    """Parse a slot end."""
    _need(data, SLOT_END_LEN, "slot end")
    slot, parent, shreds, sets, recovered, missing, end_ts = struct.unpack_from(
        "<QQIIIIQ", data, 0
    )
    return SlotEnd(
        slot=slot,
        parent_slot=parent,
        data_shreds=shreds,
        fec_sets=sets,
        recovered_sets=recovered,
        missing_shreds=missing,
        end_ts_ns=end_ts,
        complete=(data[40] & 1) != 0,
    )


@dataclass(frozen=True, slots=True)
class Entry:
    """One proof-of-history entry."""

    #: Slot the entry was produced in.
    slot: int
    #: Parent of ``slot``.
    parent_slot: int
    #: When the FEC set's first shred arrived, on the node's monotonic clock.
    rx_ts_ns: int
    #: PoH hashes since the previous entry. Zero means this is not a tick boundary.
    num_hashes: int
    #: How many transactions the entry claimed — compare against what arrived.
    tx_count: int
    #: The entry's PoH hash.
    hash: bytes
    #: FEC set the entry came from.
    fec_set_index: int
    #: Index of the entry within its batch.
    entry_index: int
    #: Signature status of the FEC set.
    verification: Verification


def parse_entry(data: bytes) -> Entry:
    """Parse an entry."""
    _need(data, ENTRY_LEN, "entry")
    slot, parent, rx_ts, num_hashes, tx_count = struct.unpack_from("<QQQQQ", data, 0)
    fec_set_index, entry_index = struct.unpack_from("<II", data, 72)
    return Entry(
        slot=slot,
        parent_slot=parent,
        rx_ts_ns=rx_ts,
        num_hashes=num_hashes,
        tx_count=tx_count,
        hash=bytes(data[40:72]),
        fec_set_index=fec_set_index,
        entry_index=entry_index,
        verification=_verdict(data[80]),
    )

@dataclass(frozen=True, slots=True)
class Duplicate:
    """Two different shreds arrived for one slot and index — the leader equivocated.

    Both signatures are carried so the report can be checked independently; which fork survives is
    not knowable at this layer, and a subscriber may care about the conflict itself.
    """

    #: The slot both shreds claim.
    slot: int
    #: The index both shreds claim.
    index: int
    #: Source that delivered the version that arrived first.
    first_source: int
    #: Source that delivered the conflicting version.
    second_source: int
    #: When the conflict was noticed, on the node's monotonic clock.
    detected_ns: int
    #: Whether the conflicting shreds were data shreds rather than parity.
    is_data: bool
    #: Signature of the version that arrived first.
    first_signature: bytes
    #: Signature of the conflicting version.
    second_signature: bytes


def parse_duplicate(data: bytes) -> Duplicate:
    """Parse a duplicate report."""
    _need(data, DUPLICATE_LEN, "duplicate")
    slot, index, first_source, second_source, detected = struct.unpack_from(
        "<QIHHQ", data, 0
    )
    return Duplicate(
        slot=slot,
        index=index,
        first_source=first_source,
        second_source=second_source,
        detected_ns=detected,
        is_data=data[24] != 0,
        first_signature=bytes(data[32:96]),
        second_signature=bytes(data[96:160]),
    )


@dataclass(frozen=True, slots=True)
class RawShred:
    """A shred republished exactly as it arrived.

    # What this stream is

    Every other event is a *conclusion* the node reached — a transaction it decoded, a slot it
    judged finished. This is the evidence those were drawn from, handed to you at the moment the
    node received it, before it verified or decoded anything.

    **Nothing here is claimed to be leader-signed.** A shred is republished as soon as it survives
    deduplication; the signature check happens later, on the FEC set as a whole. If you need the
    guarantee, take ``transactions``, which carries it. If you need the latency and run your own
    pipeline, this is for you.

    Two things it deliberately is not. **Not recovered**: a shred rebuilt from parity is not
    republished, so a gap here is a real loss rather than an artefact, and your own count matches
    the network's. **Not filtered**: a shred is a fragment of an erasure set, not yet anything a
    filter can match on.

    It is the highest-rate stream a node publishes. Take it only if you are consuming it.
    """

    #: Slot the shred belongs to.
    slot: int
    #: Index within the slot, scoped by ``is_data``.
    #:
    #: A data shred and a coding shred may share an index. Key on the pair, not on the index alone.
    index: int
    #: Index of the first data shred of the FEC set this belongs to.
    fec_set_index: int
    #: When the node received it, on the node's monotonic clock.
    rx_ts_ns: int
    #: Which configured source delivered it first.
    source: int
    #: Whether this is a data shred rather than parity.
    is_data: bool
    #: The shred exactly as it arrived, ready for a parser that expects one.
    bytes: bytes


def parse_raw_shred(data: bytes) -> RawShred:
    """Parse a republished shred."""
    _need(data, RAW_SHRED_HEADER_LEN, "raw shred")
    slot, index, fec_set_index, rx_ts, source = struct.unpack_from("<QIIQH", data, 0)
    return RawShred(
        slot=slot,
        index=index,
        fec_set_index=fec_set_index,
        rx_ts_ns=rx_ts,
        source=source,
        # Anything other than the parity marker is data: a kind byte this build does not know is a
        # newer node, and refusing the frame would break you over a field you do not use.
        is_data=data[26] != 1,
        bytes=bytes(data[RAW_SHRED_HEADER_LEN:]),
    )
