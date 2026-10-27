/**
 * The frame layer: kinds, codecs, stream bits, and the 16-byte header.
 *
 * Byte layout only. Kept apart from the session logic so a consumer driving the protocol some other
 * way — a different runtime, a proxy, a replay tool — can use the parsing without the socket.
 */

import { ProtocolError } from './failures.js';

/** Protocol version this build speaks. */
export const PROTOCOL_VERSION = 1;

/** Bytes in a frame header. */
export const FRAME_HEADER_LEN = 16;

/** Ceiling on any frame payload. */
export const MAX_FRAME_PAYLOAD = 16 << 20;

/** What a frame carries. */
export enum FrameKind {
  /** Produced when reading a kind byte this build does not know. */
  Unrecognized = 0,
  Transaction = 1,
  Entry = 2,
  SlotStart = 3,
  SlotEnd = 4,
  Duplicate = 5,
  RawShred = 6,
  Lag = 7,
  SourceStats = 8,
  Hello = 9,
  HelloAck = 10,
  FilterAck = 11,
  Error = 12,
  Ping = 13,
  Pong = 14,
  SetFilter = 15,
  Challenge = 16,
  Prove = 17,
}

/** Streams a subscriber may ask for. The node grants the intersection with the key's allowance. */
export const Stream = {
  TRANSACTIONS: 1 << 0,
  ENTRIES: 1 << 1,
  SLOT_EVENTS: 1 << 2,
  DUPLICATES: 1 << 3,
  /**
   * Every shred verbatim, before the node verifies or decodes anything.
   *
   * The highest-rate stream published — a multiple of `TRANSACTIONS`, since a shred is a fragment
   * and most fragments carry votes. Nothing on it is claimed to be leader-signed.
   */
  RAW_SHREDS: 1 << 4,
  /** Reserved on the wire; no producer exists. */
  SOURCE_STATS: 1 << 5,
  VOTES: 1 << 6,
} as const;

/** Every stream that is actually published. */
export const ALL_STREAMS =
  Stream.TRANSACTIONS |
  Stream.ENTRIES |
  Stream.SLOT_EVENTS |
  Stream.DUPLICATES |
  Stream.RAW_SHREDS |
  Stream.VOTES;

/** Compression codecs. The value is what travels in the frame flags. */
export enum Codec {
  Plain = 0,
  Lz4 = 1,
  Zstd = 2,
}

/** Bits offered in a greeting, one per codec this build can inflate. */
export const CodecBit = {
  NONE: 1 << 0,
  LZ4: 1 << 1,
  ZSTD: 1 << 2,
} as const;

/** Why the node refused or disconnected. */
export enum ErrorCode {
  Unauthorized = 1,
  Forbidden = 2,
  TooSlow = 3,
  RateLimited = 4,
  BadRequest = 5,
  Shutdown = 6,
  UnsupportedVersion = 7,
}

/** How much the node could vouch for a transaction or entry. */
export enum Verification {
  /** The leader's signature over the set's merkle root checked out. */
  Verified = 'verified',
  /** The node runs with verification switched off. */
  Disabled = 'disabled',
  /** No leader is known for the slot. */
  UnknownLeader = 'unknown-leader',
  /** The leader schedule is behind. */
  StaleSchedule = 'stale-schedule',
}

/** A decoded frame header. */
export interface FrameHeader {
  /** Payload bytes following the header. */
  len: number;
  /** What the payload is, as far as this build recognises it. */
  kind: FrameKind;
  /** The kind byte exactly as it arrived, so an unrecognized frame keeps its identity. */
  rawKind: number;
  /** Whether the payload is compressed. */
  compressed: boolean;
  /** Codec the payload was compressed with. */
  codec: Codec;
  /**
   * Which of this connection's named filters the frame matched, as a bitmask.
   *
   * Zero when the connection named none. Bit `i` is the filter at index `i` in the submitted set;
   * one transaction matching several arrives once, with every match recorded.
   */
  matched: number;
  /** Per-connection sequence number. A gap is exactly what was dropped. */
  seq: bigint;
}

/**
 * Parses a frame header.
 *
 * An unrecognised kind is not an error: a client built before a frame type existed must skip it,
 * not drop the connection, or adding one would break every deployed subscriber.
 */
export function parseFrameHeader(buf: Buffer, at = 0): FrameHeader {
  if (buf.length - at < FRAME_HEADER_LEN) {
    throw new ProtocolError(
      `frame header needs ${FRAME_HEADER_LEN} bytes, have ${buf.length - at}`,
    );
  }
  const len = buf.readUInt32LE(at);
  if (len > MAX_FRAME_PAYLOAD) {
    throw new ProtocolError(`frame declares ${len} payload bytes, limit is ${MAX_FRAME_PAYLOAD}`);
  }
  const rawKind = buf.readUInt8(at + 4);
  const flags = buf.readUInt8(at + 5);
  let kind: FrameKind = FrameKind.Unrecognized;
  if (rawKind >= 1 && rawKind <= 17) kind = rawKind;
  return {
    len,
    kind,
    rawKind,
    compressed: (flags & 0b100) !== 0,
    codec: (flags & 0b11) as Codec,
    matched: buf.readUInt16LE(at + 6),
    seq: buf.readBigUInt64LE(at + 8),
  };
}

/** Builds a frame with `payload` as its body. */
export function buildFrame(
  kind: FrameKind,
  seq: bigint,
  payload: Buffer,
  matched = 0,
): Buffer {
  const out = Buffer.allocUnsafe(FRAME_HEADER_LEN + payload.length);
  out.writeUInt32LE(payload.length, 0);
  out.writeUInt8(kind, 4);
  out.writeUInt8(0, 5);
  out.writeUInt16LE(matched, 6);
  out.writeBigUInt64LE(seq, 8);
  payload.copy(out, FRAME_HEADER_LEN);
  return out;
}
