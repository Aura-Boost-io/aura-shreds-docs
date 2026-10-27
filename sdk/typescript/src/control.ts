/**
 * Control messages: the greeting, the authentication exchange, and the small records a connection
 * carries besides its stream.
 */

import { ProtocolError } from './failures.js';
import { PROTOCOL_VERSION } from './frames.js';

/** What a subscriber offers when it connects.
 *
 * **Carries no credential.** The key is named by a one-way reference and proved afterwards. A
 * captured greeting is worth nothing.
 */
export interface Hello {
  streams: number;
  codecs: number;
  /** Which key is claimed, without disclosing it. 32 bytes. */
  keyRef: Buffer;
  /** Fresh per connection, so a captured node proof cannot be replayed at this subscriber. */
  clientNonce: Buffer;
  /** A filter document to install before the stream starts, if any. */
  filter?: string;
}

/**
 * Encodes a greeting.
 *
 * The reference and the nonce are fixed width, so the greeting has no variable-length credential
 * fields — there is no credential in it to be variable. The filter trails them, length-prefixed
 * with a `u32` because a filter naming two thousand accounts is far past 64 KiB.
 */
export function encodeHello(hello: Hello): Buffer {
  const filter = hello.filter === undefined ? undefined : Buffer.from(hello.filter, 'utf8');
  const fixed = 8 + 32 + 32;
  const out = Buffer.allocUnsafe(fixed + (filter === undefined ? 0 : 4 + filter.length));
  out.writeUInt16LE(PROTOCOL_VERSION, 0);
  out.writeUInt32LE(hello.streams, 2);
  out.writeUInt8(hello.codecs, 6);
  // Byte 7 is padding, and this protocol has no capabilities byte to put there.
  out.writeUInt8(0, 7);
  hello.keyRef.copy(out, 8);
  hello.clientNonce.copy(out, 40);
  if (filter !== undefined) {
    // Byte length, not character count: the field is UTF-8, and `string.length` would understate
    // any filter that is not ASCII.
    out.writeUInt32LE(filter.length, fixed);
    filter.copy(out, fixed + 4);
  }
  return out;
}

/** The node's nonce and its proof that it holds the key.
 *
 * Sent before the subscriber has proved anything. Checking it is what tells you the peer is the
 * node rather than something sitting in front of it.
 */
export interface Challenge {
  serverNonce: Buffer;
  proof: Buffer;
}

/** Parses a challenge. */
export function parseChallenge(buf: Buffer): Challenge {
  if (buf.length < 64) throw new ProtocolError('challenge truncated');
  return {
    serverNonce: Buffer.from(buf.subarray(0, 32)),
    proof: Buffer.from(buf.subarray(32, 64)),
  };
}

/** Encodes the subscriber's proof that it holds the key. */
export function encodeProve(proof: Buffer): Buffer {
  return Buffer.from(proof);
}

/** What the node settled. */
export interface HelloAck {
  protocolVersion: number;
  sessionId: bigint;
  /** Streams actually granted — the intersection of what was asked and what the key permits. */
  granted: number;
  codec: number;
  /** How often the node pings an idle connection. */
  keepaliveMs: number;
}

/** Encoded width. No dictionary id field: this protocol has none. */
export const HELLO_ACK_LEN = 18;

/** Parses an acknowledgement. */
export function parseHelloAck(buf: Buffer): HelloAck {
  if (buf.length < HELLO_ACK_LEN) {
    throw new ProtocolError(`hello ack needs ${HELLO_ACK_LEN} bytes, have ${buf.length}`);
  }
  return {
    protocolVersion: buf.readUInt16LE(0),
    granted: buf.readUInt32LE(2),
    sessionId: buf.readBigUInt64LE(6),
    codec: buf.readUInt8(14),
    // Byte 15 is reserved.
    keepaliveMs: buf.readUInt16LE(16),
  };
}

/** Parses a refusal. */
export function parseRefusal(buf: Buffer): { code: number; detail: string } {
  if (buf.length < 4) throw new ProtocolError('refusal truncated');
  const code = buf.readUInt16LE(0);
  const len = buf.readUInt16LE(2);
  return { code, detail: buf.subarray(4, 4 + len).toString('utf8') };
}

/** Frames this connection missed, and where the stream resumes. */
export interface Lag {
  dropped: bigint;
  resumeSeq: bigint;
}

/** Parses a lag report. */
export function parseLag(buf: Buffer): Lag {
  if (buf.length < 16) throw new ProtocolError('lag report truncated');
  return { dropped: buf.readBigUInt64LE(0), resumeSeq: buf.readBigUInt64LE(8) };
}

/** The node's verdict on a submitted filter. */
export interface FilterAck {
  accepted: boolean;
  cost: number;
  detail: string;
}

/** Parses a filter verdict. */
export function parseFilterAck(buf: Buffer): FilterAck {
  if (buf.length < 8) throw new ProtocolError('filter verdict truncated');
  const len = buf.readUInt16LE(6);
  return {
    accepted: buf.readUInt8(0) !== 0,
    // Byte 1 is reserved.
    cost: buf.readUInt32LE(2),
    detail: buf.subarray(8, 8 + len).toString('utf8'),
  };
}

/** One filter, with the name the subscriber chose for it. */
export interface NamedFilter {
  /** What you call it. Comes back in a refusal so you know which one was at fault. */
  name?: string;
  /** The filter itself. */
  spec: object;
}

/**
 * Encodes a filter submission. The frame length delimits it, so the JSON needs no prefix.
 *
 * The whole set replaces whatever the connection carried, and is accepted or refused together — a
 * connection is never left holding part of what was asked for.
 */
export function encodeFilterSet(filters: NamedFilter[]): Buffer {
  return Buffer.from(JSON.stringify({ filters }), 'utf8');
}
