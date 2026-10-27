/**
 * Frames other than transactions: slot boundaries, entries and equivocation reports.
 *
 * Each is a fixed-size little-endian record with no variable tail, so reading one is a bounds check
 * plus a handful of loads.
 *
 * # Why entries carry no transaction bytes
 *
 * An entry's transactions already travel on the transaction stream, each carrying the `entryIndex`
 * that puts it back in its entry. Repeating the bytes here would double the bandwidth of a
 * subscriber taking both streams to say nothing new. What the entry frame adds is the structure
 * around them: the PoH hash, the hash count, and how many transactions the entry claimed — which is
 * what lets a subscriber notice one is missing.
 */

import { ProtocolError } from './failures.js';
import { Verification } from './frames.js';

function need(bytes: Buffer, size: number, what: string): void {
  if (bytes.length < size) {
    throw new ProtocolError(`${what} needs ${size} bytes, have ${bytes.length}`);
  }
}

function decodeVerification(byte: number): Verification {
  switch (byte) {
    case 0:
      return Verification.Verified;
    case 2:
      return Verification.UnknownLeader;
    case 3:
      return Verification.StaleSchedule;
    default:
      return Verification.Disabled;
  }
}

/** Encoded width of a slot start. */
export const SLOT_START_SIZE = 64;
/** Encoded width of a slot end. */
export const SLOT_END_SIZE = 48;
/** Encoded width of an entry. */
export const ENTRY_SIZE = 88;
/** Encoded width of a duplicate report. */
export const DUPLICATE_SIZE = 160;
/** Bytes before a raw shred's payload. */
export const RAW_SHRED_HEADER_SIZE = 32;

/** The first shred of a slot arrived. */
export interface SlotStart {
  slot: bigint;
  /** Present once a shred declaring the parent has arrived. */
  parentSlot: bigint | null;
  /** The slot's leader, when the schedule knew one. */
  leader: Buffer | null;
  /** When the first shred arrived, on the node's monotonic clock. */
  rxTsNs: bigint;
  /** Which ingress source delivered it. */
  source: number;
  shredVersion: number;
}

/** Parses a slot start. */
export function parseSlotStart(bytes: Buffer): SlotStart {
  need(bytes, SLOT_START_SIZE, 'slot start');
  const flags = bytes.readUInt8(60);
  return {
    slot: bytes.readBigUInt64LE(0),
    parentSlot: (flags & 1) !== 0 ? bytes.readBigUInt64LE(8) : null,
    leader: (flags & 2) !== 0 ? bytes.subarray(16, 48) : null,
    rxTsNs: bytes.readBigUInt64LE(48),
    source: bytes.readUInt16LE(56),
    shredVersion: bytes.readUInt16LE(58),
  };
}

/** A slot finished, either completed or given up on. */
export interface SlotEnd {
  slot: bigint;
  parentSlot: bigint;
  dataShreds: number;
  fecSets: number;
  /** Sets that had to be rebuilt from parity. */
  recoveredSets: number;
  /** Shreds never seen, and never recoverable. */
  missingShreds: number;
  /** When the slot was retired, on the node's monotonic clock. */
  endTsNs: bigint;
  /** Whether the slot was seen whole. False means shreds were lost. */
  complete: boolean;
}

/** Parses a slot end. */
export function parseSlotEnd(bytes: Buffer): SlotEnd {
  need(bytes, SLOT_END_SIZE, 'slot end');
  return {
    slot: bytes.readBigUInt64LE(0),
    parentSlot: bytes.readBigUInt64LE(8),
    dataShreds: bytes.readUInt32LE(16),
    fecSets: bytes.readUInt32LE(20),
    recoveredSets: bytes.readUInt32LE(24),
    missingShreds: bytes.readUInt32LE(28),
    endTsNs: bytes.readBigUInt64LE(32),
    complete: (bytes.readUInt8(40) & 1) !== 0,
  };
}

/** One proof-of-history entry. */
export interface Entry {
  slot: bigint;
  parentSlot: bigint;
  rxTsNs: bigint;
  /** PoH hashes since the previous entry. Zero marks a non-tick entry. */
  numHashes: bigint;
  /** How many transactions the entry claimed — compare against what arrived. */
  txCount: bigint;
  /** The entry's PoH hash. */
  hash: Buffer;
  fecSetIndex: number;
  entryIndex: number;
  verification: Verification;
}

/** Parses an entry. */
export function parseEntry(bytes: Buffer): Entry {
  need(bytes, ENTRY_SIZE, 'entry');
  return {
    slot: bytes.readBigUInt64LE(0),
    parentSlot: bytes.readBigUInt64LE(8),
    rxTsNs: bytes.readBigUInt64LE(16),
    numHashes: bytes.readBigUInt64LE(24),
    txCount: bytes.readBigUInt64LE(32),
    hash: bytes.subarray(40, 72),
    fecSetIndex: bytes.readUInt32LE(72),
    entryIndex: bytes.readUInt32LE(76),
    verification: decodeVerification(bytes.readUInt8(80)),
  };
}

/**
 * Two different shreds arrived for one slot and index — the leader equivocated.
 *
 * Both signatures are carried so the report can be checked independently; which fork survives is
 * not knowable at this layer, and a subscriber may care about the conflict itself.
 */
export interface Duplicate {
  slot: bigint;
  index: number;
  firstSource: number;
  secondSource: number;
  /** When the conflict was noticed, on the node's monotonic clock. */
  detectedNs: bigint;
  /** Whether the conflicting shreds were data shreds rather than parity. */
  isData: boolean;
  firstSignature: Buffer;
  secondSignature: Buffer;
}

/** Parses a duplicate report. */
export function parseDuplicate(bytes: Buffer): Duplicate {
  need(bytes, DUPLICATE_SIZE, 'duplicate');
  return {
    slot: bytes.readBigUInt64LE(0),
    index: bytes.readUInt32LE(8),
    firstSource: bytes.readUInt16LE(12),
    secondSource: bytes.readUInt16LE(14),
    detectedNs: bytes.readBigUInt64LE(16),
    isData: bytes.readUInt8(24) !== 0,
    firstSignature: bytes.subarray(32, 96),
    secondSignature: bytes.subarray(96, 160),
  };
}

/**
 * A shred republished exactly as it arrived.
 *
 * # What this stream is
 *
 * Every other event is a *conclusion* the node reached — a transaction it decoded, a slot it judged
 * finished. This is the evidence those were drawn from, handed to you at the moment the node
 * received it, before it verified or decoded anything.
 *
 * **Nothing here is claimed to be leader-signed.** A shred is republished as soon as it survives
 * deduplication; the signature check happens later, on the FEC set as a whole. If you need the
 * guarantee, take `transactions`, which carries it. If you need the latency and run your own
 * pipeline, this is for you.
 *
 * Two things it deliberately is not. **Not recovered**: a shred rebuilt from parity is not
 * republished, so a gap here is a real loss rather than an artefact, and your own count matches the
 * network's. **Not filtered**: a shred is a fragment of an erasure set, not yet anything a filter
 * can match on.
 *
 * It is the highest-rate stream a node publishes. Take it only if you are consuming it.
 */
export interface RawShred {
  /** Slot the shred belongs to. */
  slot: bigint;
  /**
   * Index within the slot, scoped by `isData`.
   *
   * A data shred and a coding shred may share an index. Key on the pair, not on the index alone.
   */
  index: number;
  /** Index of the first data shred of the FEC set this belongs to. */
  fecSetIndex: number;
  /** When the node received it, on the node's monotonic clock. */
  rxTsNs: bigint;
  /** Which configured source delivered it first. */
  source: number;
  /** Whether this is a data shred rather than parity. */
  isData: boolean;
  /** The shred exactly as it arrived, ready for a parser that expects one. */
  bytes: Buffer;
}

/** Parses a republished shred, borrowing the payload rather than copying it. */
export function parseRawShred(bytes: Buffer): RawShred {
  need(bytes, RAW_SHRED_HEADER_SIZE, 'raw shred');
  return {
    slot: bytes.readBigUInt64LE(0),
    index: bytes.readUInt32LE(8),
    fecSetIndex: bytes.readUInt32LE(12),
    rxTsNs: bytes.readBigUInt64LE(16),
    source: bytes.readUInt16LE(24),
    // Anything other than the parity marker is data: a kind byte this build does not know is a
    // newer node, and refusing the frame would break you over a field you do not use.
    isData: bytes.readUInt8(26) !== 1,
    bytes: bytes.subarray(RAW_SHRED_HEADER_SIZE),
  };
}

