/**
 * The subscriber client.
 *
 * Connects, proves possession of its key, and yields decoded events as they arrive.
 *
 * # Compression is not optional
 *
 * This client offers only zstd. An aura-shreds node streams several hundred megabits of transaction
 * data per second uncompressed, and a compressed stream is roughly a third of that. Letting a
 * subscriber quietly negotiate its way to an uncompressed stream costs the operator bandwidth they
 * did not agree to, so a node can be configured to refuse it — and this client refuses it too,
 * rather than connecting and silently costing more than it should.
 *
 * The only thing this asks of a consumer is Node 22.15 or newer, where zstd is built in.
 */

import { zstdDecompressSync } from 'node:zlib';

import {
  clientProof,
  freshNonce,
  keyRef,
  verifyServer,
  type Transcript,
} from './auth.js';
import {
  ALL_STREAMS,
  Codec,
  CodecBit,
  FRAME_HEADER_LEN,
  FrameKind,
  MAX_FRAME_PAYLOAD,
  PROTOCOL_VERSION,
  buildFrame,
  parseFrameHeader,
  type FrameHeader,
} from './frames.js';
import {
  encodeFilterSet,
  encodeHello,
  encodeProve,
  parseChallenge,
  parseFilterAck,
  parseHelloAck,
  parseLag,
  parseRefusal,
  type FilterAck,
  type HelloAck,
  type Lag,
  type NamedFilter,
} from "./control.js";
import {
  parseDuplicate,
  parseEntry,
  parseRawShred,
  parseSlotEnd,
  parseSlotStart,
  type Duplicate,
  type Entry,
  type RawShred,
  type SlotEnd,
  type SlotStart,
} from './records.js';
import { ProtocolError, ServerError } from './failures.js';
import type { Wire } from './socket.js';
import { connectTcp } from './socket.js';
import { Transaction } from './tx.js';

/** How to connect. */
export interface ClientOptions {
  /** Node host. Required. */
  host: string;
  /** Node port. Required. */
  port: number;
  /**
   * The key issued to this subscriber, and the only credential there is.
   *
   * There is no key id to go with it. The greeting names your key by `SHA-256(domain ‖ secret)` and
   * never carries the secret itself, so the node finds it by that reference rather than by a name.
   *
   * A string is sent as its UTF-8 bytes, exactly as written — never decoded as hex or base64, even
   * when it looks like either. Pass a `Buffer` if your secret is genuinely binary.
   */
  secret: string | Buffer;
  /**
   * Streams to subscribe to. Defaults to everything the key permits.
   *
   * The node grants the intersection of this and what the key allows, so asking for more than the
   * key permits is not an error — check {@link AuraShredsClient.granted} for what was actually
   * given.
   */
  streams?: number;
  /** A filter document installed in the greeting, so the stream is narrowed before it starts. */
  filter?: string;
  /**
   * Named filters installed in the greeting, encoded through the same encoder `setFilters` uses.
   *
   * {@link AuraShredsClient.setFilters} leaves a window — a round trip at least — during which the
   * connection is unfiltered and everything subscribed to arrives. On a busy node that window is
   * thousands of transactions nobody asked for, and they are billed. Naming them here closes it:
   * the node installs them before the first frame is sent. A filter that does not compile, or that
   * exceeds the key's budgets, refuses the connection rather than falling back to an unfiltered
   * stream.
   */
  filters?: NamedFilter[];
  /** How long to wait for the handshake, in milliseconds. Defaults to 10 seconds. */
  connectTimeoutMs?: number;
  /**
   * Largest message to accept, compressed or not.
   *
   * Bounds both the frame taken off the socket and what a compressed one expands into, so lowering
   * it actually bounds what a node can make this process hold. A compressed body is smaller than
   * what it becomes, so nothing legitimate is lost by checking it in both places. Handshake frames
   * are bounded separately, by what each of them can be.
   */
  maxMessageBytes?: number;
}

/** Something the node sent. */
export type AuraShredsEvent =
  | {
      type: 'transaction';
      seq: bigint;
      transaction: Transaction;
      /**
       * Which of this connection's named filters this transaction matched, as a bitmask.
       *
       * Zero when the connection named none. One transaction matching several filters arrives once,
       * with every match recorded.
       */
      matched: number;
    }
  | { type: 'entry'; seq: bigint; entry: Entry }
  | { type: 'slot-start'; seq: bigint; slot: SlotStart }
  | { type: 'slot-end'; seq: bigint; slot: SlotEnd }
  | { type: 'duplicate'; seq: bigint; duplicate: Duplicate }
  /**
   * A shred republished exactly as it arrived. Needs the `RAW_SHREDS` stream.
   *
   * Delivered before the node verified or decoded anything, so nothing on it is claimed to be
   * leader-signed — see {@link RawShred}.
   */
  | { type: 'raw-shred'; seq: bigint; shred: RawShred }
  | { type: 'lag'; seq: bigint; lag: { dropped: bigint; resumeSeq: bigint } }
  | { type: 'filter-ack'; seq: bigint; ack: FilterAck }
  | { type: 'ping'; seq: bigint }
  | { type: 'pong'; seq: bigint }
  /**
   * A frame kind this build does not know. Carried rather than dropped, so a newer node does not
   * break an older subscriber.
   */
  | { type: 'other'; seq: bigint; kind: number; payload: Buffer };

const DEFAULT_CONNECT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_MESSAGE_BYTES = MAX_FRAME_PAYLOAD;

/**
 * Events buffered for a consumer that is not asking for them, before the transport stops reading.
 *
 * Large enough that a consumer doing ordinary per-event work never touches it, and small enough
 * that a consumer which has genuinely stopped is noticed by the node within its own queue rather
 * than after this one has eaten the heap.
 */
const MAX_BACKLOG = 4_096;

/** Where reading restarts, well below {@link MAX_BACKLOG}. */
const RESUME_BACKLOG = 1_024;

/** Ceiling on a control message read before the node has authenticated itself. */
const MAX_PRE_AUTH_BYTES = 64 * 1024;

/**
 * Turns a secret into the bytes the node compares against.
 *
 * A string is sent as its UTF-8 bytes, exactly as written. It is deliberately *not* decoded as hex
 * or base64 even when it looks like either: the node compares against the literal characters in its
 * key file, and a secret is usually a run of hex digits, so guessing at an encoding would silently
 * send the wrong bytes for the most common secret there is.
 */
function decodeSecret(secret: string | Buffer): Buffer {
  return Buffer.isBuffer(secret) ? secret : Buffer.from(secret, 'utf8');
}

/**
 * A live subscription.
 *
 * Iterate it to receive events:
 *
 * ```ts
 * const client = await AuraShredsClient.connect({ ... });
 * for await (const event of client) {
 *   if (event.type === 'transaction') console.log(event.transaction.slot);
 * }
 * ```
 */
export class AuraShredsClient implements AsyncIterable<AuraShredsEvent> {
  private buffer: Buffer = Buffer.alloc(0);
  private waiter: ((result: IteratorResult<AuraShredsEvent>) => void) | null = null;
  private rejecter: ((reason: unknown) => void) | null = null;
  private queue: AuraShredsEvent[] = [];
  private stopped = false;
  private failure: unknown = null;
  private finished = false;
  private lastSeq: bigint | null = null;
  private gapCount = 0n;
  private wire = 0n;
  private decoded = 0n;

  private constructor(
    private readonly socket: Wire,
    private readonly ack: HelloAck,
    private readonly maxMessageBytes: number,
    leftover: Buffer,
  ) {
    socket.onData((chunk) => this.onData(chunk));
    socket.onError((err) => this.fail(err));
    socket.onClose(() => this.finish());
    // Bytes that arrived alongside the handshake reply already belong to the stream.
    if (leftover.length > 0) this.onData(leftover);
    socket.resume();
  }

  /** Connects, authenticates, and negotiates compression. */
  static async connect(options: ClientOptions): Promise<AuraShredsClient> {
    const timeoutMs = options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS;
    const { host, port } = options;
    if (host === '' || port === 0) {
      throw new ProtocolError(
        'this build of the SDK was not provisioned with a node address. Pass host and port; one ' +
          'build serves every node',
      );
    }

    const wire = await connectTcp(host, port, timeoutMs);
    try {
      // Your key never leaves this process. It names itself by a one-way reference, and possession
      // is proved below over nonces bound to this session.
      const key = decodeSecret(options.secret);
      const reference = keyRef(key);
      const clientNonce = freshNonce();

      const greeting = encodeHello({
        streams: options.streams ?? ALL_STREAMS,
        // Only zstd: see the note at the top of this file.
        codecs: CodecBit.ZSTD,
        keyRef: reference,
        clientNonce,
        // Encoded through the same encoder `setFilters` uses, so a filter means the same thing
        // whichever way it was sent.
        ...(options.filter === undefined ? {} : { filter: options.filter }),
        ...(options.filters === undefined
          ? {}
          : { filter: encodeFilterSet(options.filters).toString('utf8') }),
      });

      const settled = await exchange(
        wire,
        buildFrame(FrameKind.Hello, 0n, greeting),
        timeoutMs,
        (header, body) => {
          if (header.kind === FrameKind.Error) {
            const refusal = parseRefusal(body);
            throw new ServerError(refusal.code, refusal.detail);
          }
          if (header.kind === FrameKind.Challenge) {
            const challenge = parseChallenge(body);
            // TCP presents no certificate, so there is nothing to bind a proof to. The key still
            // never crosses the wire.
            const transcript: Transcript = {
              keyRef: reference,
              clientNonce,
              serverNonce: challenge.serverNonce,
              binding: Buffer.alloc(32),
            };
            if (!verifyServer(transcript, key, challenge.proof)) {
              // Either the peer does not hold this key, or something is sitting between the two
              // ends presenting itself as the node. Both mean the connection must not continue,
              // and nothing has been given away: no proof of ours has been sent yet.
              throw new ProtocolError(
                'the node did not prove it holds this key; the connection is not to the node it ' +
                  'claims to be',
              );
            }
            return buildFrame(
              FrameKind.Prove,
              0n,
              // The subscriber's proof, which authenticates this side to the node.
              clientProof(transcript, key),
            );
          }
          if (header.kind === FrameKind.HelloAck) return null;
          // Anything other than a challenge here means the peer skipped proving it holds the key.
          // Accepting that would make the whole exchange optional — a server that simply never
          // challenges would be trusted, which is precisely what this replaces.
          throw new ProtocolError(`expected a challenge, got frame kind ${header.rawKind}`);
        },
      );

      if (settled.header.kind !== FrameKind.HelloAck) {
        throw new ProtocolError(
          `expected a hello ack, got frame kind ${settled.header.rawKind}`,
        );
      }
      const ack = parseHelloAck(settled.payload);
      if (ack.protocolVersion !== PROTOCOL_VERSION) {
        throw new ProtocolError(
          `the node speaks protocol version ${ack.protocolVersion}, this build speaks ` +
            `${PROTOCOL_VERSION}`,
        );
      }
      if (ack.codec !== Codec.Zstd) {
        throw new ProtocolError(
          `the node negotiated ${ack.codec}, but this client requires zstd; the node has zstd ` +
            'disabled',
        );
      }

      return new AuraShredsClient(
        wire,
        ack,
        options.maxMessageBytes ?? DEFAULT_MAX_MESSAGE_BYTES,
        settled.rest,
      );
    } catch (err) {
      wire.close();
      throw err;
    }
  }

  /** Streams the node actually granted — the intersection of what was asked and what the key allows. */
  get granted(): number {
    return this.ack.granted;
  }

  /** This connection's node-assigned id, which the operator's logs are keyed by. */
  get sessionId(): bigint {
    return this.ack.sessionId;
  }

  /** How often the node pings an idle connection. */
  get keepaliveMs(): number {
    return this.ack.keepaliveMs;
  }

  /** Compressed bytes received. */
  get wireBytes(): bigint {
    return this.wire;
  }

  /** Bytes after decompression. Against {@link wireBytes}, this is the achieved ratio. */
  get decodedBytes(): bigint {
    return this.decoded;
  }

  /** Frames dropped because this client could not keep up. */
  get gaps(): bigint {
    return this.gapCount;
  }

  /**
   * Replaces the node-side filter.
   *
   * Returns once the request is written, not once it is in force: the node applies it
   * asynchronously and confirms with a `filter-ack` event. Frames already in flight still arrive
   * under the previous filter, so a consumer that needs certainty should wait for the ack.
   */
  setFilter(spec: object): void {
    this.setFilters([{ spec }]);
  }

  /**
   * Replaces this connection's filters with a named set, up to sixteen.
   *
   * Every transaction says which of them it matched — see the `matched` field on the event — so one
   * connection can carry several interests and still tell them apart on arrival. The set is
   * accepted or refused together, so a connection never ends up holding part of what was asked for.
   */
  setFilters(filters: NamedFilter[]): void {
    this.socket.write(buildFrame(FrameKind.SetFilter, 0n, encodeFilterSet(filters)));
  }

  /** Sends a liveness probe. The node answers with a `pong` event. */
  ping(): void {
    this.socket.write(buildFrame(FrameKind.Ping, 0n, Buffer.alloc(0)));
  }

  /** Closes the connection. The iterator ends. */
  close(): void {
    this.socket.close();
  }

  /**
   * Waits for the next event, leaving the connection open.
   *
   * Use this when you need to read until something specific happens and then carry on — waiting for
   * a `filter-ack` before trusting the filter, say. Doing that with `for await` and a `break`
   * closes the connection, which is right for "I am done" and wrong for "I am done waiting".
   *
   * Rejects if the connection failed, and resolves to `null` once it has closed.
   */
  next(): Promise<AuraShredsEvent | null> {
    const ready = this.queue.shift();
    if (ready !== undefined) {
      this.drained();
      return Promise.resolve(ready);
    }
    if (this.failure !== null) return Promise.reject(this.failure);
    if (this.finished) return Promise.resolve(null);
    return new Promise((resolve, reject) => {
      this.waiter = (result) => resolve(result.done ? null : result.value);
      this.rejecter = reject;
    });
  }

  [Symbol.asyncIterator](): AsyncIterator<AuraShredsEvent> {
    return {
      next: (): Promise<IteratorResult<AuraShredsEvent>> => {
        const ready = this.queue.shift();
        if (ready !== undefined) {
          this.drained();
          return Promise.resolve({ value: ready, done: false });
        }
        if (this.failure !== null) return Promise.reject(this.failure);
        if (this.finished) return Promise.resolve({ value: undefined, done: true });
        return new Promise((resolve, reject) => {
          this.waiter = resolve;
          this.rejecter = reject;
        });
      },
      return: (): Promise<IteratorResult<AuraShredsEvent>> => {
        this.close();
        return Promise.resolve({ value: undefined, done: true });
      },
    };
  }

  private emit(event: AuraShredsEvent): void {
    const waiter = this.waiter;
    this.waiter = null;
    this.rejecter = null;
    if (waiter) {
      waiter({ value: event, done: false });
      return;
    }
    this.queue.push(event);
    // Nobody is waiting and the backlog has grown, so stop reading rather than buffering the
    // firehose. Two things depend on this. Memory: an unbounded queue is a client that dies of the
    // stream it could not keep up with, and on a busy node that is seconds away. And honesty: the
    // node decides what a subscriber which cannot keep up is owed — it drops the oldest frames and
    // sends a `Lag` naming the count — but only if it can *see* the client falling behind. Draining
    // the socket into memory hides that, so the client silently accumulates stale events while the
    // node believes it is keeping up.
    if (!this.stopped && this.queue.length >= MAX_BACKLOG) {
      this.stopped = true;
      this.socket.pause();
    }
  }

  /** Resumes reading once the consumer has taken enough of the backlog to be worth refilling. */
  private drained(): void {
    if (this.stopped && this.queue.length <= RESUME_BACKLOG) {
      this.stopped = false;
      this.socket.resume();
    }
  }

  private fail(reason: unknown): void {
    if (this.failure !== null || this.finished) return;
    this.failure = reason;
    const rejecter = this.rejecter;
    this.waiter = null;
    this.rejecter = null;
    if (rejecter) rejecter(reason);
  }

  private finish(): void {
    if (this.finished) return;
    this.finished = true;
    const waiter = this.waiter;
    this.waiter = null;
    this.rejecter = null;
    if (waiter) waiter({ value: undefined, done: true });
  }

  private onData(chunk: Buffer): void {
    this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
    try {
      this.drain();
    } catch (err) {
      this.fail(err);
      this.socket.close();
    }
  }

  /** Pulls every whole frame out of the buffer. */
  private drain(): void {
    let at = 0;
    while (this.buffer.length - at >= FRAME_HEADER_LEN) {
      const header = parseFrameHeader(this.buffer, at);
      // Refused on the number rather than after buffering up to it. Checking only what a compressed
      // body expands into would leave this setting with no effect at all on an uncompressed frame,
      // which is exactly the case someone lowering it is trying to bound.
      if (header.len > this.maxMessageBytes) {
        throw new ProtocolError(
          `the node sent a ${FrameKind[header.kind] ?? header.rawKind} frame of ${header.len} ` +
            `bytes, and this connection accepts at most ${this.maxMessageBytes}`,
        );
      }
      const end = at + FRAME_HEADER_LEN + header.len;
      if (this.buffer.length < end) break;
      const payload = this.buffer.subarray(at + FRAME_HEADER_LEN, end);
      at = end;

      this.wire += BigInt(FRAME_HEADER_LEN + header.len);
      const body = header.compressed ? this.inflate(payload, header.codec) : payload;
      this.decoded += BigInt(body.length);

      // A sequence gap means the node dropped frames for this connection; it is reported by the
      // Lag frame too, but counting here catches a gap even if that frame is itself lost.
      if (this.lastSeq !== null && header.seq > this.lastSeq + 1n) {
        this.gapCount += header.seq - this.lastSeq - 1n;
      }
      this.lastSeq = header.seq;

      const event = this.decode(header, body);
      if (event) this.emit(event);
    }
    this.buffer = at === 0 ? this.buffer : Buffer.from(this.buffer.subarray(at));
  }

  private inflate(payload: Buffer, codec: Codec): Buffer {
    if (codec !== Codec.Zstd) {
      throw new ProtocolError(`the node sent ${Codec[codec] ?? codec}, which was never offered`);
    }
    return zstdDecompressSync(payload, { maxOutputLength: this.maxMessageBytes });
  }

  private decode(header: FrameHeader, body: Buffer): AuraShredsEvent | null {
    const { seq } = header;
    switch (header.kind) {
      case FrameKind.Transaction:
        return {
          type: 'transaction',
          seq,
          transaction: Transaction.read(body),
          matched: header.matched,
        };
      case FrameKind.Entry:
        return { type: 'entry', seq, entry: parseEntry(body) };
      case FrameKind.SlotStart:
        return { type: 'slot-start', seq, slot: parseSlotStart(body) };
      case FrameKind.SlotEnd:
        return { type: 'slot-end', seq, slot: parseSlotEnd(body) };
      case FrameKind.Duplicate:
        return { type: 'duplicate', seq, duplicate: parseDuplicate(body) };
      case FrameKind.RawShred:
        return { type: 'raw-shred', seq, shred: parseRawShred(body) };
      case FrameKind.Lag: {
        const lag = parseLag(body);
        this.gapCount += lag.dropped;
        this.lastSeq = lag.resumeSeq - 1n;
        return { type: 'lag', seq, lag };
      }
      case FrameKind.FilterAck:
        return { type: 'filter-ack', seq, ack: parseFilterAck(body) };
      case FrameKind.Ping:
        // Answered here so a consumer that is slow to iterate is not disconnected for being idle.
        this.socket.write(buildFrame(FrameKind.Pong, 0n, Buffer.alloc(0)));
        return { type: 'ping', seq };
      case FrameKind.Pong:
        return { type: 'pong', seq };
      case FrameKind.Error: {
        const refusal = parseRefusal(body);
        this.fail(new ServerError(refusal.code, refusal.detail));
        this.socket.close();
        return null;
      }
      default:
        return { type: 'other', seq, kind: header.rawKind, payload: Buffer.from(body) };
    }
  }
}

/**
 * Writes one frame and reads the frames the handshake needs.
 *
 * Used for the handshake, before the streaming loop takes over. Anything that arrived past the
 * settled frame is handed back rather than dropped: a reply and the first stream bytes can land in
 * one read.
 *
 * `respond` is called with each frame in turn and returns the bytes to send next, or `null` when
 * the exchange is finished.
 */
function exchange(
  wire: Wire,
  request: Buffer,
  timeoutMs: number,
  respond: (header: FrameHeader, payload: Buffer) => Buffer | null,
): Promise<{ header: FrameHeader; payload: Buffer; rest: Buffer }> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    let settled = false;
    const finish = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };
    const timer = setTimeout(
      () => finish(() => reject(new ProtocolError(`handshake timed out after ${timeoutMs}ms`))),
      timeoutMs,
    );

    wire.onError((err) => finish(() => reject(err)));
    wire.onClose(() =>
      finish(() => reject(new ProtocolError('the node closed the connection during the handshake'))),
    );
    const onChunk = (chunk: Buffer): void => {
      if (settled) return;
      // Always concatenated rather than aliased: this runs once per connection, and aliasing a
      // chunk the transport may reuse would be a subtle way to corrupt the handshake.
      buffer = Buffer.concat([buffer, chunk]);
      // A reply and the next frame can land in one chunk, so every whole buffered frame is
      // processed here rather than just the first.
      while (!settled && buffer.length >= FRAME_HEADER_LEN) {
        let header: FrameHeader;
        try {
          header = parseFrameHeader(buffer);
        } catch (err) {
          finish(() => reject(err));
          return;
        }
        // Bounded on its own: everything here comes from a peer that has proved nothing yet.
        if (header.len > 64 * 1024) {
          finish(() =>
            reject(
              new ProtocolError(
                `the node sent a ${FrameKind[header.kind] ?? header.rawKind} frame of ` +
                  `${header.len} bytes during the handshake, and one may be at most ${64 * 1024}`,
              ),
            ),
          );
          return;
        }
        const end = FRAME_HEADER_LEN + header.len;
        if (buffer.length < end) return;
        const payload = buffer.subarray(FRAME_HEADER_LEN, end);
        let next: Buffer | null;
        try {
          next = respond(header, payload);
        } catch (err) {
          finish(() => reject(err));
          return;
        }
        if (next === null) {
          finish(() => resolve({ header, payload, rest: buffer.subarray(end) }));
          return;
        }
        // Consumed; whatever follows belongs to the next frame.
        buffer = Buffer.from(buffer.subarray(end));
        wire.write(next);
      }
    };
    wire.onData(onChunk);

    wire.write(request);
    wire.resume();
  });
}

export { ProtocolError, ServerError } from "./failures.js";
export { TransportError } from "./failures.js";
export { ALL_STREAMS, Codec, CodecBit, ErrorCode, FrameKind, Stream, Verification } from './frames.js';
export {
  parseFrameHeader,
  buildFrame,
  FRAME_HEADER_LEN,
  MAX_FRAME_PAYLOAD,
  PROTOCOL_VERSION,
  type FrameHeader,
} from './frames.js';
export {
  encodeFilterSet,
  encodeHello,
  encodeProve,
  parseChallenge,
  parseFilterAck,
  parseHelloAck,
  parseLag,
  parseRefusal,
  HELLO_ACK_LEN,
  type Challenge,
  type FilterAck,
  type Hello,
  type HelloAck,
  type Lag,
  type NamedFilter,
} from './control.js';
export {
  parseDuplicate,
  parseEntry,
  parseRawShred,
  parseSlotEnd,
  parseSlotStart,
  DUPLICATE_SIZE,
  ENTRY_SIZE,
  RAW_SHRED_HEADER_SIZE,
  SLOT_END_SIZE,
  SLOT_START_SIZE,
  type Duplicate,
  type Entry,
  type RawShred,
  type SlotEnd,
  type SlotStart,
} from './records.js';
export {
  Transaction,
  TxFlag,
  INSTRUCTION_ENTRY_LEN,
  LOOKUP_ENTRY_LEN,
  MESSAGE_VERSION_LEGACY,
  TX_HEADER_LEN,
  type AddressLookup,
  type Instruction,
} from './tx.js';
export { connectTcp, type Wire } from './socket.js';
export * as handshake from './auth.js';
