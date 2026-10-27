# Protocol

The wire contract, for anyone writing a client in a language the SDK does not cover. If you use the
SDK, you do not need any of this.

The protocol version is `1`. Within version 1, the framing, message layouts and field offsets below
do not change: a client built today keeps working against later nodes. All integers are
little-endian. The transport is TCP.

The SDK under [`sdk/`](../sdk) is the reference implementation, and
[`sdk/fixtures`](../sdk/fixtures) holds real frames produced by the node's own encoders, with a
`manifest.json` stating every field. Test your decoder against them.

## Frames

Every message is a 16-byte header and a payload:

```text
 0  u32  len       payload bytes that follow
 4  u8   kind
 5  u8   flags     bits 0..1: codec of the body; bit 2: the body is compressed
 6  u16  matched   transactions: bitmask of the named filters matched. Zero elsewhere
 8  u64  seq       per connection, monotonic
16       payload
```

| Kind | Name | Direction |
|---|---|---|
| 1 | Transaction | node → you |
| 2 | Entry | node → you |
| 3 | SlotStart | node → you |
| 4 | SlotEnd | node → you |
| 5 | Duplicate | node → you |
| 6 | RawShred | node → you |
| 7 | Lag | node → you |
| 8 | Reserved | |
| 9 | Hello | you → node |
| 10 | HelloAck | node → you |
| 11 | FilterAck | node → you |
| 12 | Error | node → you |
| 13 | Ping | both |
| 14 | Pong | both |
| 15 | SetFilter | you → node |
| 16 | Challenge | node → you |
| 17 | Prove | you → node |

**Treat an unknown kind as skippable, not fatal.** Read `len`, skip the payload, carry on. New frame
types may be added, and a client that fails on one it does not know breaks the day that happens.

Codecs: `0` uncompressed, `2` zstd. A body that did not shrink is sent uncompressed even on a zstd
connection, so check bit 2 on every frame rather than assuming the negotiated codec.

### Size limits

`len` is chosen by the sender, so check it before allocating, not after.

| What | Limit |
|---|---|
| Any frame payload | 16 MiB |
| A filter document | 256 KiB |
| Any frame during the handshake | 64 KiB |

The last limit matters: a challenge or a refusal comes from a peer that has proved nothing yet, and
a client that allowed 16 MiB there would let any address it dials cost it that much for the price of
a header. Apply your own maximum to what a compressed body expands into as well as to the frame.

## Handshake

```text
you  → node   Hello       streams, codecs, a reference to your key, your nonce, an optional filter
node → you    Challenge   the node's nonce, and its proof that it holds your key
you            verify the node's proof; stop if it is wrong
you  → node   Prove       your proof
node → you    HelloAck    or Error, then the stream
```

Your secret never crosses the wire, and the node proves itself first, so you learn whether you are
talking to a node that holds your key before you have sent anything that depends on it.

### Hello

```text
 0  u16   protocol version (1)
 2  u32   streams wanted (see Streams below)
 6  u8    codecs you can decode: bit 0 uncompressed, bit 2 zstd
 7  u8    padding, zero
 8  [32]  key reference
40  [32]  client nonce: 32 fresh random bytes
72  u32   filter length          ┐ optional: present only when
76  ...   filter document (JSON) ┘ you send a filter
```

A Hello that stops after the client nonce carries no filter. One that stops partway through the
length, or declares a length it does not deliver, is refused as truncated.

**Key reference**: `SHA-256("aura-shreds/key-ref/v1" ‖ secret)`, where `secret` is the UTF-8 bytes
of your secret exactly as written.

### Challenge and Prove

Challenge: the node's nonce (32 bytes), then the node's proof (32 bytes). Prove: your proof
(32 bytes).

Both proofs are HMAC-SHA-256 keyed with your secret, over a domain string followed by the
transcript:

```text
transcript = key reference ‖ client nonce ‖ node nonce ‖ 32 zero bytes
node proof = HMAC(secret, "aura-shreds/server-proof/v1" ‖ transcript)
your proof = HMAC(secret, "aura-shreds/client-proof/v1" ‖ transcript)
```

Compare the node's proof in constant time. If it does not match, close the connection without
sending yours: the peer does not hold your key.

### HelloAck

```text
 0  u16  protocol version
 2  u32  streams granted
 6  u64  session id
14  u8   codec chosen: 0 uncompressed, 2 zstd
15  u8   reserved
16  u16  keepalive interval, in milliseconds
```

**Check the granted streams.** They are the intersection of what you asked for and what your key
allows, and a stream you asked for but were not granted is silently absent.

### Error

```text
 0  u16  code
 2  u16  detail length
 4  ...  detail, UTF-8
```

| Code | Name |
|---|---|
| 1 | Unauthorized |
| 2 | Forbidden |
| 3 | TooSlow |
| 4 | RateLimited |
| 5 | BadRequest |
| 6 | Shutdown |
| 7 | UnsupportedVersion |

An Error can arrive in place of a Challenge or HelloAck, or at any time on an open connection. The
node closes the connection after sending it.

## Streams

| Stream | Bit |
|---|---|
| `transactions` | `1 << 0` |
| `entries` | `1 << 1` |
| `slot_events` | `1 << 2` |
| `duplicates` | `1 << 3` |
| `raw_shreds` | `1 << 4` |
| `votes` | `1 << 6` |

See [Streams](streams.md) for what each carries.

## Transaction

A fixed 104-byte header, then sections in a fixed order. Every section starts 8-byte aligned, so
fields can be read at their offsets without parsing.

```text
  0  u64  slot                    64  u32  fec_set_index
  8  u64  parent_slot             68  u32  entry_index
 16  u64  rx_ts_ns                72  u32  tx_index
 24  u64  emit_ts_ns              76  u32  instruction_bytes_len
 32  [32] leader                  80  u32  lookup_bytes_len
                                  84  u32  raw_tx_len
                                  88  u16  source_id
                                  90  u16  flags
                                  92  u16  account_count
                                  94  u16  instruction_count
                                  96  u8   signature_count
                                  97  u8   message_version (0xff = legacy)
                                  98  u8   lookup_count
                                  99  u8   required_signatures
                                 100  u8   readonly_signed
                                 101  u8   readonly_unsigned
                                 102  u16  reserved
104       signatures          signature_count × 64
          account_keys        account_count × 32
          recent_blockhash    32
          instruction_table   instruction_count × 16
          instruction_bytes   instruction_bytes_len, padded to 8
          lookup_table        lookup_count × 40
          lookup_bytes        lookup_bytes_len, padded to 8
          raw_tx              raw_tx_len, only when flags bit 2 is set
```

**Flags:**

| Bit | Meaning |
|---|---|
| 0 | A simple vote |
| 1 | Verified |
| 2 | `raw_tx` is appended |
| 3 | Recovered: the shred set was rebuilt from parity |
| 4 | `leader` is set |
| 5..6 | When bit 1 is clear, why: 0 verification disabled, 1 unknown leader, 2 stale schedule |

**Instruction table entry** (16 bytes): program index (`u8`), padding (`u8`), accounts offset
(`u16`), accounts length (`u16`), padding (`u16`), data offset (`u32`), data length (`u32`). Offsets
are relative to the start of `instruction_bytes`.

**Lookup table entry** (40 bytes): table account (32 bytes), writable indexes offset and length
(`u16` each), readonly indexes offset and length (`u16` each). Offsets are relative to the start of
`lookup_bytes`.

Reject an entry whose offset and length reach past its region.

`rx_ts_ns` and `emit_ts_ns` come from the node's monotonic clock: their difference is time spent in
the node, and neither is comparable to your own clock.

## Other records

Fixed-size records with no variable tail. Each may grow at the end in a later version, so accept a
longer body than you expect.

**SlotStart** (64 bytes): slot `u64` @0, parent slot `u64` @8, leader `[32]` @16, arrival time
`u64` @48, source `u16` @56, shred version `u16` @58, flags `u8` @60 (bit 0: parent slot present,
bit 1: leader present).

**SlotEnd** (48 bytes): slot `u64` @0, parent slot `u64` @8, data shreds `u32` @16, FEC sets
`u32` @20, recovered sets `u32` @24, missing shreds `u32` @28, end time `u64` @32, flags `u8` @40
(bit 0: complete).

**Entry** (88 bytes): slot `u64` @0, parent slot `u64` @8, arrival time `u64` @16, hash count
`u64` @24, transaction count `u64` @32, PoH hash `[32]` @40, FEC set index `u32` @72, entry index
`u32` @76, verification `u8` @80 (0 verified, 1 disabled, 2 unknown leader, 3 stale schedule).

**Duplicate** (160 bytes): slot `u64` @0, index `u32` @8, first source `u16` @12, second source
`u16` @14, detection time `u64` @16, data shred `u8` @24 (0 = coding), first signature `[64]` @32,
second signature `[64]` @96.

**RawShred** (32-byte header, then the shred): slot `u64` @0, index `u32` @8, FEC set index `u32`
@12, arrival time `u64` @16, source `u16` @24, kind `u8` @26 (1 = coding, anything else data), then
the shred exactly as it arrived from @32.

**Lag** (16 bytes): frames dropped `u64` @0, `seq` the stream resumes at `u64` @8.

## Filters

**SetFilter**: the payload is the filter document, JSON:

```json
{"filters": [{"name": "jupiter", "spec": {"programs": {"include": ["…"]}}}]}
```

The same document can go in the Hello instead, which is better: see [Filters](filters.md).

**FilterAck**:

```text
0  u8   accepted (0 or 1)
1  u8   reserved
2  u32  cost
6  u16  detail length
8  ...  detail, UTF-8
```

## Keepalive

The node sends Ping on an idle connection, at the interval given in the HelloAck. Answer each with
Pong (empty payload). You may send Ping too; the node answers with Pong.
