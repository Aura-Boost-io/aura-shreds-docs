# TypeScript SDK

Node 22.15 or newer, where zstd is built in. No runtime dependencies.

## Install

The package is attached to each [release](https://github.com/Aura-Boost-io/aura-shreds-docs/releases)
as a ready-built tarball:

```bash
npm install https://github.com/Aura-Boost-io/aura-shreds-docs/releases/download/v0.1.0/aura-shreds-sdk-0.1.0.tgz
```

It installs as `@aura-shreds/sdk` and ships its own type definitions. The source is in
[`sdk/typescript`](../sdk/typescript).

## Connect

```typescript
import { AuraShredsClient, Stream } from '@aura-shreds/sdk';

const client = await AuraShredsClient.connect({
  host: 'ams.auraboost.wtf',
  port: 9000,
  secret: process.env.AURA_SHREDS_SECRET!,
  streams: Stream.TRANSACTIONS | Stream.SLOT_EVENTS,
  filters: [
    { name: 'jupiter', spec: { programs: { include: ['JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4'] } } },
  ],
});

// Check what was granted, not what was asked for.
if ((client.granted & Stream.TRANSACTIONS) === 0) throw new Error('transactions not granted');
```

| Option | Meaning |
|---|---|
| `host`, `port` | The endpoint. Required |
| `secret` | Your secret. A string is sent as its UTF-8 bytes exactly as written, never decoded as hex or base64. Pass a `Buffer` if your secret is binary |
| `streams` | Streams to ask for. Defaults to everything your key allows |
| `filters` | Named filters installed before the first frame |
| `connectTimeoutMs` | Handshake timeout. Default 10 s |
| `maxMessageBytes` | Largest message accepted, compressed or not. Default 16 MiB |

The connection is always zstd-compressed. The SDK refuses a node that would send it uncompressed.

## Read events

The client is an async iterable:

```typescript
for await (const event of client) {
  switch (event.type) {
    case 'transaction': {
      const tx = event.transaction;
      console.log(tx.slot, tx.signature?.toString('hex'), event.matched);
      for (const ix of tx.instructions()) {
        void ix.programIdIndex, ix.accounts, ix.data;
      }
      break;
    }
    case 'slot-start': console.log('slot', event.slot.slot); break;
    case 'slot-end': if (!event.slot.complete) { /* the tail of this slot was never seen */ } break;
    // Never ignore this one: it is the only signal that frames were lost.
    case 'lag': console.warn(`lost ${event.lag.dropped} frames, resuming at ${event.lag.resumeSeq}`); break;
    case 'filter-ack': console.log('filter', event.ack.accepted ? 'accepted' : `refused: ${event.ack.detail}`); break;
  }
}
```

| `type` | Payload |
|---|---|
| `transaction` | `transaction`, and `matched`: a bitmask of the named filters it matched |
| `entry` | `entry` |
| `slot-start`, `slot-end` | `slot` |
| `duplicate` | `duplicate`: leader equivocation, with both conflicting signatures |
| `raw-shred` | `shred`. Only with `Stream.RAW_SHREDS` |
| `lag` | `lag`: `dropped` and `resumeSeq` |
| `filter-ack` | `ack`: `accepted`, `cost`, `detail` |
| `ping`, `pong` | Nothing. Pings are answered for you |
| `other` | `kind` and `payload`: a frame type this version does not know |

Every event also carries its `seq`.

Breaking out of `for await` closes the connection. To wait for one particular event and carry on
reading, use `await client.next()`, which leaves the connection open and returns `null` once it has
closed.

Transaction accessors return `Buffer` views into the received frame. Copy anything you keep past
the event with `Buffer.from(...)`.

## Transactions

| Accessor | Returns |
|---|---|
| `slot`, `parentSlot` | `bigint` |
| `entryIndex`, `txIndex`, `fecSetIndex` | Position within the slot |
| `signature`, `signatures()` | The first signature (the transaction's ID), and all of them |
| `accountKeys()`, `accountKey(i)`, `accountCount` | Static account keys. Index 0 is the fee payer |
| `recentBlockhash` | 32 bytes |
| `instructions()`, `instruction(i)`, `instructionCount` | `programIdIndex`, `accounts`, `data` |
| `lookups()`, `lookupCount` | Address lookup table references, unresolved |
| `messageVersion` | `0xff` for legacy, otherwise the version |
| `requiredSignatures`, `readonlySigned`, `readonlyUnsigned` | The message header |
| `isVote` | Whether it is a simple vote |
| `verification` | `'verified'`, `'disabled'`, `'unknown-leader'` or `'stale-schedule'` |
| `recovered` | Whether its shreds were rebuilt from parity |
| `leader` | The slot's leader, when known |
| `pipelineNs`, `rxTsNs`, `emitTsNs` | Latency inside Aura. See [Delivery](delivery.md#latency) |
| `rawTx` | The serialized transaction, when the node includes it |

Keys, signatures and hashes are raw bytes. Encode them to base58 with the library of your choice.

## Change filters

```typescript
client.setFilters([{ name: 'no-votes', spec: { is_vote: { value: false } } }]);
```

`setFilters` returns once the request is written, not once it is in force. Wait for the
`filter-ack` event before assuming the stream has narrowed. See
[Filters](filters.md#changing-filters-on-an-open-connection).

## Other members

| Member | Use |
|---|---|
| `granted` | Streams the node granted |
| `sessionId` | The node's ID for this connection. Quote it when reporting a problem |
| `gaps` | Frames lost to lag so far |
| `wireBytes`, `decodedBytes` | Bytes received, before and after decompression |
| `ping()` | Probe the connection |
| `close()` | Close the connection |

## Errors

| Class | Meaning |
|---|---|
| `ServerError` | The node refused the connection or closed it with a reason: `code` and `detail` |
| `TransportError` | The connection could not be made, or failed while open |
| `ProtocolError` | Something arrived that could not be read |

See [Troubleshooting](troubleshooting.md).
