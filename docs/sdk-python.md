# Python SDK

Python 3.14 or newer, where zstd is in the standard library. No dependencies. Built on asyncio.

## Install

```bash
pip install "aura-shreds-sdk @ git+https://github.com/Aura-Boost-io/aura-shreds-docs@v0.1.0#subdirectory=sdk/python"
```

The source is in [`sdk/python`](../sdk/python).

## Connect

```python
import os
from aura_shreds_sdk import Client, NamedFilter, Stream

client = await Client.connect(
    host="ams.auraboost.wtf",
    port=9000,
    secret=os.environ["AURA_SHREDS_SECRET"],
    streams=Stream.TRANSACTIONS | Stream.SLOT_EVENTS,
    filters=[
        NamedFilter(
            name="jupiter",
            spec={"programs": {"include": ["JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"]}},
        ),
    ],
)

# Check what was granted, not what was asked for.
assert client.granted & Stream.TRANSACTIONS
```

| Argument | Meaning |
|---|---|
| `host`, `port` | The endpoint. Required, keyword-only |
| `secret` | Your secret, as `str` or `bytes`. A `str` is sent as its UTF-8 bytes exactly as written |
| `streams` | Streams to ask for. Defaults to everything your key allows |
| `filters` | Named filters installed before the first frame |
| `connect_timeout` | Handshake timeout in seconds. Default 10 |
| `max_message_bytes` | Largest message accepted, compressed or not. Default 16 MiB |

The connection is always zstd-compressed. The SDK refuses a node that would send it uncompressed.

The client is an async context manager, so `async with await Client.connect(...) as client:` closes
it for you.

## Read events

```python
async for event in client:
    match event.type:
        case "transaction":
            tx = event.transaction
            print(tx.slot, tx.signature.hex() if tx.signature else None, event.matched)
            for ix in tx.instructions():
                ix.program_id_index, ix.accounts, ix.data
        case "slot-start":
            print("slot", event.slot.slot)
        case "slot-end":
            if not event.slot.complete:
                pass  # the tail of this slot was never seen
        case "lag":
            # Never ignore this one: it is the only signal that frames were lost.
            print(f"lost {event.lag.dropped} frames, resuming at {event.lag.resume_seq}")
        case "filter-ack":
            print("filter", "accepted" if event.ack.accepted else f"refused: {event.ack.detail}")
```

| `type` | Event class | Payload |
|---|---|---|
| `transaction` | `TransactionEvent` | `transaction`, and `matched`: a bitmask of the named filters it matched |
| `entry` | `EntryEvent` | `entry` |
| `slot-start`, `slot-end` | `SlotStartEvent`, `SlotEndEvent` | `slot` |
| `duplicate` | `DuplicateEvent` | `duplicate`: leader equivocation, with both conflicting signatures |
| `raw-shred` | `RawShredEvent` | `shred`. Only with `Stream.RAW_SHREDS` |
| `lag` | `LagEvent` | `lag`: `dropped` and `resume_seq` |
| `filter-ack` | `FilterAckEvent` | `ack`: `accepted`, `cost`, `detail` |
| `ping`, `pong` | `PingEvent`, `PongEvent` | Nothing. Pings are answered for you |
| `unknown` | `UnknownEvent` | `kind` and `payload`: a frame type this version does not know |

Every event also carries its `seq`. To read one event at a time, use `await client.next_event()`.

## Transactions

| Member | Returns |
|---|---|
| `slot`, `parent_slot` | Slot numbers |
| `entry_index`, `tx_index`, `fec_set_index` | Position within the slot |
| `signature`, `signatures()` | The first signature (the transaction's ID), and all of them |
| `account_keys()`, `account_key(i)`, `account_count` | Static account keys. Index 0 is the fee payer |
| `recent_blockhash` | 32 bytes |
| `instructions()`, `instruction(i)`, `instruction_count` | `program_id_index`, `accounts`, `data` |
| `lookups()`, `lookup_count` | Address lookup table references, unresolved |
| `message_version` | `0xff` for legacy, otherwise the version |
| `required_signatures`, `readonly_signed`, `readonly_unsigned` | The message header |
| `is_vote` | Whether it is a simple vote |
| `verification` | `Verification.VERIFIED`, `DISABLED`, `UNKNOWN_LEADER` or `STALE_SCHEDULE` |
| `recovered` | Whether its shreds were rebuilt from parity |
| `leader` | The slot's leader, when known |
| `pipeline_ns`, `rx_ts_ns`, `emit_ts_ns` | Latency inside Aura. See [Delivery](delivery.md#latency) |
| `raw_tx` | The serialized transaction, when the node includes it |

Members written with `()` are methods; the rest are properties. Keys, signatures and hashes are raw
`bytes`. Encode them to base58 with the library of your choice.

## Change filters

```python
await client.set_filters([NamedFilter(name="no-votes", spec={"is_vote": {"value": False}})])
```

`set_filters` returns once the request is written, not once it is in force. Wait for the
`filter-ack` event before assuming the stream has narrowed. See
[Filters](filters.md#changing-filters-on-an-open-connection).

## Other members

| Member | Use |
|---|---|
| `granted` | Streams the node granted |
| `session_id` | The node's ID for this connection. Quote it when reporting a problem |
| `wire_bytes`, `message_bytes` | Bytes received, before and after decompression |
| `ping()` | Probe the connection |
| `close()` | Close the connection |

## Errors

| Class | Meaning |
|---|---|
| `ServerError` | The node refused the connection or closed it with a reason: `code` and `detail` |
| `TransportError` | The connection could not be made, or failed while open |
| `ProtocolError` | Something arrived that could not be read |

See [Troubleshooting](troubleshooting.md).
