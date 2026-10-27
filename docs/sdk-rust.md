# Rust SDK

Rust 1.85 or newer (edition 2024), on tokio.

## Install

```toml
[dependencies]
aura-shreds-sdk = { git = "https://github.com/Aura-Boost-io/aura-shreds-docs", tag = "v0.1.0" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

API reference: `cargo doc --open -p aura-shreds-sdk`.

## Connect

The shortest form takes the address and your secret, and subscribes to everything your key allows:

```rust
let mut client =
    aura_shreds_sdk::connect("ams.auraboost.wtf:9000", std::env::var("AURA_SHREDS_SECRET")?)
        .await?;
```

To choose streams or filter from the first frame, build a `Config`:

```rust
use aura_shreds_sdk::{Client, Config, NamedFilter, StreamMask};

let config = Config::new(std::env::var("AURA_SHREDS_SECRET")?)
    .streams(StreamMask(StreamMask::TRANSACTIONS | StreamMask::SLOT_EVENTS))
    .filters(&[NamedFilter {
        name: "jupiter",
        spec_json: r#"{"programs": {"include": ["JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"]}}"#,
    }]);
let mut client = Client::connect("ams.auraboost.wtf:9000", config).await?;

// Check what was granted, not what was asked for.
assert!(client.granted().contains(StreamMask::TRANSACTIONS));
```

`Config` also has `connect_timeout` (default 10 s) and `max_message_bytes` (default 16 MiB) fields.

The connection is always zstd-compressed. The SDK refuses a node that would send it uncompressed.

## Read events

```rust
use aura_shreds_sdk::Event;

loop {
    match client.next_event().await? {
        Event::Transaction { tx, matched } => {
            println!("{} {:?} filters {:?}", tx.slot(), tx.signature(), matched.indices().collect::<Vec<_>>());
            for ix in tx.instructions() {
                let _ = (ix.program_id_index, ix.accounts, ix.data);
            }
        }
        Event::SlotStart(start) => { let _ = start.slot; }
        Event::SlotEnd(end) => {
            if !end.complete { /* the tail of this slot was never seen */ }
        }
        Event::Entry(entry) => { let _ = entry.tx_count; }
        Event::Duplicate(report) => { /* leader equivocation */ }
        Event::RawShred(shred) => { /* only with StreamMask::RAW_SHREDS */ }
        // Never ignore this one: it is the only signal that frames were lost.
        Event::Lag(lag) => eprintln!("lost {} frames, resuming at {}", lag.dropped, lag.resume_seq),
        Event::FilterAck(ack) => { let _ = (ack.accepted, ack.cost); }
        // Required: `Event` is non-exhaustive, so new frame types arrive here instead of breaking
        // your build.
        _ => {}
    }
}
```

An event borrows the client's buffer and is valid until the next `next_event()` call. Copy anything
you keep.

Pings from the node are answered for you.

## Transactions

| Accessor | Returns |
|---|---|
| `slot()`, `parent_slot()` | Slot numbers |
| `entry_index()`, `tx_index()`, `fec_set_index()` | Position within the slot |
| `signature()`, `signatures()` | The first signature (the transaction's ID), and all of them |
| `account_keys()`, `account_key(i)`, `account_count()` | Static account keys. Index 0 is the fee payer |
| `recent_blockhash()` | 32 bytes |
| `instructions()`, `instruction(i)`, `instruction_count()` | Program index, account indices and data |
| `lookups()`, `lookup_count()` | Address lookup table references, unresolved |
| `message_version()` | `0xff` for legacy, otherwise the version |
| `required_signatures()`, `readonly_signed()`, `readonly_unsigned()` | The message header |
| `is_vote()` | Whether it is a simple vote |
| `verification()` | `Verified`, `Disabled`, `UnknownLeader` or `StaleSchedule` |
| `recovered()` | Whether its shreds were rebuilt from parity |
| `leader()` | The slot's leader, when known |
| `pipeline_ns()`, `rx_ts_ns()`, `emit_ts_ns()` | Latency inside Aura. See [Delivery](delivery.md#latency) |
| `raw_tx()` | The serialized transaction, when the node includes it |

Keys, signatures and hashes are raw bytes. Encode them to base58 with the crate of your choice.

## Change filters

```rust
client
    .submit_filters(&[NamedFilter { name: "no-votes", spec_json: r#"{"is_vote": {"value": false}}"# }])
    .await?;
```

`submit_filters` returns once the request is written, not once it is in force. The node confirms
with `Event::FilterAck`, and frames already in flight still arrive under the previous filter. See
[Filters](filters.md#changing-filters-on-an-open-connection).

## Other methods

| Method | Use |
|---|---|
| `granted()` | Streams the node granted |
| `session_id()` | The node's ID for this connection. Quote it when reporting a problem |
| `dropped()` | Frames lost to lag so far |
| `wire_bytes()`, `decoded_bytes()` | Bytes received, before and after decompression |
| `ping()` | Probe the connection. The answer arrives as `Event::Pong` |
| `close()` | Close the connection |

## Errors

Every failure is an `aura_shreds_sdk::Error`. `Error::Rejected { code, detail }` is the node
refusing the connection or closing it with a reason; the rest are network and protocol failures.
See [Troubleshooting](troubleshooting.md).
