# Delivery

## Sequence numbers

Every frame carries a `seq`: per connection, monotonic, starting from the handshake. There are no
acknowledgements and no retransmission.

## Lag

If your client falls behind, the node drops the **oldest** frames queued for you, never the newest,
and sends a `lag` event with how many were dropped and the `seq` the stream resumes at. A client that
stays too slow is disconnected.

**Do not ignore `lag`.** It is the only signal that your view has a hole in it. A gap in `seq` means
the same thing, and the SDKs count both (`dropped()` in Rust, `gaps` in TypeScript).

The SDKs stop reading from the socket when your code stops consuming events, so a slow consumer
shows up on the node as lag rather than as memory growing on your side.

## Ordering

- **Across slots, order is arrival order.** Slots complete when their shreds do, so a later slot can
  be delivered before an earlier one finishes. Order by `slot`, then `entry_index`, then `tx_index`,
  not by receipt.
- **Within a batch, order is kept**, but the transactions of one batch may arrive in parts as their
  bytes complete.
- **A `SlotEnd` with `complete = false`** means the end of the slot was never seen. Not an error: a
  leader may skip its turn.

## Verification

Every transaction carries a verdict:

| Verdict | Meaning |
|---|---|
| `Verified` | The leader's signature over the shred set's merkle root checked out, and this shred proved to that root |
| `Disabled` | The node is running with signature verification off |
| `UnknownLeader` | No leader is known for the slot |
| `StaleSchedule` | The node's leader schedule is behind |

Anything other than `Verified` is still delivered, as an ordinary transaction with that field set,
not as an error. **If your use depends on authenticity, check this field** and treat anything other
than `Verified` as untrusted. A transaction spanning two shred sets carries the weaker of their two
verdicts.

## Recovered transactions

`recovered` is set when the transaction's shred set was rebuilt from parity because some of its
shreds never arrived. The transaction is complete and correct; the flag tells you the network lost
part of it on the way.

## Latency

Each transaction carries two timestamps from Aura's monotonic clock:

- `rx_ts_ns`: when the first shred of its batch arrived.
- `emit_ts_ns`: when the transaction was encoded for you.

Their difference, `pipeline_ns`, is the time spent inside Aura. Neither timestamp is comparable to
your own wall clock. To measure what you actually receive, including the network and your own
client, run [`aura-cli stats`](cli.md#stats).

## Keepalive

The node pings an idle connection, and the SDKs answer for you. A connection that stops answering
is closed.

## Compression

The stream is zstd-compressed, which costs a few microseconds per message and cuts bandwidth to
about a third. A frame whose body did not shrink is sent uncompressed even on a compressed
connection; every SDK handles that per frame.
