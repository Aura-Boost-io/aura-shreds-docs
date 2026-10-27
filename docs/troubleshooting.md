# Troubleshooting

## Refusals

When the node refuses a connection or closes one, it sends a code and a detail. The SDKs raise it as
`Error::Rejected` (Rust) or `ServerError` (TypeScript, Python).

| Code | Meaning | What to do |
|---|---|---|
| `Unauthorized` (1) | The secret is wrong, or shred access is not enabled on the key | Check the secret. The two cases are deliberately indistinguishable |
| `Forbidden` (2) | None of the streams you asked for is granted to your key, or the key already has its maximum number of connections open (4 by default) | Read the detail. Close connections you no longer use, or ask Aura what your key grants |
| `TooSlow` (3) | Your client fell behind for too long | Consume faster, ask for fewer streams, or filter more narrowly |
| `BadRequest` (5) | A filter did not compile or exceeded a budget, or the handshake was malformed or timed out | The detail names what was wrong |
| `UnsupportedVersion` (7) | The client speaks a protocol version the node does not | Update the SDK |

Codes 4 (`RateLimited`) and 6 (`Shutdown`) are reserved. A connection closed without a code, for
example when the node restarts, should simply be reopened after a short delay.

## The connection works but nothing arrives

- **A stream you asked for was not granted.** Compare the granted mask with what you asked for.
- **Your filter matches nothing.** Remember that accounts reached through an address lookup table
  are not matched.
- **You subscribed to `slot_events` only.** Transactions need `transactions`.

## Things that look like bugs but are not

**`lag` events.** Your client was not keeping up. The node dropped the oldest frames rather than
falling behind with you. See [Delivery](delivery.md#lag).

**Unwanted transactions just after changing a filter.** Frames already encoded still arrive under the
previous filter until the `filter-ack`. Filter at connect to avoid the window entirely.

**A later slot before an earlier one.** Order across slots is arrival order. Sort by `slot`,
`entry_index` and `tx_index`.

**`SlotEnd` with `complete = false`.** The slot's tail was never seen, usually because its leader
skipped the turn.

**A transaction marked `Unverified`.** Not an error frame: the transaction is delivered with its
verdict set. Check `verification` if authenticity matters to you.

**Account keys missing from a transaction.** Address lookup tables are not resolved, since that needs
account state a shred stream does not have. `lookups()` gives you the references to resolve
yourself.

**Signatures and keys are bytes, not strings.** Encode them to base58 yourself.

**Your latency figure does not match `pipeline_ns`.** `pipeline_ns` is time inside Aura only. Use
`aura-cli stats` to measure what you receive.

## Limits

| What | Limit |
|---|---|
| Connections per key | 4 |
| Named filters per connection | 16 |
| Filter evaluation cost per connection | 1,000 |
| Keys named across a connection's filters | 100,000 |
| A filter document | 256 KiB |
| Any frame | 16 MiB |

Ask Aura if you need more connections or higher filter limits.

## Reporting a problem

Include the session ID (`session_id()` in Rust, `sessionId` in TypeScript, `session_id` in Python,
or the `connected: session N` line from `aura-cli`), the time in UTC, and the error text.
