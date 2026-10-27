# Streams

A connection carries any combination of the streams below. Your key grants a set; your client asks
for a subset; the node delivers the intersection. Streams are opt-in end to end: a frame nobody
asked for is never encoded, so asking only for what you read costs you nothing and saves the node
work.

| Stream | Bit | Carries | Rate |
|---|---|---|---|
| `transactions` | `1 << 0` | Fully decoded transactions | The firehose |
| `entries` | `1 << 1` | Each entry's PoH hash, hash count and transaction count | Tens per slot |
| `slot_events` | `1 << 2` | `SlotStart` and `SlotEnd` | About 2 per slot |
| `duplicates` | `1 << 3` | Leader equivocation, with both conflicting signatures | Rare, and important |
| `raw_shreds` | `1 << 4` | Every shred as it arrived, before verification or decoding | Highest of all |
| `votes` | `1 << 6` | Whether vote transactions are included in `transactions` | About half the firehose |

Bit `1 << 5` is reserved.

Which streams your key grants is set when shred access is enabled on it. If one you need is missing
from the granted mask, ask Aura.

## transactions

Every transaction Aura decoded, with its signatures, account keys, recent blockhash, instructions
and address lookup references. See the SDK guides for the accessors, and [Delivery](delivery.md)
for ordering and verification.

## votes

Not a separate stream: it decides whether vote transactions are included in `transactions`. Votes
are about half of mainnet traffic. If you do not want them, do not ask for `votes`, and the node
never encodes them for you at all. That is cheaper for both ends than filtering them out.

## slot_events

- **`SlotStart`**: the first shred of a slot arrived. Slot, parent slot (once known), leader (when
  known), shred version and arrival time.
- **`SlotEnd`**: the slot finished. Data shreds, FEC sets, how many sets were rebuilt from parity,
  how many shreds were never seen, and a `complete` flag.

`complete = false` means the slot was evicted before its last shred was seen. That is not an error,
since a leader may skip its turn, but anyone rebuilding the ledger needs to know the tail is missing.

## entries

One record per PoH entry: slot, PoH hash, hash count, FEC set and entry index, verification, and how
many transactions the entry claimed. `tx_count == 0` is a tick.

Entries carry no transaction bytes. The transactions travel on `transactions` with the same
`entry_index`, so taking both streams costs the bytes once, and comparing the claimed count with
what arrived tells you when a transaction is missing.

## duplicates

Raised when a leader signed two different shreds for the same slot and index. Both conflicting
signatures are delivered: which fork survives is not knowable at this layer.

## raw_shreds

Every shred, republished the instant it survives deduplication and before it is verified. That
ordering is the point: waiting for the signature check would cost the latency this stream exists to
save. Take it only if you run your own pipeline.

- **Nothing on it is claimed to be leader-signed.** Verify it yourself, or take `transactions`.
- **Not recovered.** A shred rebuilt from parity is not republished, so gaps are real losses.
- **Not filtered.** A shred is a fragment of an erasure set, not yet anything a filter can match.

It is a multiple of the `transactions` rate, since most fragments carry votes.
