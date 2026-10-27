# Filters

Filters narrow the `transactions` stream on the node, before anything is encoded or sent. A narrow
filter reduces the node's work as well as your bandwidth.

## Filter at connect

Pass your filters when you connect (`filters` in every SDK, `--account`, `--program` or
`--filter-file` in the CLI). The node installs them before the connection joins the stream, so
there is no moment at which you are connected and unfiltered.

A filter that does not compile, or that exceeds your key's budgets, **refuses the connection** with
a `BadRequest` naming the problem. It never falls back to an unfiltered stream: that would send you
exactly the traffic you were trying to avoid, without saying so.

## Named filters

One connection carries up to **16 named filters**, and every transaction says which of them it
matched. That lets one connection serve several interests and still tell them apart on arrival.

```json
{"filters": [
  {"name": "jupiter", "spec": {"programs": {"include": ["JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"]}}},
  {"name": "my-desk", "spec": {"and": [
    {"is_vote": {"value": false}},
    {"accounts": {"include": ["…"], "exclude": ["…"]}}
  ]}}
]}
```

A transaction matching several filters arrives **once**, with every match recorded in its `matched`
mask: bit `i` is the filter at index `i` of the set you submitted.

The SDKs build this document for you from a list of `{name, spec}` pairs.

## The filter language

| Filter | Shape | Matches |
|---|---|---|
| `all` | `"all"` | Everything |
| `none` | `"none"` | Nothing |
| `is_vote` | `{"is_vote": {"value": bool}}` | Votes, or non-votes |
| `verified` | `{"verified": {"value": bool}}` | By [verification verdict](delivery.md#verification) |
| `accounts` | `{"accounts": {"include": […], "exclude": […], "required": […]}}` | By account key |
| `programs` | `{"programs": { … same … }}` | By invoked program |
| `fee_payers` | `{"fee_payers": { … same … }}` | By fee payer |
| `signature` | `{"signature": "<base58>"}` | One transaction |
| `slot_range` | `{"slot_range": {"from": u64 or null, "to": u64 or null}}` | By slot |
| `data_prefix` | `{"data_prefix": {"program": "<base58>" or null, "prefix": [byte, …]}}` | Instructions whose data starts with these bytes |
| `and`, `or` | `{"and": [filter, …]}` | Combinations |
| `not` | `{"not": filter}` | The opposite |

### Key sets

`accounts`, `programs` and `fee_payers` each take three independent sets. Any of them may be left
out, and a missing set is no constraint, so `exclude` on its own is a filter.

| Set | Meaning |
|---|---|
| `include` | At least one of these is present |
| `exclude` | None of these is present |
| `required` | Every one of these is present |

Sets of a few thousand keys are expected and cost nothing extra per transaction: the node indexes
every subscriber's keys together, so its work depends on the transaction, not on how many keys you
named.

### Address lookup tables

Accounts reached through an **address lookup table** are not matched. Resolving them needs account
state a shred stream does not have, so a filter naming an account misses any transaction that
reaches it through a table.

## Changing filters on an open connection

Every SDK can replace the filter set on a live connection (`submit_filters`, `setFilters`,
`set_filters`). The new set replaces the old one whole, and is accepted or refused together.

The node answers with a `filter-ack` event carrying `accepted`, a `cost`, and on refusal a
`detail`. **A filter is in force when its acknowledgement arrives, not when you send it.** Frames
already encoded still arrive under the previous filter, so a few unwanted ones after you submit are
expected. A refused set leaves the previous one in force.

Until a connection's first filter is acknowledged, it is unfiltered. That is why filtering at
connect is better: there is no such window.

- An empty list means no filtering, which is the full stream.
- To receive nothing, submit `"none"`.

## Budgets

Each key has two filter budgets, counted across all filters on a connection:

| Budget | Default | Spent by |
|---|---|---|
| Evaluation cost | 1,000 | Combinators, and `data_prefix`, which walks every instruction |
| Named keys | 100,000 | Every key in every `include`, `exclude` and `required` set |

A refusal reports the measured value, so you see by how much you were over. Ask Aura if you need
more.
