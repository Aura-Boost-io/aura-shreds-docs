# aura-cli

A command-line client for checking a connection, watching the stream and measuring it from your
side.

## Install

`aura-cli` is a single static binary for Linux x86_64, attached to every
[release](https://github.com/Aura-Boost-io/aura-shreds-docs/releases).

```bash
curl -LO https://github.com/Aura-Boost-io/aura-shreds-docs/releases/latest/download/aura-cli-linux-x86_64.tar.gz
tar -xzf aura-cli-linux-x86_64.tar.gz
cd aura-cli-linux-x86_64 && sha256sum -c aura-cli.sha256
sudo install -m 755 aura-cli /usr/local/bin/aura-cli
```

On another platform, use one of the [SDKs](../README.md#documentation) instead.

## tail

Prints transactions as they arrive.

```bash
aura-cli tail --addr ams.auraboost.wtf:9000 --key KEY_ID --secret SECRET [options]
```

| Option | Meaning |
|---|---|
| `--addr <host:port>` | The endpoint. Required |
| `--key <id>` | Your key ID. Required |
| `--secret <secret>` | Your secret. Required |
| `--votes` | Include vote transactions. Off by default |
| `--account <pubkey>` | Only transactions touching this account. Repeatable |
| `--program <pubkey>` | Only transactions invoking this program. Repeatable |
| `--filter-file <path>` | One filter as JSON, overriding `--account` and `--program` |
| `--count <n>` | Stop after `n` transactions |
| `--quiet` | Print the summary only |
| `--no-compression` | Ask for an uncompressed stream |

Each line is one transaction:

```text
slot  462241688   1/0   5HaR1Y3s5NPXDJ6uFpWY8g3fJzD4n836Ae2fj5aVVCr8tqCvwXbWMhR9e6euaiYdnzUQGacrBV89RPzSuXGJkLHU Unverified(Disabled) recovered 4 keys 4 ix
```

That is the slot, the entry and transaction index within it, the signature, the
[verification verdict](delivery.md#verification), `recovered` if the transaction's shreds were
rebuilt from parity, and the number of account keys and instructions.

On exit it prints a summary: how many transactions arrived and how fast, the mean pipeline latency,
and how many frames were lost to sequence gaps.

### Filters

`--account` and `--program` cover the common cases. For anything else, write the filter to a file
and pass it with `--filter-file`. The file holds **one filter spec**, not the named-filter document
the SDKs submit:

```json
{"and": [
  {"is_vote": {"value": false}},
  {"programs": {"include": ["JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"]}}
]}
```

The filter is sent in the greeting, so it is in force from the first frame. See
[Filters](filters.md) for the full language.

## stats

Measures the stream as your client receives it.

```bash
aura-cli stats --addr ams.auraboost.wtf:9000 --key KEY_ID --secret SECRET --interval 5
```

```text
 elapsed       tx/s    votes/s        p50        p99        max  delivery    Mbit/s    lost
      5s        109          0     6.33ms    12.97ms    13.42ms        -         0.9       0
```

| Column | Meaning |
|---|---|
| `tx/s`, `votes/s` | Transactions and votes received per second |
| `p50`, `p99`, `max` | Pipeline latency: from the first shred of a batch arriving at Aura to the transaction being encoded |
| `delivery` | Not available from your side. It needs Aura's own clock |
| `Mbit/s` | Bandwidth on the wire, after compression |
| `lost` | Frames dropped because the client fell behind |

| Option | Meaning |
|---|---|
| `--interval <s>` | Seconds between report lines. Default 5 |
| `--for <s>` | Stop after this many seconds |
| `--votes` | Include vote transactions |
| `--no-compression` | Ask for an uncompressed stream |

This is the subscriber's view: queueing, compression and network time only exist at your end.
