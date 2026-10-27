# Aura Shreds

Aura receives shreds directly from Solana validators, recovers what the network lost, decodes them
into transactions and streams the result to you over TCP. A transaction reaches you as soon as the
shreds carrying it arrive: before the block is assembled, and long before any RPC sees it.

This repository holds everything a subscriber needs:

- **Documentation**: how to connect, what the streams carry, how to filter them, and the wire
  protocol for anyone writing their own client.
- **SDK** for Rust, TypeScript and Python, under [`sdk/`](sdk).
- **`aura-cli`**, a command-line client for Linux x86_64, attached to each
  [release](https://github.com/Aura-Boost-io/aura-shreds-docs/releases).

## What you need

| | |
|---|---|
| Endpoint | `ams.auraboost.wtf:9000` (TCP) |
| Secret | Your Aura API key, with shred access enabled |
| Key ID | The ID of that key. Only `aura-cli` asks for it; the SDK needs the secret alone |

Your secret never travels over the network. The connection proves that both sides hold it with a
challenge and response, so a captured connection is worth nothing to anyone else. The stream itself
is not encrypted.

## Quick start

Check your credentials and network path with the CLI:

```bash
aura-cli tail --addr ams.auraboost.wtf:9000 --key KEY_ID --secret SECRET --count 20
```

Then connect from code. Each SDK has its own guide; these are the shortest working programs.

```rust
use aura_shreds_sdk::Event;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client =
        aura_shreds_sdk::connect("ams.auraboost.wtf:9000", std::env::var("AURA_SHREDS_SECRET")?)
            .await?;
    loop {
        if let Event::Transaction { tx, .. } = client.next_event().await? {
            println!("slot {} sig {:?}", tx.slot(), tx.signature());
        }
    }
}
```

```typescript
import { AuraShredsClient } from '@aura-shreds/sdk';

const client = await AuraShredsClient.connect({
  host: 'ams.auraboost.wtf',
  port: 9000,
  secret: process.env.AURA_SHREDS_SECRET!,
});
for await (const event of client) {
  if (event.type === 'transaction') console.log(event.transaction.slot);
}
```

```python
import asyncio, os
from aura_shreds_sdk import Client

async def main():
    client = await Client.connect(
        host="ams.auraboost.wtf", port=9000, secret=os.environ["AURA_SHREDS_SECRET"]
    )
    async for event in client:
        if event.type == "transaction":
            print(event.transaction.slot)

asyncio.run(main())
```

By default you are subscribed to every stream your key allows, votes included. Narrowing that is the
first thing to read about: see [Streams](docs/streams.md) and [Filters](docs/filters.md).

## Documentation

| Guide | What it covers |
|---|---|
| [Getting started](docs/getting-started.md) | Credentials, the first connection, checking what you were granted |
| [CLI](docs/cli.md) | Installing `aura-cli`, `tail` and `stats` |
| [Rust SDK](docs/sdk-rust.md) | Installing, connecting, events, filters |
| [TypeScript SDK](docs/sdk-typescript.md) | Installing, connecting, events, filters |
| [Python SDK](docs/sdk-python.md) | Installing, connecting, events, filters |
| [Streams](docs/streams.md) | What each stream carries and what it costs |
| [Filters](docs/filters.md) | Narrowing the stream on the server, named filters, budgets |
| [Delivery](docs/delivery.md) | Sequence numbers, lag, ordering, verification, latency |
| [Protocol](docs/protocol.md) | The wire format, for writing your own client |
| [Troubleshooting](docs/troubleshooting.md) | Errors, limits, and things that look like bugs but are not |

## License

The SDK and the documentation are MIT licensed. See [LICENSE](LICENSE).
