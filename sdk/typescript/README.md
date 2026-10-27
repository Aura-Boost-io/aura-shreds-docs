# @aura-shreds/sdk

TypeScript subscriber client for the aura-shreds Solana shred stream.

- Getting started: [the SDK guide](../../docs/sdk-typescript.md)

## Development

```bash
npm install
npm test
```

Node 22.15 or newer is required, where zstd is built in. The wire fixtures under `fixtures/` are
bytes produced by the server's own encoders; `test/` decodes them and asserts every field the
manifest states, so a decoder that drifts from the node fails here rather than on a live stream.
