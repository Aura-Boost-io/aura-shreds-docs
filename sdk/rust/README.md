# aura-shreds-sdk

Rust subscriber client for the aura-shreds Solana shred stream.

- Getting started: [the SDK guide](../../docs/sdk-rust.md)
- API reference: `cargo doc --open`

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

The wire fixtures under `fixtures/` are bytes produced by the server's own encoders; `tests/` decodes
them and asserts every field the manifest states, so a decoder that drifts from the node fails here
rather than on a live stream.
