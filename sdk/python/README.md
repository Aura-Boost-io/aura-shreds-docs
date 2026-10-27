# aura-shreds-sdk

Python subscriber client for the aura-shreds Solana shred stream.

- Getting started: [the SDK guide](../../docs/sdk-python.md)

## Development

```bash
uv sync
uv run pytest
```

Python 3.14 or newer is required, where zstd is in the standard library. The wire fixtures under
`fixtures/` are bytes produced by the server's own encoders; `tests/` decodes them and asserts every
field the manifest states, so a decoder that drifts from the node fails here rather than on a live
stream.
