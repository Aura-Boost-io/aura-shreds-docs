# Getting started

## 1. Credentials

You need two things from Aura:

- **The endpoint**, `ams.auraboost.wtf:9000`. The transport is plain TCP.
- **Your secret**: your Aura API key, with shred access enabled on it.

`aura-cli` also asks for your **key ID**, the ID of that API key. The SDK does not: it finds your
key from the secret alone.

The secret is the only credential, so keep it out of source control. Every example here reads it
from the `AURA_SHREDS_SECRET` environment variable.

## 2. Check the connection

Before writing any code, confirm that your credentials and network path work:

```bash
aura-cli tail --addr ams.auraboost.wtf:9000 --key KEY_ID --secret SECRET --count 20
```

If it prints transactions, everything is in order. If it prints `Unauthorized`, either the secret is
wrong or shred access is not enabled on your key. The two cases are deliberately indistinguishable.
See [CLI](cli.md) for installing it.

## 3. Connect from code

Pick an SDK:

- [Rust](sdk-rust.md): Rust 1.85 or newer, on tokio.
- [TypeScript](sdk-typescript.md): Node 22.15 or newer.
- [Python](sdk-python.md): Python 3.14 or newer.

All three speak the same protocol and expose the same events. If none of them fits, the
[protocol](protocol.md) is documented in full.

## 4. Check what you were granted

Your key grants a set of streams, and your client asks for a subset. The node gives you the
intersection. Asking for a stream your key does not grant is **not an error**: the connection works
and simply never delivers it. Only if none of the streams you asked for is granted does the node
refuse the connection, with `Forbidden`.

So after connecting, compare the granted mask with what you asked for:

| SDK | Granted streams |
|---|---|
| Rust | `client.granted()` |
| TypeScript | `client.granted` |
| Python | `client.granted` |

A connection that works but delivers nothing is almost always a stream that was never granted.

## 5. Narrow the stream

By default you receive every stream your key allows, votes included. Votes are about half of
mainnet traffic. Before going further:

- Ask only for the [streams](streams.md) you read. A stream nobody asked for is never encoded.
- Put a [filter](filters.md) in the connection itself, so the stream is narrowed before the first
  frame instead of after a round trip.

## 6. Handle lag

If your client falls behind, the node drops the oldest frames queued for you and tells you with a
`lag` event. It is the only signal that your view has a hole in it. Read [Delivery](delivery.md)
before relying on the stream for anything that must be complete.
