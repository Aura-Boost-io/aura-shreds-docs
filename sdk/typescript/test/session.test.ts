/** Exercises the client against a stub node that speaks the real wire format. */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer, type Socket } from 'node:net';
import { test } from 'node:test';

import {
  AuraShredsClient,
  ErrorCode,
  FrameKind,
  Stream,
  buildFrame,
  type ClientOptions,
} from '../src/index.js';
import { NO_BINDING, keyRef, serverProof, type Transcript } from '../src/auth.js';

const KEY = Buffer.from('stub-key');
const FIXTURES = new URL('../../../fixtures', import.meta.url).pathname;

/** Runs the handshake as the node does, up to but excluding the ack. */
function serveHello(socket: Socket, secret: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    socket.on('data', (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length < 16) return;
      const len = buffer.readUInt32LE(0);
      if (buffer.length < 16 + len) return;
      const kind = buffer.readUInt8(4);
      if (kind === 9) {
        // Hello: only zstd offered, no capabilities byte.
        const hello = buffer.subarray(16, 16 + len);
        assert.equal(hello[6], 4, 'the greeting offers only zstd');
        assert.equal(hello[7], 0, 'no capabilities byte');
        const serverNonce = Buffer.alloc(32, 0x5a);
        const transcript: Transcript = {
          keyRef: keyRef(secret),
          clientNonce: Buffer.from(hello.subarray(40, 72)),
          serverNonce,
          binding: NO_BINDING,
        };
        const body = Buffer.concat([serverNonce, serverProof(transcript, secret)]);
        socket.write(buildFrame(16, 0n, body));
        buffer = Buffer.alloc(0);
        return;
      }
      if (kind === 17) {
        // The ack, which is what connect() waits for.
        const ack = Buffer.alloc(18);
        ack.writeUInt16LE(1, 0);
        ack.writeUInt32LE(Stream.TRANSACTIONS, 2);
        ack.writeBigUInt64LE(99n, 6);
        ack.writeUInt8(2, 14); // zstd
        ack.writeUInt16LE(20000, 16);
        socket.write(buildFrame(10, 0n, ack));
        socket.removeAllListeners('data');
        resolve(buffer.subarray(16 + len));
        return;
      }
      reject(new Error(`unexpected frame kind ${kind}`));
    });
    socket.on('error', reject);
  });
}

async function withClient(
  frames: Buffer[],
  run: (addr: { host: string; port: number }) => Promise<void>,
): Promise<void> {
  const server = createServer((socket) => {
    serveHello(socket, KEY)
      .then(() => {
        for (const frame of frames) socket.write(frame);
        setTimeout(() => socket.destroy(), 200);
      })
      .catch(() => socket.destroy());
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === 'object');
  try {
    await run({ host: addr.address, port: addr.port });
  } finally {
    server.close();
  }
}

const zstdTx = readFileSync(
  new URL('../../../fixtures/frame_zstd.bin', import.meta.url).pathname,
);

test('connects, authenticates and reads a compressed transaction', async () => {
  await withClient([zstdTx], async (addr) => {
    const options: ClientOptions = { host: addr.host, port: addr.port, secret: KEY };
    const client = await AuraShredsClient.connect(options);
    try {
      assert.equal(client.granted, Stream.TRANSACTIONS);
      assert.equal(client.sessionId, 99n);
      assert.equal(client.keepaliveMs, 20000);
      const event = await client.next();
      assert.ok(event && event.type === 'transaction', `expected a transaction, got ${event?.type}`);
      assert.equal(event.transaction.slot, 412500101n);
      assert.ok(client.decodedBytes > client.wireBytes - 16n);
    } finally {
      client.close();
    }
  });
});

test('refuses a wrong key before sending any proof', async () => {
  await withClient([], async (addr) => {
    const options: ClientOptions = {
      host: addr.host,
      port: addr.port,
      secret: Buffer.from('not-the-key'),
    };
    await assert.rejects(() => AuraShredsClient.connect(options), /did not prove/);
  });
});

test('reports a node refusal with its reason', async () => {
  const server = createServer((socket) => {
    socket.on('data', (chunk: Buffer) => {
      if (chunk.length < 16) return;
      const detail = 'unknown key';
      const body = Buffer.alloc(4 + detail.length);
      body.writeUInt16LE(ErrorCode.Unauthorized, 0);
      body.writeUInt16LE(detail.length, 2);
      body.write(detail, 4);
      socket.write(buildFrame(12, 0n, body));
      socket.destroy();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === 'object');
  try {
    await assert.rejects(
      () => AuraShredsClient.connect({ host: addr.address, port: addr.port, secret: KEY }),
      /unknown key/,
    );
  } finally {
    server.close();
  }
});
