/**
 * Reaching the node: TCP.
 *
 * The aura-shreds node serves subscribers over TCP. Nothing here checks a certificate, because
 * there is none: the node authenticates itself with your key during the handshake. See `auth` for
 * why that is not the weakening it looks like.
 */

import { connect as tcpConnect, type Socket } from 'node:net';

import { TransportError } from './failures.js';

/**
 * A byte pipe to the node.
 *
 * Deliberately small: the client does all the framing, so a consumer wanting a transport this
 * package does not ship — a proxy, a replay file, a test double — implements these methods.
 */
export interface Wire {
  /** Called with every chunk that arrives. */
  onData(handler: (chunk: Buffer) => void): void;
  /** Called once the peer is done. */
  onClose(handler: () => void): void;
  /** Called when the connection fails. */
  onError(handler: (err: Error) => void): void;
  /** Writes bytes. */
  write(bytes: Buffer): void;
  /** Closes the connection. */
  close(): void;
  /** Starts or restarts delivering data. */
  resume(): void;
  /**
   * Stops reading, so the transport's flow control pushes back on the node.
   *
   * A client that stops consuming events must stop consuming *bytes*, or it buffers the firehose in
   * memory while the node goes on believing it is keeping up.
   */
  pause(): void;
}

/** Opens a TCP connection with Nagle disabled. */
export function connectTcp(host: string, port: number, timeoutMs: number): Promise<Wire> {
  return new Promise((resolve, reject) => {
    const socket = tcpConnect({ host, port, noDelay: true });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new TransportError(`connecting to ${host}:${port} timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    const fail = (err: Error): void => {
      clearTimeout(timer);
      reject(err);
    };
    socket.once('error', fail);
    socket.once('connect', () => {
      clearTimeout(timer);
      socket.removeListener('error', fail);
      socket.pause();
      resolve(wrap(socket));
    });
  });
}

function wrap(socket: Socket): Wire {
  return {
    onData: (handler) => socket.on('data', handler),
    onClose: (handler) => socket.on('close', handler),
    onError: (handler) => socket.on('error', handler),
    write: (bytes) => void socket.write(bytes),
    close: () => socket.destroy(),
    resume: () => socket.resume(),
    pause: () => socket.pause(),
  };
}
