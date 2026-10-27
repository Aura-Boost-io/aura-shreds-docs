/**
 * Failure types for the subscriber protocol.
 */

/** Anything the protocol could not be read as. */
export class ProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProtocolError';
  }
}

/** The node refused the connection, or closed it with a reason. */
export class ServerError extends Error {
  constructor(
    readonly code: number,
    readonly detail: string,
  ) {
    super(`refused by node [${code}]: ${detail}`);
    this.name = 'ServerError';
  }
}

/** The connection could not be established, or failed while open. */
export class TransportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TransportError';
  }
}
