/**
 * Authenticating without disclosing the key.
 *
 * A key is one value that serves as both name and credential, so a handshake that sends it would
 * put a working credential on the wire on every connect. Instead each side computes an HMAC over a
 * transcript both can reconstruct:
 *
 * ```text
 * subscriber → node   reference = SHA-256(domain ‖ key), subscriber nonce
 * node       → subscriber   node nonce, HMAC(key, node domain ‖ transcript)
 * subscriber checks it, then answers with HMAC(key, client domain ‖ transcript)
 * ```
 *
 * The node proves first, so an impostor is abandoned having learned nothing.
 *
 * TCP presents no certificate, so the transcript's binding is the all-zero sentinel. The key still
 * never travels; what plain TCP gives up is relay detection, which is why it suits a subscriber on
 * a network it trusts.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const REFERENCE_DOMAIN = Buffer.from('aura-shreds/key-ref/v1');
const NODE_DOMAIN = Buffer.from('aura-shreds/server-proof/v1');
const SUBSCRIBER_DOMAIN = Buffer.from('aura-shreds/client-proof/v1');

/** Bytes in a key reference, a nonce, a binding and a proof — all SHA-256 sized. */
export const DIGEST_LEN = 32;

/**
 * A non-reversible stand-in for a key, safe to log or quote.
 *
 * SHA-256 of the key under a domain separator. The greeting carries it; the node uses it to find
 * which key to prove against.
 */
export function keyRef(key: Buffer): Buffer {
  return createHash('sha256').update(REFERENCE_DOMAIN).update(key).digest();
}

/** Enough hex to tell two keys apart in a log line. */
export function shortRef(reference: Buffer): string {
  return reference.toString('hex').slice(0, 16);
}

/**
 * Hash of whatever the transport presented, when it presents anything.
 *
 * All zeroes for plain TCP, which presents none.
 */
export const NO_BINDING: Buffer = Buffer.alloc(DIGEST_LEN);

/** Binds a proof to a presented certificate. */
export function bindingOf(certificateDer: Uint8Array): Buffer {
  return createHash('sha256').update(certificateDer).digest();
}

/** The material both sides hash to produce their proofs. */
export interface Transcript {
  /** Reference of the key being claimed. */
  keyRef: Buffer;
  /** Chosen by the subscriber. */
  clientNonce: Buffer;
  /** Chosen by the node. */
  serverNonce: Buffer;
  /** Session material, or the zero sentinel over TCP. */
  binding: Buffer;
}


function mac(transcript: Transcript, key: Buffer, domain: Buffer): Buffer {
  return createHmac('sha256', key)
    .update(domain)
    .update(transcript.keyRef)
    .update(transcript.clientNonce)
    .update(transcript.serverNonce)
    .update(transcript.binding)
    .digest();
}

/** What the node must produce to authenticate itself. */
export function serverProof(transcript: Transcript, key: Buffer): Buffer {
  return mac(transcript, key, NODE_DOMAIN);
}

/** What the subscriber must produce to authenticate itself. */
export function clientProof(transcript: Transcript, key: Buffer): Buffer {
  return mac(transcript, key, SUBSCRIBER_DOMAIN);
}

/**
 * Whether `presented` matches the node's expected proof.
 *
 * Compared in constant time: an early exit would grade a forger's guess byte by byte.
 */
export function verifyServer(transcript: Transcript, key: Buffer, presented: Buffer): boolean {
  const expected = serverProof(transcript, key);
  // `timingSafeEqual` throws on a length mismatch rather than returning false, and a short proof is
  // something a peer can send, so the length is checked first and separately.
  if (presented.length !== expected.length) return false;
  return timingSafeEqual(expected, presented);
}

/**
 * A fresh nonce for one exchange.
 *
 * From the operating system's generator: uniqueness is not enough. A predictable nonce would let
 * an attacker obtain a proof over a transcript chosen in advance.
 */
export function freshNonce(): Buffer {
  return randomBytes(DIGEST_LEN);
}
