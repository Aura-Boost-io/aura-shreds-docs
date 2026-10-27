/**
 * Decodes the committed fixtures and checks every field the manifest states.
 *
 * The fixtures are bytes produced by the node's own encoders, so this is the test that keeps this
 * package's vendored decoders from drifting from what the node actually sends.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { zstdDecompressSync } from 'node:zlib';
import { test } from 'node:test';

import { Codec, FrameKind, Stream, Verification, parseFrameHeader } from '../src/frames.js';
import {
  HELLO_ACK_LEN,
  parseFilterAck,
  parseHelloAck,
  parseLag,
  parseRefusal,
} from '../src/control.js';
import {
  DUPLICATE_SIZE,
  ENTRY_SIZE,
  SLOT_END_SIZE,
  SLOT_START_SIZE,
  parseDuplicate,
  parseEntry,
  parseRawShred,
  parseSlotEnd,
  parseSlotStart,
} from '../src/records.js';
import {
  NO_BINDING,
  bindingOf,
  clientProof,
  keyRef,
  serverProof,
  verifyServer,
  type Transcript,
} from '../src/auth.js';
import { Transaction } from '../src/tx.js';

const FIXTURES = new URL('../../../fixtures', import.meta.url).pathname;
const M: Record<string, any> = JSON.parse(readFileSync(`${FIXTURES}/manifest.json`, 'utf8'));

function f(name: string): Buffer {
  return readFileSync(`${FIXTURES}/${name}`);
}

test('proof vectors match the manifest', () => {
  const hs = M.handshake;
  const key = Buffer.from(hs.key_material_utf8, 'utf8');
  const cert = Buffer.from(hs.certificate_der_utf8, 'utf8');
  const session: Transcript = {
    keyRef: keyRef(key),
    clientNonce: Buffer.alloc(32, hs.client_nonce_byte),
    serverNonce: Buffer.alloc(32, hs.server_nonce_byte),
    binding: bindingOf(cert),
  };
  assert.equal(session.keyRef.toString('hex'), hs.key_ref_hex);
  assert.equal(session.binding.toString('hex'), hs.binding_hex);
  assert.equal(serverProof(session, key).toString('hex'), hs.server_proof_hex);
  assert.equal(clientProof(session, key).toString('hex'), hs.client_proof_hex);
  assert.equal(
    serverProof({ ...session, binding: NO_BINDING }, key).toString('hex'),
    hs.tcp_binding_server_proof_hex,
  );
  assert.equal(verifyServer(session, key, serverProof(session, key)), true);
});

test('greeting layout is pinned', () => {
  const h = M.hello;
  const buf = f('hello.bin');
  assert.equal(buf.readUInt16LE(0), h.protocol_version);
  assert.equal(buf.readUInt32LE(2), h.streams);
  assert.equal(buf.readUInt8(6), h.codecs);
  assert.equal(buf.readUInt8(7), 0, 'no capabilities byte');
  assert.deepEqual(buf.subarray(8, 40), keyRef(Buffer.from(h.key_material_utf8)));
  assert.equal(buf.length, 72, 'no dictionary id trails the nonce');
});

test('filtered greeting carries its document', () => {
  const h = M.hello_filtered;
  const buf = f('hello_filtered.bin');
  const filter = Buffer.from(h.filter, 'utf8');
  assert.equal(buf.readUInt32LE(72), filter.length);
  assert.deepEqual(buf.subarray(76), filter);
});

test('acknowledgement is eighteen bytes', () => {
  const ack = M.hello_ack;
  const buf = f('hello_ack.bin');
  assert.equal(buf.length, HELLO_ACK_LEN, 'no dictionary id field');
  const parsed = parseHelloAck(buf);
  assert.equal(parsed.protocolVersion, ack.protocol_version);
  assert.equal(parsed.granted, ack.granted);
  assert.equal(parsed.sessionId, BigInt(ack.session_id));
  assert.equal(parsed.codec, ack.codec);
  assert.equal(parsed.keepaliveMs, ack.keepalive_ms);
});

test('refusal carries its code and detail', () => {
  const buf = f('error.bin');
  const len = buf.readUInt16LE(2);
  assert.equal(buf.readUInt16LE(0), M.error.code);
  assert.equal(buf.subarray(4, 4 + len).toString(), M.error.detail);
});

test('lag report parses', () => {
  const parsed = parseLag(f('lag.bin'));
  assert.equal(parsed.dropped, BigInt(M.lag.dropped));
  assert.equal(parsed.resumeSeq, BigInt(M.lag.resume_seq));
});

test('filter verdict parses', () => {
  const ack = M.filter_ack;
  const parsed = parseFilterAck(f('filter_ack.bin'));
  assert.equal(parsed.accepted, ack.accepted);
  assert.equal(parsed.cost, ack.cost);
  assert.equal(parsed.detail, ack.detail);
});

test('slot start parses', () => {
  const s = M.slot_start;
  const parsed = parseSlotStart(f('slot_start.bin'));
  assert.equal(parsed.slot, BigInt(s.slot));
  assert.equal(parsed.parentSlot, BigInt(s.parent_slot));
  assert.equal(parsed.leader?.[0], s.leader_byte);
  assert.equal(parsed.shredVersion, s.shred_version);
  assert.equal(parsed.rxTsNs, BigInt(s.rx_ts_ns));
  assert.equal(parsed.source, s.source);
});

test('bare slot start has no parent and no leader', () => {
  const parsed = parseSlotStart(f('slot_start_bare.bin'));
  assert.equal(parsed.slot, BigInt(M.slot_start_bare.slot));
  assert.equal(parsed.parentSlot, null);
  assert.equal(parsed.leader, null);
});

test('slot end parses', () => {
  const e = M.slot_end;
  const parsed = parseSlotEnd(f('slot_end.bin'));
  assert.equal(parsed.slot, BigInt(e.slot));
  assert.equal(parsed.parentSlot, BigInt(e.parent_slot));
  assert.equal(parsed.dataShreds, e.data_shreds);
  assert.equal(parsed.fecSets, e.fec_sets);
  assert.equal(parsed.recoveredSets, e.recovered_sets);
  assert.equal(parsed.missingShreds, e.missing_shreds);
  assert.equal(parsed.complete, e.complete);
  assert.equal(parsed.endTsNs, BigInt(e.end_ts_ns));
});

test('entry parses', () => {
  const e = M.entry;
  const parsed = parseEntry(f('entry.bin'));
  assert.equal(parsed.slot, BigInt(e.slot));
  assert.equal(parsed.parentSlot, BigInt(e.parent_slot));
  assert.equal(parsed.rxTsNs, BigInt(e.rx_ts_ns));
  assert.equal(parsed.numHashes, BigInt(e.num_hashes));
  assert.equal(parsed.txCount, BigInt(e.tx_count));
  assert.equal(parsed.hash[0], e.hash_byte);
  assert.equal(parsed.fecSetIndex, e.fec_set_index);
  assert.equal(parsed.entryIndex, e.entry_index);
  assert.equal(parsed.verification, Verification.StaleSchedule);
});

test('duplicate parses', () => {
  const d = M.duplicate;
  const parsed = parseDuplicate(f('duplicate.bin'));
  assert.equal(parsed.slot, BigInt(d.slot));
  assert.equal(parsed.index, d.index);
  assert.equal(parsed.firstSource, d.first_source);
  assert.equal(parsed.secondSource, d.second_source);
  assert.equal(parsed.detectedNs, BigInt(d.detected_ns));
  assert.equal(parsed.isData, d.is_data);
  assert.equal(parsed.firstSignature[0], d.first_signature_byte);
  assert.equal(parsed.secondSignature[0], d.second_signature_byte);
});

test('plain transaction parses field by field', () => {
  const t = M.tx_simple;
  const buf = f('tx_simple.bin');
  assert.equal(buf.length, M.tx_simple_len);
  const tx = Transaction.read(buf);
  assert.equal(tx.slot, BigInt(t.slot));
  assert.equal(tx.parentSlot, BigInt(t.parent_slot));
  assert.equal(tx.rxTsNs, BigInt(t.rx_ts_ns));
  assert.equal(tx.emitTsNs, BigInt(t.emit_ts_ns));
  assert.equal(tx.leader?.[0], t.leader_byte);
  assert.equal(tx.fecSetIndex, t.fec_set_index);
  assert.equal(tx.entryIndex, t.entry_index);
  assert.equal(tx.txIndex, t.tx_index);
  assert.equal(tx.sourceId, t.source_id);
  assert.equal(tx.isVote, t.is_vote);
  assert.equal(tx.recovered, t.recovered);
  assert.equal(tx.verification, Verification.Verified);
  assert.equal(tx.accountCount, t.account_count);
  assert.equal(tx.instructionCount, t.instruction_count);
  assert.equal(tx.signatureCount, t.signature_count);
  assert.equal(tx.messageVersion, t.message_version);
  assert.equal(tx.lookupCount, t.lookup_count);
  assert.equal(tx.requiredSignatures, t.required_signatures);
  assert.equal(tx.readonlySigned, t.readonly_signed);
  assert.equal(tx.readonlyUnsigned, t.readonly_unsigned);
  assert.equal(tx.signature?.[0], t.signature_byte);
  assert.equal(tx.recentBlockhash[0], t.blockhash_byte);
  assert.equal(tx.rawTx, null);
  const ix = tx.instruction(0);
  assert.deepEqual(ix?.data, Buffer.from(t.instruction_data));
  assert.deepEqual(ix?.accounts, Buffer.from(t.instruction_accounts));
  assert.equal(ix?.programIdIndex, t.program_id_index);
});

test('full transaction parses', () => {
  const t = M.tx_full;
  const tx = Transaction.read(f('tx_full.bin'));
  assert.equal(tx.accountCount, t.account_count);
  assert.equal(tx.instructionCount, t.instruction_count);
  assert.equal(tx.signatureCount, t.signature_count);
  assert.equal(tx.lookupCount, t.lookup_count);
  assert.equal(tx.isVote, t.is_vote);
  assert.equal(tx.recovered, t.recovered);
  assert.equal(tx.messageVersion, t.message_version);
  const raw = tx.rawTx;
  assert.ok(raw);
  assert.equal(raw.length, t.raw_tx_len);
  assert.equal(tx.instruction(0)?.data.length, t.instruction_data_len);
  const ls = tx.lookups();
  assert.deepEqual(ls[0]?.writableIndexes, Buffer.from(t.lookup_writable));
  assert.deepEqual(ls[0]?.readonlyIndexes, Buffer.from(t.lookup_readonly));
  assert.equal(ls[0]?.accountKey[0], t.lookup0_key_byte);
  assert.equal(ls[1]?.accountKey[0], t.lookup1_key_byte);
});

test('legacy transaction parses', () => {
  const t = M.tx_legacy;
  const tx = Transaction.read(f('tx_legacy.bin'));
  assert.equal(tx.messageVersion, t.message_version);
  assert.equal(tx.messageVersion, 0xff);
  assert.equal(tx.accountCount, t.account_count);
  assert.equal(tx.leader, null);
  assert.equal(tx.verification, Verification.UnknownLeader);
  const ix = tx.instruction(0);
  assert.deepEqual(ix?.data, Buffer.from(t.instruction_data));
  assert.equal(ix?.programIdIndex, t.program_id_index);
});

test('malformed transaction decodes without throwing', () => {
  const t = M.tx_malformed;
  const tx = Transaction.read(f('tx_malformed.bin'));
  assert.equal(tx.signatureCount, t.signature_count);
  assert.equal(tx.signature, null);
  assert.equal(tx.accountCount, t.account_count);
  assert.equal(tx.instructionCount, t.instruction_count);
  assert.equal(tx.instruction(0)?.programIdIndex, t.program_id_index);
  assert.equal(tx.accountKey(9), null);
});

test('frame headers parse', () => {
  const plain = parseFrameHeader(f('frame_plain.bin'));
  assert.equal(plain.kind, 1);
  assert.equal(plain.seq, BigInt(M.frame_plain.seq));
  assert.equal(plain.compressed, false);
  const zstd = parseFrameHeader(f('frame_zstd.bin'));
  assert.equal(zstd.seq, BigInt(M.frame_zstd.seq));
  assert.equal(zstd.compressed, true);
  const matched = parseFrameHeader(f('frame_matched.bin'));
  assert.equal(matched.matched, M.frame_matched.matched);
  const indices: number[] = [];
  for (let i = 0; i < 16; i += 1) if ((matched.matched & (1 << i)) !== 0) indices.push(i);
  assert.deepEqual(indices, M.frame_matched.matched_indices);
});

test('zstd frame inflates to the plain transaction', () => {
  const frame = f('frame_zstd.bin');
  const header = parseFrameHeader(frame);
  assert.deepEqual(zstdDecompressSync(frame.subarray(16, 16 + header.len)), f('tx_simple.bin'));
});

test('raw shred round trips its payload', () => {
  const payload = Buffer.from([9, 8, 7, 6, 5]);
  const buf = Buffer.alloc(32 + payload.length);
  buf.writeBigUInt64LE(412500103n, 0);
  buf.writeUInt32LE(47, 8);
  buf.writeUInt32LE(32, 12);
  buf.writeBigUInt64LE(1900000100900n, 16);
  buf.writeUInt16LE(3, 24);
  buf.writeUInt8(1, 26); // the parity marker
  payload.copy(buf, 32);
  const parsed = parseRawShred(buf);
  assert.equal(parsed.slot, 412500103n);
  assert.equal(parsed.index, 47);
  assert.equal(parsed.fecSetIndex, 32);
  assert.equal(parsed.rxTsNs, 1900000100900n);
  assert.equal(parsed.source, 3);
  assert.equal(parsed.isData, false);
  assert.deepEqual(parsed.bytes, payload);
});

test('frame sizes stay fixed', () => {
  assert.equal(SLOT_START_SIZE, 64);
  assert.equal(SLOT_END_SIZE, 48);
  assert.equal(ENTRY_SIZE, 88);
  assert.equal(DUPLICATE_SIZE, 160);
  assert.equal(Stream.TRANSACTIONS, 1);
});
