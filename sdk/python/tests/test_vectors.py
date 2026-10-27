"""Decodes the committed fixtures and checks every field the manifest states.

The fixtures are bytes produced by the node's own encoders, so this is the test that keeps this
package's vendored decoders from drifting from what the node actually sends.
"""

import json
import pathlib
import struct

import pytest

from aura_shreds_sdk import (
    DUPLICATE_LEN,
    ENTRY_LEN,
    FRAME_HEADER_LEN,
    SLOT_END_LEN,
    SLOT_START_LEN,
    Duplicate,
    Entry,
    RawShred,
    SlotEnd,
    SlotStart,
    Transaction,
)
from aura_shreds_sdk.records import (
    parse_duplicate,
    parse_entry,
    parse_raw_shred,
    parse_slot_end,
    parse_slot_start,
)
from aura_shreds_sdk.wire import (
    HELLO_ACK_LEN,
    Codec,
    FrameKind,
    Stream,
    Verification,
    parse_filter_ack,
    parse_frame_header,
    parse_hello_ack,
    parse_lag,
    parse_refusal,
)

FIXTURES = pathlib.Path(__file__).resolve().parent.parent.parent / "fixtures"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text())


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def test_proof_vectors_match_the_manifest():
    from aura_shreds_sdk.auth import (
        NO_BINDING,
        Transcript,
        binding_of,
        client_proof,
        key_ref,
        server_proof,
    )

    hs = MANIFEST["handshake"]
    key = hs["key_material_utf8"].encode()
    cert = hs["certificate_der_utf8"].encode()

    session = Transcript(
        key_ref=key_ref(key),
        client_nonce=bytes([hs["client_nonce_byte"]]) * 32,
        server_nonce=bytes([hs["server_nonce_byte"]]) * 32,
        binding=binding_of(cert),
    )
    assert session.key_ref.hex() == hs["key_ref_hex"]
    assert session.binding.hex() == hs["binding_hex"]
    assert server_proof(session, key).hex() == hs["server_proof_hex"]
    assert client_proof(session, key).hex() == hs["client_proof_hex"]
    tcp = Transcript(session.key_ref, session.client_nonce, session.server_nonce, NO_BINDING)
    assert server_proof(tcp, key).hex() == hs["tcp_binding_server_proof_hex"]


def test_the_greeting_layout_is_pinned():
    hello = MANIFEST["hello"]
    data = fixture("hello.bin")
    version, streams, codecs, pad = struct.unpack_from("<HIBB", data, 0)
    assert version == hello["protocol_version"] == 1
    assert streams == hello["streams"]
    assert codecs == hello["codecs"]
    assert pad == 0, "the padding byte stays zero: this protocol has no capabilities byte"
    from aura_shreds_sdk.auth import key_ref

    assert data[8:40] == key_ref(hello["key_material_utf8"].encode())
    assert set(data[40:72]) == {0}
    assert len(data) == 72, "no dictionary id trails the nonce; the greeting ends there"


def test_the_filtered_greeting_carries_its_document():
    hello = MANIFEST["hello_filtered"]
    data = fixture("hello_filtered.bin")
    (length,) = struct.unpack_from("<I", data, 72)
    assert length == len(hello["filter"].encode())
    assert data[76:].decode() == hello["filter"]


def test_the_acknowledgement_is_eighteen_bytes():
    ack = MANIFEST["hello_ack"]
    data = fixture("hello_ack.bin")
    assert len(data) == HELLO_ACK_LEN == 18, "no dictionary id field"
    parsed = parse_hello_ack(data)
    assert parsed.protocol_version == ack["protocol_version"]
    assert parsed.granted == ack["granted"] == Stream.TRANSACTIONS
    assert parsed.session_id == int(ack["session_id"])
    assert parsed.codec == Codec(ack["codec"])
    assert parsed.keepalive_ms == ack["keepalive_ms"]


def test_the_refusal_carries_its_code_and_detail():
    error = MANIFEST["error"]
    data = fixture("error.bin")
    parsed = parse_refusal(data)
    assert parsed.code == error["code"]
    assert parsed.detail == error["detail"]


def test_the_lag_report_parses():
    lag = MANIFEST["lag"]
    parsed = parse_lag(fixture("lag.bin"))
    assert parsed.dropped == int(lag["dropped"])
    assert parsed.resume_seq == int(lag["resume_seq"])


def test_the_filter_verdict_parses():
    ack = MANIFEST["filter_ack"]
    parsed = parse_filter_ack(fixture("filter_ack.bin"))
    assert parsed.accepted is ack["accepted"]
    assert parsed.cost == ack["cost"]
    assert parsed.detail == ack["detail"]


def test_the_slot_start_record_parses():
    start = MANIFEST["slot_start"]
    parsed = parse_slot_start(fixture("slot_start.bin"))
    assert parsed.slot == int(start["slot"])
    assert parsed.parent_slot == int(start["parent_slot"])
    assert parsed.leader[0] == start["leader_byte"]
    assert parsed.shred_version == start["shred_version"]
    assert parsed.rx_ts_ns == int(start["rx_ts_ns"])
    assert parsed.source == start["source"]


def test_the_bare_slot_start_has_no_parent_and_no_leader():
    start = MANIFEST["slot_start_bare"]
    parsed = parse_slot_start(fixture("slot_start_bare.bin"))
    assert parsed.slot == int(start["slot"])
    assert parsed.parent_slot is None
    assert parsed.leader is None


def test_the_slot_end_record_parses():
    end = MANIFEST["slot_end"]
    parsed = parse_slot_end(fixture("slot_end.bin"))
    assert parsed.slot == int(end["slot"])
    assert parsed.parent_slot == int(end["parent_slot"])
    assert parsed.data_shreds == end["data_shreds"]
    assert parsed.fec_sets == end["fec_sets"]
    assert parsed.recovered_sets == end["recovered_sets"]
    assert parsed.missing_shreds == end["missing_shreds"]
    assert parsed.complete is end["complete"]
    assert parsed.end_ts_ns == int(end["end_ts_ns"])


def test_the_entry_record_parses():
    entry = MANIFEST["entry"]
    parsed = parse_entry(fixture("entry.bin"))
    assert parsed.slot == int(entry["slot"])
    assert parsed.parent_slot == int(entry["parent_slot"])
    assert parsed.rx_ts_ns == int(entry["rx_ts_ns"])
    assert parsed.num_hashes == int(entry["num_hashes"])
    assert parsed.tx_count == int(entry["tx_count"])
    assert parsed.hash[0] == entry["hash_byte"]
    assert parsed.fec_set_index == entry["fec_set_index"]
    assert parsed.entry_index == entry["entry_index"]
    assert parsed.verification == Verification(entry["verification"])


def test_the_duplicate_record_parses():
    dup = MANIFEST["duplicate"]
    parsed = parse_duplicate(fixture("duplicate.bin"))
    assert parsed.slot == int(dup["slot"])
    assert parsed.index == dup["index"]
    assert parsed.first_source == dup["first_source"]
    assert parsed.second_source == dup["second_source"]
    assert parsed.detected_ns == int(dup["detected_ns"])
    assert parsed.is_data is dup["is_data"]
    assert parsed.first_signature[0] == dup["first_signature_byte"]
    assert parsed.second_signature[0] == dup["second_signature_byte"]


def test_the_plain_transaction_parses_field_by_field():
    tx = MANIFEST["tx_simple"]
    data = fixture("tx_simple.bin")
    assert len(data) == MANIFEST["tx_simple_len"]

    parsed = Transaction.read(data)
    assert parsed.slot == int(tx["slot"])
    assert parsed.parent_slot == int(tx["parent_slot"])
    assert parsed.rx_ts_ns == int(tx["rx_ts_ns"])
    assert parsed.emit_ts_ns == int(tx["emit_ts_ns"])
    assert parsed.leader[0] == tx["leader_byte"]
    assert parsed.fec_set_index == tx["fec_set_index"]
    assert parsed.entry_index == tx["entry_index"]
    assert parsed.tx_index == tx["tx_index"]
    assert parsed.source_id == tx["source_id"]
    assert parsed.is_vote is tx["is_vote"]
    assert parsed.recovered is tx["recovered"]
    assert parsed.verification == Verification(tx["verification"])
    assert parsed.account_count == tx["account_count"]
    assert parsed.instruction_count == tx["instruction_count"]
    assert parsed.signature_count == tx["signature_count"]
    assert parsed.message_version == tx["message_version"]
    assert parsed.lookup_count == tx["lookup_count"]
    assert parsed.required_signatures == tx["required_signatures"]
    assert parsed.readonly_signed == tx["readonly_signed"]
    assert parsed.readonly_unsigned == tx["readonly_unsigned"]
    assert parsed.signature[0] == tx["signature_byte"]
    assert parsed.recent_blockhash[0] == tx["blockhash_byte"]
    assert parsed.raw_tx is None

    instruction = parsed.instruction(0)
    assert instruction.data == bytes(tx["instruction_data"])
    assert instruction.accounts == bytes(tx["instruction_accounts"])
    assert instruction.program_id_index == tx["program_id_index"]


def test_the_full_transaction_parses():
    tx = MANIFEST["tx_full"]
    parsed = Transaction.read(fixture("tx_full.bin"))

    assert parsed.account_count == tx["account_count"]
    assert parsed.instruction_count == tx["instruction_count"]
    assert parsed.signature_count == tx["signature_count"]
    assert parsed.lookup_count == tx["lookup_count"]
    assert parsed.is_vote is tx["is_vote"]
    assert parsed.recovered is tx["recovered"]
    assert parsed.message_version == tx["message_version"]

    raw = parsed.raw_tx
    assert raw is not None and len(raw) == tx["raw_tx_len"]
    assert len(parsed.instruction(0).data) == tx["instruction_data_len"]

    lookups = parsed.lookups()
    assert lookups[0].writable_indexes == b"\x01"
    assert lookups[0].readonly_indexes == b"\x02"
    assert lookups[0].account_key[0] == tx["lookup0_key_byte"]
    assert lookups[1].account_key[0] == tx["lookup1_key_byte"]


def test_the_legacy_transaction_parses():
    tx = MANIFEST["tx_legacy"]
    parsed = Transaction.read(fixture("tx_legacy.bin"))

    assert parsed.message_version == tx["message_version"] == 0xFF
    assert parsed.account_count == tx["account_count"]
    assert parsed.leader is None
    assert parsed.verification == Verification(tx["verification"])
    instruction = parsed.instruction(0)
    assert instruction.data == bytes(tx["instruction_data"])
    assert instruction.program_id_index == tx["program_id_index"]


def test_the_malformed_transaction_decodes_without_raising():
    tx = MANIFEST["tx_malformed"]
    parsed = Transaction.read(fixture("tx_malformed.bin"))

    assert parsed.signature_count == tx["signature_count"] == 0
    assert parsed.signature is None
    assert parsed.account_count == tx["account_count"]
    assert parsed.instruction_count == tx["instruction_count"]
    # The instruction names a program index past its own account list; decoding must not refuse it.
    assert parsed.instruction(0).program_id_index == tx["program_id_index"]
    assert parsed.account_key(9) is None


def test_the_frame_headers_parse():
    plain = fixture("frame_plain.bin")
    header = parse_frame_header(plain)
    assert header.kind is FrameKind.TRANSACTION
    assert header.seq == int(MANIFEST["frame_plain"]["seq"])
    assert not header.compressed
    assert header.codec is Codec.PLAIN

    compressed = fixture("frame_zstd.bin")
    header = parse_frame_header(compressed)
    assert header.seq == int(MANIFEST["frame_zstd"]["seq"])
    assert header.compressed
    assert header.codec is Codec.ZSTD

    matched = fixture("frame_matched.bin")
    header = parse_frame_header(matched)
    assert header.matched == MANIFEST["frame_matched"]["matched"]
    indices = [i for i in range(16) if header.matched & (1 << i)]
    assert indices == MANIFEST["frame_matched"]["matched_indices"]


def test_the_zstd_frame_decompresses_to_the_plain_transaction():
    from compression import zstd

    frame = fixture("frame_zstd.bin")
    header = parse_frame_header(frame)
    payload = frame[FRAME_HEADER_LEN : FRAME_HEADER_LEN + header.len]
    assert zstd.decompress(payload) == fixture("tx_simple.bin")


def test_a_raw_shred_round_trips_its_payload():
    payload = bytes([9, 8, 7, 6, 5])
    buf = bytearray(32 + len(payload))
    struct.pack_into("<Q", buf, 0, 412500103)
    struct.pack_into("<I", buf, 8, 47)
    struct.pack_into("<I", buf, 12, 32)
    struct.pack_into("<Q", buf, 16, 1900000100900)
    struct.pack_into("<H", buf, 24, 3)
    buf[26] = 1  # the parity marker
    buf[32:] = payload

    parsed = parse_raw_shred(bytes(buf))
    assert parsed.slot == 412500103
    assert parsed.index == 47
    assert parsed.fec_set_index == 32
    assert parsed.rx_ts_ns == 1900000100900
    assert parsed.source == 3
    assert parsed.is_data is False, "the parity marker was recognised"
    assert parsed.bytes == payload


def test_the_frame_sizes_stay_fixed():
    assert SLOT_START_LEN == 64
    assert SLOT_END_LEN == 48
    assert ENTRY_LEN == 88
    assert DUPLICATE_LEN == 160
    assert Stream.TRANSACTIONS == 1
