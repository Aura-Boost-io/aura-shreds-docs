//! Decodes the committed fixtures and checks every field the manifest states.
//!
//! The fixtures are bytes produced by the node's own encoders, so this is the test that keeps this
//! crate's vendored decoders from drifting from what the node actually sends.

use std::path::PathBuf;

use aura_shreds_sdk::{
    auth::{ChannelBinding, KeyRef, Transcript},
    records::{Duplicate, Entry, RawShred, SlotEnd, SlotStart},
    tx::Transaction,
    wire::{
        Codec, ErrorCode, FrameKind, HelloAck, Lag, StreamMask, Verification,
        parse_header,
    },
};

fn load(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|err| panic!("reading {name}: {err}"))
}

fn manifest() -> serde_json::Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/manifest.json");
    serde_json::from_str(&std::fs::read_to_string(&path).expect("manifest")).expect("manifest json")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The known-answer vectors for the proof derivation, from the manifest.
#[test]
fn proof_vectors_match_the_manifest() {
    let manifest = manifest();
    let handshake = &manifest["handshake"];
    let key = handshake["key_material_utf8"].as_str().unwrap().as_bytes();
    let certificate = handshake["certificate_der_utf8"]
        .as_str()
        .unwrap()
        .as_bytes();

    let session = Transcript {
        key_ref: KeyRef::derive(key),
        client_nonce: [handshake["client_nonce_byte"].as_u64().unwrap() as u8; 32],
        server_nonce: [handshake["server_nonce_byte"].as_u64().unwrap() as u8; 32],
        binding: ChannelBinding::from_certificate(certificate),
    };

    assert_eq!(hex(&session.key_ref.0), handshake["key_ref_hex"]);
    assert_eq!(hex(&session.binding.0), handshake["binding_hex"]);
    assert_eq!(
        hex(&session.node_proof(key).0),
        handshake["server_proof_hex"]
    );
    assert_eq!(
        hex(&session.subscriber_proof(key).0),
        handshake["client_proof_hex"]
    );
    assert_eq!(
        hex(&Transcript {
            binding: ChannelBinding::NONE,
            ..session
        }
        .node_proof(key)
        .0),
        handshake["tcp_binding_server_proof_hex"]
    );
}

/// The greeting layout: fixed fields, then the optional filter.
#[test]
fn the_greeting_layout_is_pinned() {
    let manifest = manifest();
    let hello = &manifest["hello"];
    let bytes = load("hello.bin");

    assert_eq!(
        u16::from_le_bytes([bytes[0], bytes[1]]),
        hello["protocol_version"].as_u64().unwrap() as u16
    );
    assert_eq!(
        u32::from_le_bytes(bytes[2..6].try_into().unwrap()),
        hello["streams"].as_u64().unwrap() as u32
    );
    assert_eq!(bytes[6], hello["codecs"].as_u64().unwrap() as u8);
    // Byte 7 is padding, always zero: this protocol carries no capabilities byte.
    assert_eq!(bytes[7], 0);
    let key_ref = KeyRef::derive(hello["key_material_utf8"].as_str().unwrap().as_bytes());
    assert_eq!(&bytes[8..40], &key_ref.0);
    // The nonce is 32 bytes of 0x00 — "00" in the manifest names the byte value, not the length.
    assert!(bytes[40..72].iter().all(|&byte| byte == 0));
    // No dictionary id trails the nonce: the greeting ends at byte 72.
    assert_eq!(bytes.len(), 72);
}

/// A greeting with a filter carries it length-prefixed after the fixed fields.
#[test]
fn the_filtered_greeting_carries_its_document() {
    let manifest = manifest();
    let hello = &manifest["hello_filtered"];
    let bytes = load("hello_filtered.bin");

    assert_eq!(bytes[7], 0, "no capabilities byte");
    let document = hello["filter"].as_str().unwrap();
    assert_eq!(bytes.len(), 72 + 4 + document.len());
    let length = u32::from_le_bytes(bytes[72..76].try_into().unwrap()) as usize;
    assert_eq!(length, document.len());
    assert_eq!(&bytes[76..], document.as_bytes());
}

/// The acknowledgement is eighteen bytes: no dictionary id field exists.
#[test]
fn the_acknowledgement_is_eighteen_bytes() {
    let manifest = manifest();
    let ack = &manifest["hello_ack"];
    let bytes = load("hello_ack.bin");

    assert_eq!(bytes.len(), 18);
    let parsed = HelloAck::parse(&bytes).unwrap();
    assert_eq!(
        parsed.protocol_version,
        ack["protocol_version"].as_u64().unwrap() as u16
    );
    assert_eq!(parsed.granted.0, ack["granted"].as_u64().unwrap() as u32);
    assert_eq!(
        parsed.session_id,
        ack["session_id"].as_str().unwrap().parse::<u64>().unwrap()
    );
    assert_eq!(parsed.codec as u8, ack["codec"].as_u64().unwrap() as u8);
    assert_eq!(
        parsed.keepalive_ms,
        ack["keepalive_ms"].as_u64().unwrap() as u16
    );
}

#[test]
fn the_refusal_carries_its_code_and_detail() {
    let manifest = manifest();
    let error = &manifest["error"];
    assert_eq!(
        ErrorCode::decode(error["code"].as_u64().unwrap() as u16),
        ErrorCode::BadRequest
    );
    let bytes = load("error.bin");
    let len = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
    assert_eq!(&bytes[4..4 + len], error["detail"].as_str().unwrap().as_bytes());
}

#[test]
fn the_lag_report_parses() {
    let manifest = manifest();
    let parsed = Lag::parse(&load("lag.bin")).unwrap();
    assert_eq!(
        parsed.dropped,
        manifest["lag"]["dropped"].as_str().unwrap().parse::<u64>().unwrap()
    );
    assert_eq!(
        parsed.resume_seq,
        manifest["lag"]["resume_seq"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
    );
}

#[test]
fn the_filter_verdict_parses() {
    let manifest = manifest();
    let ack = &manifest["filter_ack"];
    let parsed = aura_shreds_sdk::wire::FilterAck::parse(&load("filter_ack.bin")).unwrap();
    assert_eq!(parsed.accepted, ack["accepted"].as_bool().unwrap());
    assert_eq!(parsed.cost, ack["cost"].as_u64().unwrap() as u32);
    assert_eq!(parsed.detail, ack["detail"].as_str().unwrap());
}

#[test]
fn the_slot_start_record_parses() {
    let manifest = manifest();
    let start = &manifest["slot_start"];
    let parsed = SlotStart::parse(&load("slot_start.bin")).unwrap();

    assert_eq!(parsed.slot, start["slot"].as_str().unwrap().parse::<u64>().unwrap());
    assert_eq!(
        parsed.parent_slot,
        Some(start["parent_slot"].as_str().unwrap().parse::<u64>().unwrap())
    );
    assert_eq!(parsed.leader.unwrap()[0], start["leader_byte"].as_u64().unwrap() as u8);
    assert_eq!(
        parsed.shred_version,
        start["shred_version"].as_u64().unwrap() as u16
    );
    assert_eq!(
        parsed.rx_ts_ns,
        start["rx_ts_ns"].as_str().unwrap().parse::<u64>().unwrap()
    );
    assert_eq!(parsed.source, start["source"].as_u64().unwrap() as u16);
}

#[test]
fn the_bare_slot_start_has_no_parent_and_no_leader() {
    let manifest = manifest();
    let start = &manifest["slot_start_bare"];
    let parsed = SlotStart::parse(&load("slot_start_bare.bin")).unwrap();

    assert_eq!(parsed.slot, start["slot"].as_str().unwrap().parse::<u64>().unwrap());
    assert_eq!(parsed.parent_slot, None);
    assert_eq!(parsed.leader, None);
}

#[test]
fn the_slot_end_record_parses() {
    let manifest = manifest();
    let end = &manifest["slot_end"];
    let parsed = SlotEnd::parse(&load("slot_end.bin")).unwrap();

    assert_eq!(parsed.slot, end["slot"].as_str().unwrap().parse::<u64>().unwrap());
    assert_eq!(parsed.data_shreds, end["data_shreds"].as_u64().unwrap() as u32);
    assert_eq!(parsed.fec_sets, end["fec_sets"].as_u64().unwrap() as u32);
    assert_eq!(
        parsed.recovered_sets,
        end["recovered_sets"].as_u64().unwrap() as u32
    );
    assert_eq!(
        parsed.missing_shreds,
        end["missing_shreds"].as_u64().unwrap() as u32
    );
    assert_eq!(parsed.complete, end["complete"].as_bool().unwrap());
    assert_eq!(
        parsed.end_ts_ns,
        end["end_ts_ns"].as_str().unwrap().parse::<u64>().unwrap()
    );
}

#[test]
fn the_entry_record_parses() {
    let manifest = manifest();
    let entry = &manifest["entry"];
    let parsed = Entry::parse(&load("entry.bin")).unwrap();

    assert_eq!(parsed.slot, entry["slot"].as_str().unwrap().parse::<u64>().unwrap());
    assert_eq!(
        parsed.num_hashes,
        entry["num_hashes"].as_str().unwrap().parse::<u64>().unwrap()
    );
    assert_eq!(
        parsed.tx_count,
        entry["tx_count"].as_str().unwrap().parse::<u64>().unwrap()
    );
    assert_eq!(parsed.hash[0], entry["hash_byte"].as_u64().unwrap() as u8);
    assert_eq!(
        parsed.fec_set_index,
        entry["fec_set_index"].as_u64().unwrap() as u32
    );
    assert_eq!(parsed.entry_index, entry["entry_index"].as_u64().unwrap() as u32);
    assert_eq!(parsed.verification, Verification::StaleSchedule);
}

#[test]
fn the_duplicate_record_parses() {
    let manifest = manifest();
    let duplicate = &manifest["duplicate"];
    let parsed = Duplicate::parse(&load("duplicate.bin")).unwrap();

    assert_eq!(
        parsed.slot,
        duplicate["slot"].as_str().unwrap().parse::<u64>().unwrap()
    );
    assert_eq!(parsed.index, duplicate["index"].as_u64().unwrap() as u32);
    assert_eq!(
        parsed.first_source,
        duplicate["first_source"].as_u64().unwrap() as u16
    );
    assert_eq!(
        parsed.second_source,
        duplicate["second_source"].as_u64().unwrap() as u16
    );
    assert_eq!(
        parsed.detected_ns,
        duplicate["detected_ns"].as_str().unwrap().parse::<u64>().unwrap()
    );
    assert_eq!(parsed.is_data, duplicate["is_data"].as_bool().unwrap());
    assert_eq!(
        parsed.first_signature[0],
        duplicate["first_signature_byte"].as_u64().unwrap() as u8
    );
    assert_eq!(
        parsed.second_signature[0],
        duplicate["second_signature_byte"].as_u64().unwrap() as u8
    );
}

#[test]
fn the_plain_transaction_parses_field_by_field() {
    let manifest = manifest();
    let tx = &manifest["tx_simple"];
    let bytes = load("tx_simple.bin");
    assert_eq!(
        bytes.len(),
        manifest["tx_simple_len"].as_u64().unwrap() as usize
    );

    let parsed = Transaction::read(&bytes).unwrap();
    assert_eq!(parsed.slot(), tx["slot"].as_str().unwrap().parse::<u64>().unwrap());
    assert_eq!(
        parsed.parent_slot(),
        tx["parent_slot"].as_str().unwrap().parse::<u64>().unwrap()
    );
    assert_eq!(
        parsed.rx_ts_ns(),
        tx["rx_ts_ns"].as_str().unwrap().parse::<u64>().unwrap()
    );
    assert_eq!(
        parsed.emit_ts_ns(),
        tx["emit_ts_ns"].as_str().unwrap().parse::<u64>().unwrap()
    );
    assert_eq!(parsed.leader().unwrap()[0], tx["leader_byte"].as_u64().unwrap() as u8);
    assert_eq!(
        parsed.fec_set_index(),
        tx["fec_set_index"].as_u64().unwrap() as u32
    );
    assert_eq!(parsed.entry_index(), tx["entry_index"].as_u64().unwrap() as u32);
    assert_eq!(parsed.tx_index(), tx["tx_index"].as_u64().unwrap() as u32);
    assert_eq!(parsed.source_id(), tx["source_id"].as_u64().unwrap() as u16);
    assert_eq!(parsed.is_vote(), tx["is_vote"].as_bool().unwrap());
    assert_eq!(parsed.recovered(), tx["recovered"].as_bool().unwrap());
    assert_eq!(parsed.verification(), Verification::Verified);
    assert_eq!(
        parsed.account_count(),
        tx["account_count"].as_u64().unwrap() as usize
    );
    assert_eq!(
        parsed.instruction_count(),
        tx["instruction_count"].as_u64().unwrap() as usize
    );
    assert_eq!(
        parsed.signature_count(),
        tx["signature_count"].as_u64().unwrap() as usize
    );
    assert_eq!(
        parsed.message_version(),
        tx["message_version"].as_u64().unwrap() as u8
    );
    assert_eq!(parsed.lookup_count(), tx["lookup_count"].as_u64().unwrap() as usize);
    assert_eq!(
        parsed.required_signatures(),
        tx["required_signatures"].as_u64().unwrap() as u8
    );
    assert_eq!(
        parsed.readonly_signed(),
        tx["readonly_signed"].as_u64().unwrap() as u8
    );
    assert_eq!(
        parsed.readonly_unsigned(),
        tx["readonly_unsigned"].as_u64().unwrap() as u8
    );
    assert_eq!(
        parsed.signature().unwrap()[0],
        tx["signature_byte"].as_u64().unwrap() as u8
    );
    assert_eq!(
        parsed.recent_blockhash()[0],
        tx["blockhash_byte"].as_u64().unwrap() as u8
    );
    assert_eq!(parsed.raw_tx(), None);

    let instruction = parsed.instruction(0).unwrap();
    let expected_data: Vec<u8> = tx["instruction_data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_u64().unwrap() as u8)
        .collect();
    assert_eq!(instruction.data, expected_data);
    let expected_accounts: Vec<u8> = tx["instruction_accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_u64().unwrap() as u8)
        .collect();
    assert_eq!(instruction.accounts, expected_accounts);
    assert_eq!(
        instruction.program_id_index,
        tx["program_id_index"].as_u64().unwrap() as u8
    );
}

#[test]
fn the_full_transaction_parses() {
    let manifest = manifest();
    let tx = &manifest["tx_full"];
    let bytes = load("tx_full.bin");
    let parsed = Transaction::read(&bytes).unwrap();

    assert_eq!(
        parsed.account_count(),
        tx["account_count"].as_u64().unwrap() as usize
    );
    assert_eq!(
        parsed.instruction_count(),
        tx["instruction_count"].as_u64().unwrap() as usize
    );
    assert_eq!(
        parsed.signature_count(),
        tx["signature_count"].as_u64().unwrap() as usize
    );
    assert_eq!(parsed.lookup_count(), tx["lookup_count"].as_u64().unwrap() as usize);
    assert_eq!(parsed.is_vote(), tx["is_vote"].as_bool().unwrap());
    assert_eq!(parsed.recovered(), tx["recovered"].as_bool().unwrap());
    assert_eq!(
        parsed.message_version(),
        tx["message_version"].as_u64().unwrap() as u8
    );

    let raw = parsed.raw_tx().unwrap();
    assert_eq!(raw.len(), tx["raw_tx_len"].as_u64().unwrap() as usize);

    let instruction = parsed.instruction(0).unwrap();
    assert_eq!(
        instruction.data.len(),
        tx["instruction_data_len"].as_u64().unwrap() as usize
    );

    let lookups: Vec<_> = parsed.lookups().collect();
    assert_eq!(lookups[0].writable_indexes, &[1u8]);
    assert_eq!(lookups[0].readonly_indexes, &[2u8]);
    assert_eq!(
        lookups[0].account_key[0],
        tx["lookup0_key_byte"].as_u64().unwrap() as u8
    );
    assert_eq!(
        lookups[1].account_key[0],
        tx["lookup1_key_byte"].as_u64().unwrap() as u8
    );
}

#[test]
fn the_legacy_transaction_parses() {
    let manifest = manifest();
    let tx = &manifest["tx_legacy"];
    let bytes = load("tx_legacy.bin");
    let parsed = Transaction::read(&bytes).unwrap();

    assert_eq!(
        parsed.message_version(),
        tx["message_version"].as_u64().unwrap() as u8
    );
    assert_eq!(
        parsed.message_version(),
        aura_shreds_sdk::tx::MESSAGE_VERSION_LEGACY
    );
    assert_eq!(
        parsed.account_count(),
        tx["account_count"].as_u64().unwrap() as usize
    );
    assert_eq!(parsed.leader(), None);
    assert_eq!(parsed.verification(), Verification::UnknownLeader);
    let instruction = parsed.instruction(0).unwrap();
    let expected_data: Vec<u8> = tx["instruction_data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_u64().unwrap() as u8)
        .collect();
    assert_eq!(instruction.data, expected_data);
    assert_eq!(
        instruction.program_id_index,
        tx["program_id_index"].as_u64().unwrap() as u8
    );
}

#[test]
fn the_malformed_transaction_decodes_without_failing() {
    let manifest = manifest();
    let tx = &manifest["tx_malformed"];
    let bytes = load("tx_malformed.bin");
    let parsed = Transaction::read(&bytes).unwrap();

    assert_eq!(
        parsed.signature_count(),
        tx["signature_count"].as_u64().unwrap() as usize
    );
    assert_eq!(parsed.signature(), None);
    assert_eq!(
        parsed.account_count(),
        tx["account_count"].as_u64().unwrap() as usize
    );
    assert_eq!(
        parsed.instruction_count(),
        tx["instruction_count"].as_u64().unwrap() as usize
    );
    // The instruction names a program index past its own account list; decoding must not refuse it.
    assert_eq!(
        parsed.instruction(0).unwrap().program_id_index,
        tx["program_id_index"].as_u64().unwrap() as u8
    );
    assert_eq!(parsed.account_key(9), None);
}

#[test]
fn the_frame_headers_parse() {
    let manifest = manifest();

    let plain = load("frame_plain.bin");
    let header = parse_header(&plain).unwrap();
    assert_eq!(header.kind, FrameKind::Transaction);
    assert_eq!(
        header.seq,
        manifest["frame_plain"]["seq"].as_str().unwrap().parse::<u64>().unwrap()
    );
    assert!(!header.compressed);
    assert_eq!(header.codec, Codec::Plain);

    let zstd = load("frame_zstd.bin");
    let header = parse_header(&zstd).unwrap();
    assert_eq!(
        header.seq,
        manifest["frame_zstd"]["seq"].as_str().unwrap().parse::<u64>().unwrap()
    );
    assert!(header.compressed);
    assert_eq!(header.codec, Codec::Zstd);

    let matched = load("frame_matched.bin");
    let header = parse_header(&matched).unwrap();
    assert_eq!(
        header.matched.0,
        manifest["frame_matched"]["matched"].as_u64().unwrap() as u16
    );
    let indices: Vec<u8> = header.matched.indices().collect();
    assert_eq!(
        indices,
        manifest["frame_matched"]["matched_indices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_u64().unwrap() as u8)
            .collect::<Vec<_>>()
    );
}

#[test]
fn the_zstd_frame_inflates_to_the_plain_transaction() {
    let frame = load("frame_zstd.bin");
    let header = parse_header(&frame).unwrap();
    let payload = &frame[16..16 + header.len];
    let decoded = zstd::bulk::decompress(payload, 16 << 20).expect("inflate");
    assert_eq!(decoded, load("tx_simple.bin"));
}

/// A raw shred round trips its payload, and the parity marker is recognised.
#[test]
fn a_raw_shred_round_trips() {
    let payload = [9u8, 8, 7, 6, 5];
    let mut bytes = vec![0u8; 32 + payload.len()];
    bytes[0..8].copy_from_slice(&412_500_103u64.to_le_bytes());
    bytes[8..12].copy_from_slice(&47u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&32u32.to_le_bytes());
    bytes[16..24].copy_from_slice(&1_900_000_100_900u64.to_le_bytes());
    bytes[24..26].copy_from_slice(&3u16.to_le_bytes());
    bytes[26] = 1; // the parity marker
    bytes[32..].copy_from_slice(&payload);

    let parsed = RawShred::parse(&bytes).unwrap();
    assert_eq!(parsed.slot, 412_500_103);
    assert_eq!(parsed.index, 47);
    assert_eq!(parsed.fec_set_index, 32);
    assert_eq!(parsed.rx_ts_ns, 1_900_000_100_900);
    assert_eq!(parsed.source, 3);
    assert!(!parsed.is_data, "the parity marker was recognised");
    assert_eq!(parsed.bytes, payload);
}

/// The stream constants stay part of the contract this file pins.
#[test]
fn stream_bits_are_stable() {
    assert_eq!(StreamMask::TRANSACTIONS, 1);
    assert_eq!(StreamMask::ALL.0, 0b0101_1111);
}
