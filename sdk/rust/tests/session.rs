//! Exercises the client against a stub node that speaks the real wire format.
//!
//! The frames it sends are the committed fixtures, so this checks framing, authentication and
//! decompression without re-asserting layout that `vectors.rs` already pins down.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use std::path::PathBuf;

use aura_shreds_sdk::{
    Client, Config, Event, FilterMask, StreamMask,
    auth::{ChannelBinding, KeyRef, Transcript},
    wire::{HEADER_LEN, FrameKind, codec_bit, parse_header},
};

fn load(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|err| panic!("reading {name}: {err}"))
}

/// The encoded acknowledgement: eighteen bytes, no dictionary id field.
fn ack_bytes(codec: aura_shreds_sdk::wire::Codec, granted: u32) -> Vec<u8> {
    let mut body = vec![0u8; 18];
    body[0..2].copy_from_slice(&1u16.to_le_bytes());
    body[2..6].copy_from_slice(&granted.to_le_bytes());
    body[6..14].copy_from_slice(&99u64.to_le_bytes());
    body[14] = codec as u8;
    body[16..18].copy_from_slice(&20_000u16.to_le_bytes());
    body
}

fn ack_frame(codec: aura_shreds_sdk::wire::Codec, granted: u32) -> Vec<u8> {
    let mut frame = Vec::new();
    aura_shreds_sdk::wire::append_frame(
        &mut frame,
        FrameKind::HelloAck,
        0,
        &ack_bytes(codec, granted),
    );
    frame
}

/// A refusal, encoded the way the node sends one.
fn refusal_frame(code: aura_shreds_sdk::wire::ErrorCode, detail: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(code as u16).to_le_bytes());
    body.extend_from_slice(&(detail.len() as u16).to_le_bytes());
    body.extend_from_slice(detail.as_bytes());
    let mut frame = Vec::new();
    aura_shreds_sdk::wire::append_frame(&mut frame, FrameKind::Error, 0, &body);
    frame
}

/// The key the stub proves against, and the client connects with.
const KEY: &[u8] = b"stub-key";

/// Reads the client's greeting off `socket`, or fails when it closes first.
async fn read_greeting(socket: &mut tokio::net::TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    loop {
        let read = socket.read_buf(&mut buffer).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "client closed before greeting",
            ));
        }
        if buffer.len() < HEADER_LEN {
            continue;
        }
        let header = parse_header(&buffer).expect("header");
        let end = HEADER_LEN + header.len;
        if buffer.len() < end {
            continue;
        }
        assert_eq!(header.kind, FrameKind::Hello);
        return Ok(buffer[..end].to_vec());
    }
}

/// Runs the handshake as the node performs it, up to but excluding the ack.
///
/// The node proves with [`KEY`] but never checks the client's proof: a client holding the wrong key
/// refuses the node's proof and drops before sending one, and this stub must not panic about it —
/// the tests assert the client's error, not the node's.
async fn serve_handshake(socket: &mut tokio::net::TcpStream) -> std::io::Result<Vec<u8>> {
    let greeting = read_greeting(socket).await?;
    let body = &greeting[HEADER_LEN..];
    assert_eq!(body[6], codec_bit::ZSTD, "the greeting offers only zstd");
    assert_eq!(body[7], 0, "the padding byte stays zero");

    let key_ref = KeyRef(
        body[8..40]
            .try_into()
            .expect("a 32-byte key reference"), // TryFrom<&[u8]> for [u8; 32]
    );
    assert!(
        !body.windows(KEY.len()).any(|window| window == KEY),
        "the key itself crossed the wire"
    );
    let client_nonce: [u8; 32] = body[40..72].try_into().unwrap();

    let server_nonce = [0x5au8; 32];
    let transcript = Transcript {
        key_ref,
        client_nonce,
        server_nonce,
        binding: ChannelBinding::NONE,
    };
    let mut challenge_body = Vec::new();
    challenge_body.extend_from_slice(&server_nonce);
    challenge_body.extend_from_slice(&transcript.node_proof(KEY).0);
    let mut challenge = Vec::new();
    aura_shreds_sdk::wire::append_frame(
        &mut challenge,
        FrameKind::Challenge,
        0,
        &challenge_body,
    );
    socket.write_all(&challenge).await?;

    // The client's proof, when it sends one. It may drop first.
    let mut buffer = Vec::new();
    loop {
        let read = socket.read_buf(&mut buffer).await?;
        if read == 0 {
            return Ok(greeting);
        }
        if buffer.len() < HEADER_LEN {
            continue;
        }
        let header = parse_header(&buffer).expect("header");
        let end = HEADER_LEN + header.len;
        if buffer.len() < end {
            continue;
        }
        assert_eq!(header.kind, FrameKind::Prove);
        break;
    }
    Ok(greeting)
}

/// A stub node that completes the handshake and then plays `frames`.
async fn stub_node(listener: tokio::net::TcpListener, frames: Vec<Vec<u8>>) {
    let (mut socket, _) = listener.accept().await.expect("accept");
    if serve_handshake(&mut socket).await.is_err() {
        return;
    }
    socket
        .write_all(&ack_frame(aura_shreds_sdk::wire::Codec::Zstd, 1))
        .await
        .expect("write ack");
    for frame in frames {
        socket.write_all(&frame).await.expect("write frame");
    }
    // Held open until the client has read everything; closed on drop.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
}

async fn connect_to(addr: std::net::SocketAddr, config: Config) -> Client {
    Client::connect(addr, config).await.expect("connect")
}


#[tokio::test]
async fn a_client_connects_and_reads_a_transaction() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let node = tokio::spawn(stub_node(listener, vec![load("frame_plain.bin")]));

    let mut client = connect_to(addr, Config::new(KEY)).await;
    node.await.unwrap();

    assert_eq!(client.granted(), StreamMask(StreamMask::TRANSACTIONS));
    assert_eq!(client.session_id(), 99);
    assert_eq!(client.keepalive_ms(), 20_000);

    match client.next_event().await.unwrap() {
        Event::Transaction { tx, matched } => {
            assert_eq!(tx.slot(), 412_500_101);
            assert_eq!(matched, FilterMask::NONE);
        }
        other => panic!("expected a transaction, got {other:?}"),
    }
}

#[tokio::test]
async fn a_compressed_transaction_inflates() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let node = tokio::spawn(stub_node(listener, vec![load("frame_zstd.bin")]));

    let mut client = connect_to(addr, Config::new(KEY)).await;
    node.await.unwrap();

    match client.next_event().await.unwrap() {
        Event::Transaction { tx, .. } => assert_eq!(tx.slot(), 412_500_101),
        other => panic!("expected a transaction, got {other:?}"),
    }
    assert!(client.decoded_bytes() > client.wire_bytes() - HEADER_LEN as u64);
}

#[tokio::test]
async fn a_matched_transaction_reports_its_filters() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let node = tokio::spawn(stub_node(listener, vec![load("frame_matched.bin")]));

    let mut client = connect_to(addr, Config::new(KEY)).await;
    node.await.unwrap();

    match client.next_event().await.unwrap() {
        Event::Transaction { matched, .. } => {
            assert_eq!(matched.0, 9);
            let indices: Vec<u8> = matched.indices().collect();
            assert_eq!(indices, vec![0, 3]);
        }
        other => panic!("expected a transaction, got {other:?}"),
    }
}

#[tokio::test]
async fn a_refusal_frame_surfaces_as_a_rejection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let node = tokio::spawn(stub_node(
        listener,
        vec![refusal_frame(
            aura_shreds_sdk::wire::ErrorCode::TooSlow,
            "you were too slow",
        )],
    ));

    let mut client = connect_to(addr, Config::new(KEY)).await;
    node.await.unwrap();

    let error = client.next_event().await.unwrap_err();
    assert!(
        error.to_string().contains("too slow"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn a_ping_is_answered_automatically() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut ping = Vec::new();
    aura_shreds_sdk::wire::append_frame(&mut ping, FrameKind::Ping, 1, &[]);
    let node = tokio::spawn(stub_node(listener, vec![ping]));

    let mut client = connect_to(addr, Config::new(KEY)).await;
    node.await.unwrap();

    match client.next_event().await.unwrap() {
        Event::Ping => {}
        other => panic!("expected a ping, got {other:?}"),
    }
}

#[tokio::test]
async fn a_sequence_gap_is_counted() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut first = Vec::new();
    aura_shreds_sdk::wire::append_frame(&mut first, FrameKind::Pong, 5, &[]);
    let mut second = Vec::new();
    aura_shreds_sdk::wire::append_frame(&mut second, FrameKind::Pong, 9, &[]);
    let node = tokio::spawn(stub_node(listener, vec![first, second]));

    let mut client = connect_to(addr, Config::new(KEY)).await;
    node.await.unwrap();

    client.next_event().await.unwrap();
    client.next_event().await.unwrap();
    // The first frame seeds the expectation; 9 - (5 + 1) is what the second reports.
    assert_eq!(client.dropped(), 3);
}

#[tokio::test]
async fn a_lag_frame_updates_the_drop_count_and_resume_point() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut lag = Vec::new();
    let lag_body = load("lag.bin");
    aura_shreds_sdk::wire::append_frame(&mut lag, FrameKind::Lag, 3, &lag_body);
    let node = tokio::spawn(stub_node(listener, vec![lag]));

    let mut client = connect_to(addr, Config::new(KEY)).await;
    node.await.unwrap();

    match client.next_event().await.unwrap() {
        Event::Lag(lag) => {
            assert_eq!(lag.dropped, 7_777);
            assert_eq!(lag.resume_seq, 555_000);
        }
        other => panic!("expected a lag report, got {other:?}"),
    }
    assert_eq!(client.dropped(), 7_777);
}

#[tokio::test]
async fn an_unknown_frame_kind_arrives_as_other() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut unknown = Vec::new();
    unknown.extend_from_slice(&3u32.to_le_bytes());
    unknown.push(200);
    unknown.push(0);
    unknown.extend_from_slice(&0u16.to_le_bytes());
    unknown.extend_from_slice(&2u64.to_le_bytes());
    unknown.extend_from_slice(&[1, 2, 3]);
    let node = tokio::spawn(stub_node(listener, vec![unknown]));

    let mut client = connect_to(addr, Config::new(KEY)).await;
    node.await.unwrap();

    match client.next_event().await.unwrap() {
        Event::Other { kind, payload } => {
            assert_eq!(kind, 200);
            assert_eq!(payload, &[1, 2, 3]);
        }
        other => panic!("expected an unknown frame, got {other:?}"),
    }
}

#[tokio::test]
async fn a_wrong_key_is_refused_by_the_client() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let node = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        // The client refuses the proof before sending one of its own, so this ends early.
        let _ = serve_handshake(&mut socket).await;
    });

    let error = Client::connect(addr, Config::new(b"not-the-key".to_vec()))
        .await
        .expect_err("a wrong key must not authenticate");
    node.await.unwrap();
    assert!(error.to_string().contains("did not prove"), "{error}");
}

#[tokio::test]
async fn a_refusal_before_the_challenge_surfaces_the_node_reason() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let node = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let _ = read_greeting(&mut socket).await;
        socket
            .write_all(&refusal_frame(
                aura_shreds_sdk::wire::ErrorCode::Unauthorized,
                "unknown key",
            ))
            .await
            .expect("write refusal");
    });

    let error = Client::connect(addr, Config::new(KEY))
        .await
        .expect_err("an unauthorized key must be refused");
    node.await.unwrap();
    assert!(error.to_string().contains("unknown key"), "{error}");
}

#[tokio::test]
async fn a_filter_in_the_greeting_is_sent_before_the_stream_starts() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let node = tokio::spawn(stub_node(listener, vec![]));

    let config = Config::new(KEY).filter(r#"{"is_vote":{"value":false}}"#);
    let _client = connect_to(addr, config).await;
    node.await.unwrap();
}

#[tokio::test]
async fn submit_filter_writes_a_submission_frame() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let node = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        if serve_handshake(&mut socket).await.is_err() {
            return;
        }
        socket
            .write_all(&ack_frame(aura_shreds_sdk::wire::Codec::Zstd, 1))
            .await
            .expect("write ack");
        // The filter submission the client sends.
        let mut buffer = Vec::new();
        loop {
            socket.read_buf(&mut buffer).await.expect("read");
            if buffer.len() < HEADER_LEN {
                continue;
            }
            let header = parse_header(&buffer).expect("header");
            let end = HEADER_LEN + header.len;
            if buffer.len() < end {
                continue;
            }
            assert_eq!(header.kind, FrameKind::SetFilter);
            let json = std::str::from_utf8(&buffer[HEADER_LEN..end]).expect("json");
            assert!(json.contains("\"filters\""), "{json}");
            break;
        }
    });

    let mut client = Client::connect(addr, Config::new(KEY)).await.unwrap();
    client
        .set_filter(r#"{"is_vote":{"value":false}}"#)
        .await
        .unwrap();
    node.await.unwrap();
}

#[tokio::test]
async fn a_version_mismatch_is_reported() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let node = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        if serve_handshake(&mut socket).await.is_err() {
            return;
        }
        let mut body = vec![0u8; 18];
        body[0..2].copy_from_slice(&99u16.to_le_bytes()); // wrong version
        let mut frame = Vec::new();
        aura_shreds_sdk::wire::append_frame(&mut frame, FrameKind::HelloAck, 0, &body);
        socket.write_all(&frame).await.expect("write");
    });

    let error = Client::connect(addr, Config::new(KEY))
        .await
        .expect_err("a version mismatch must be refused");
    node.await.unwrap();
    assert!(error.to_string().contains("version"), "{error}");
}

#[tokio::test]
async fn an_uncompressed_negotiation_is_refused() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let node = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        if serve_handshake(&mut socket).await.is_err() {
            return;
        }
        socket
            .write_all(&ack_frame(aura_shreds_sdk::wire::Codec::Plain, 1))
            .await
            .expect("write");
    });

    let error = Client::connect(addr, Config::new(KEY))
        .await
        .expect_err("an uncompressed stream must be refused");
    node.await.unwrap();
    assert!(error.to_string().contains("zstd"), "{error}");
}

/// The greeting this client sends offers zstd and nothing else, in the fixed position.
#[test]
fn the_greeting_codec_byte_is_zstd() {
    let mut body = Vec::new();
    aura_shreds_sdk::wire::Hello {
        streams: StreamMask::ALL,
        codecs: codec_bit::ZSTD,
        key_ref: KeyRef::derive(b"k"),
        client_nonce: [0; 32],
        filter: None,
    }
    .append(&mut body);
    assert_eq!(body[6], codec_bit::ZSTD);
    assert_eq!(body[7], 0, "the padding byte stays zero");
    // No capabilities byte and no dictionary id: the greeting ends at byte 72.
    assert_eq!(body.len(), 72);
}
