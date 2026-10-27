//! Frame framing and the control messages of the aura-shreds protocol.
//!
//! Byte layout only. Keeping it apart from the session logic lets a consumer drive the protocol
//! through some other transport — a proxy, a replay, a test double — with the parsing alone.
//!
//! Every frame is a 16-byte header followed by a payload:
//!
//! ```text
//!  0   u32  len       payload bytes that follow
//!  4   u8   kind
//!  5   u8   flags     bits 0..1 codec, bit 2 body is compressed
//!  6   u16  matched   which named filters matched, when the connection named any
//!  8   u64  seq       per-connection, monotonic
//! 16        payload
//! ```

use crate::{
    auth::{KeyRef, Proof},
    error::{Error, Outcome},
};

/// Protocol version this build speaks.
pub const PROTOCOL_VERSION: u16 = 1;

/// Header width.
pub const HEADER_LEN: usize = 16;

/// Ceiling on any frame payload.
pub const MAX_PAYLOAD: usize = 16 << 20;

/// Ceiling on a control message read before the node has authenticated itself.
///
/// The length field belongs to the peer, and at this stage of the exchange the peer has proved
/// nothing — so the ceiling is what any legitimate message of this kind can be, not the global
/// frame ceiling. Judged by [`MAX_PAYLOAD`] instead, any address you dial could cost you sixteen
/// megabytes for the price of a header.
pub const MAX_PRE_AUTH_BYTES: usize = 64 * 1024;

/// What a frame carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    /// Produced when reading a kind byte this build does not know.
    Unrecognized = 0,
    /// A decoded transaction.
    Transaction = 1,
    /// A proof-of-history entry.
    Entry = 2,
    /// The first shred of a slot arrived.
    SlotStart = 3,
    /// A slot finished.
    SlotEnd = 4,
    /// A leader equivocated.
    Duplicate = 5,
    /// A shred republished verbatim.
    RawShred = 6,
    /// Frames this connection missed.
    Lag = 7,
    /// Ingress source statistics.
    SourceStats = 8,
    /// A subscriber greeting.
    Hello = 9,
    /// The reply to a greeting.
    HelloAck = 10,
    /// The verdict on a filter.
    FilterAck = 11,
    /// A refusal or a disconnect.
    Error = 12,
    /// A liveness probe.
    Ping = 13,
    /// The answer to a probe.
    Pong = 14,
    /// A filter submission.
    SetFilter = 15,
    /// The node nonce and its proof.
    Challenge = 16,
    /// The subscriber proof.
    Prove = 17,
}

impl FrameKind {
    /// Maps a kind byte; anything unlisted becomes [`FrameKind::Unrecognized`].
    ///
    /// Unlisted is not a failure: a frame type added after this build must be skipped, not treated
    /// as fatal, or the addition would disconnect every running subscriber.
    #[inline]
    pub const fn decode(byte: u8) -> Self {
        match byte {
            1 => Self::Transaction,
            2 => Self::Entry,
            3 => Self::SlotStart,
            4 => Self::SlotEnd,
            5 => Self::Duplicate,
            6 => Self::RawShred,
            7 => Self::Lag,
            8 => Self::SourceStats,
            9 => Self::Hello,
            10 => Self::HelloAck,
            11 => Self::FilterAck,
            12 => Self::Error,
            13 => Self::Ping,
            14 => Self::Pong,
            15 => Self::SetFilter,
            16 => Self::Challenge,
            17 => Self::Prove,
            _ => Self::Unrecognized,
        }
    }
}

/// Streams a subscriber can request.
///
/// The node grants the intersection of the request and the key's allowance, so over-asking is not
/// an error — compare the granted mask on the ack instead.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct StreamMask(pub u32);

impl StreamMask {
    /// Decoded transactions.
    pub const TRANSACTIONS: u32 = 1 << 0;
    /// Proof-of-history entries.
    pub const ENTRIES: u32 = 1 << 1;
    /// Slot starts and ends.
    pub const SLOT_EVENTS: u32 = 1 << 2;
    /// Equivocation reports.
    pub const DUPLICATES: u32 = 1 << 3;
    /// Every shred verbatim, before the node verifies or decodes anything.
    ///
    /// The highest-rate stream published — a multiple of [`Self::TRANSACTIONS`], since a shred is a
    /// fragment and most fragments carry votes. Nothing on it is claimed to be leader-signed.
    pub const RAW_SHREDS: u32 = 1 << 4;
    /// Reserved on the wire; no producer exists.
    pub const SOURCE_STATS: u32 = 1 << 5;
    /// Vote transactions, which `TRANSACTIONS` excludes unless this is also set.
    pub const VOTES: u32 = 1 << 6;

    /// Every stream that is actually published.
    pub const ALL: Self = Self(
        Self::TRANSACTIONS
            | Self::ENTRIES
            | Self::SLOT_EVENTS
            | Self::DUPLICATES
            | Self::RAW_SHREDS
            | Self::VOTES,
    );

    /// Whether every stream in `other` is present.
    #[inline]
    pub const fn contains(self, other: u32) -> bool {
        self.0 & other == other
    }
}

/// Compression codecs. The value is what travels in the frame flags.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum Codec {
    /// The body is as sent.
    #[default]
    Plain = 0,
    /// lz4, which this SDK never offers.
    Lz4 = 1,
    /// zstd.
    Zstd = 2,
}

impl Codec {
    /// Maps a codec byte.
    #[inline]
    pub const fn decode(byte: u8) -> Self {
        match byte {
            1 => Self::Lz4,
            2 => Self::Zstd,
            _ => Self::Plain,
        }
    }
}

/// Handshake bits, one per codec this build can inflate.
pub mod codec_bit {
    /// Uncompressed, which every peer must support.
    pub const NONE: u8 = 1 << 0;
    /// lz4.
    pub const LZ4: u8 = 1 << 1;
    /// zstd.
    pub const ZSTD: u8 = 1 << 2;
}

/// Why the node refused or disconnected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
    /// The key or secret was not accepted.
    Unauthorized = 1,
    /// The key does not permit what was asked.
    Forbidden = 2,
    /// The subscriber fell too far behind.
    TooSlow = 3,
    /// Too many requests.
    RateLimited = 4,
    /// Malformed, or against node policy.
    BadRequest = 5,
    /// The node is going away.
    Shutdown = 6,
    /// The node does not speak this version.
    UnsupportedVersion = 7,
    /// A code this build does not know.
    Other = 0,
}

impl ErrorCode {
    /// Maps a code; anything unlisted becomes [`ErrorCode::Other`].
    #[inline]
    pub const fn decode(value: u16) -> Self {
        match value {
            1 => Self::Unauthorized,
            2 => Self::Forbidden,
            3 => Self::TooSlow,
            4 => Self::RateLimited,
            5 => Self::BadRequest,
            6 => Self::Shutdown,
            7 => Self::UnsupportedVersion,
            _ => Self::Other,
        }
    }
}

/// How much the node could vouch for a transaction or entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verification {
    /// The leader's signature over the FEC set's merkle root checked out.
    Verified,
    /// The node runs with signature verification switched off.
    Disabled,
    /// No leader is known for the slot.
    UnknownLeader,
    /// The leader schedule is behind.
    StaleSchedule,
}

impl Verification {
    /// Reads the one-byte encoding used by entry frames.
    #[inline]
    pub(crate) const fn decode(byte: u8) -> Self {
        match byte {
            0 => Self::Verified,
            2 => Self::UnknownLeader,
            3 => Self::StaleSchedule,
            _ => Self::Disabled,
        }
    }
}

/// Which of a connection's named filters a frame matched.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct FilterMask(pub u16);

impl FilterMask {
    /// Named filters one connection may hold.
    pub const CAPACITY: usize = 16;

    /// Nothing matched, or nothing was named.
    pub const NONE: Self = Self(0);

    /// Whether the filter at `index` matched.
    #[inline]
    pub const fn has(self, index: u8) -> bool {
        self.0 & (1u16 << index) != 0
    }

    /// Whether nothing matched.
    #[inline]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Indices of the filters that matched.
    pub fn indices(self) -> impl Iterator<Item = u8> {
        (0..Self::CAPACITY as u8).filter(move |index| self.has(*index))
    }
}

/// A decoded frame header.
#[derive(Clone, Copy, Debug)]
pub struct Header {
    /// Payload bytes following the header.
    pub len: usize,
    /// What the payload is, as far as this build recognises it.
    pub kind: FrameKind,
    /// The kind byte exactly as it arrived, so an unrecognized frame keeps its identity.
    pub raw_kind: u8,
    /// Whether the payload is compressed.
    pub compressed: bool,
    /// The codec the payload was compressed with.
    pub codec: Codec,
    /// Which named filters the frame matched.
    pub matched: FilterMask,
    /// Per-connection sequence number. A gap is exactly what was dropped.
    pub seq: u64,
}

/// Parses a frame header.
pub fn parse_header(bytes: &[u8]) -> Outcome<Header> {
    if bytes.len() < HEADER_LEN {
        return Err(Error::short("frame header", HEADER_LEN, bytes.len()));
    }
    let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(Error::Oversized {
            message: "frame",
            declared: len,
            limit: MAX_PAYLOAD,
        });
    }
    let flags = bytes[5];
    Ok(Header {
        len,
        kind: FrameKind::decode(bytes[4]),
        raw_kind: bytes[4],
        compressed: flags & 0b100 != 0,
        codec: Codec::decode(flags & 0b11),
        matched: FilterMask(u16::from_le_bytes([bytes[6], bytes[7]])),
        seq: u64::from_le_bytes(bytes[8..16].try_into().expect("bounds checked")),
    })
}

/// Appends a frame carrying `payload` to `out`.
pub fn append_frame(out: &mut Vec<u8>, kind: FrameKind, seq: u64, payload: &[u8]) {
    out.reserve(HEADER_LEN + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.push(kind as u8);
    out.push(0);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(payload);
}

/// What a subscriber offers when it connects.
///
/// **Carries no credential.** The key is named by [`KeyRef`], a one-way function of it, and
/// possession is proved afterwards — see [`crate::auth`]. A captured greeting is worth nothing.
#[derive(Clone, Debug)]
pub struct Hello {
    /// Streams to subscribe to.
    pub streams: StreamMask,
    /// Codecs this build can inflate, as a bitmask — see [`codec_bit`].
    pub codecs: u8,
    /// Which key is claimed, without disclosing it.
    pub key_ref: KeyRef,
    /// Fresh per connection, so a captured node proof cannot be replayed at this subscriber.
    pub client_nonce: [u8; 32],
    /// A filter document to install before the stream starts, if any.
    pub filter: Option<String>,
}

impl Hello {
    /// Appends the encoded greeting to `out`.
    ///
    /// The reference and the nonce are fixed width, so the greeting has no variable-length
    /// credential fields — there is no credential in it to be variable. The filter trails them,
    /// length-prefixed with a `u32` because a filter naming two thousand accounts is far past
    /// 64 KiB.
    pub fn append(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        out.extend_from_slice(&self.streams.0.to_le_bytes());
        out.push(self.codecs);
        out.push(0);
        out.extend_from_slice(&self.key_ref.0);
        out.extend_from_slice(&self.client_nonce);
        if let Some(filter) = &self.filter {
            out.extend_from_slice(&(filter.len() as u32).to_le_bytes());
            out.extend_from_slice(filter.as_bytes());
        }
    }
}

/// The node's nonce and its proof that it holds the key.
///
/// Sent before the subscriber has proved anything. Checking it is what tells you the peer is the
/// node rather than something sitting in front of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Challenge {
    /// Chosen by the node.
    pub server_nonce: [u8; 32],
    /// `HMAC(key, node domain ‖ transcript)`.
    pub proof: Proof,
}

impl Challenge {
    /// Encoded width.
    pub const SIZE: usize = 64;

    /// Parses the message.
    pub fn parse(bytes: &[u8]) -> Outcome<Self> {
        if bytes.len() < Self::SIZE {
            return Err(Error::short("challenge", Self::SIZE, bytes.len()));
        }
        let mut server_nonce = [0u8; 32];
        server_nonce.copy_from_slice(&bytes[0..32]);
        let mut proof = [0u8; 32];
        proof.copy_from_slice(&bytes[32..64]);
        Ok(Self {
            server_nonce,
            proof: Proof(proof),
        })
    }
}

/// The subscriber's proof that it holds the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prove {
    /// `HMAC(key, subscriber domain ‖ transcript)`.
    pub proof: Proof,
}

impl Prove {
    /// Encoded width.
    pub const SIZE: usize = 32;

    /// Appends the encoded message to `out`.
    pub fn append(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.proof.0);
    }
}

/// What the node settled.
#[derive(Clone, Copy, Debug)]
pub struct HelloAck {
    /// Version the node speaks.
    pub protocol_version: u16,
    /// Streams actually granted.
    pub granted: StreamMask,
    /// This connection's node-assigned id, which the operator's logs are keyed by.
    pub session_id: u64,
    /// The negotiated codec.
    pub codec: Codec,
    /// How often the node pings an idle connection.
    pub keepalive_ms: u16,
}

impl HelloAck {
    /// Encoded width. No dictionary id field: this protocol has none.
    pub const SIZE: usize = 18;

    /// Parses an acknowledgement.
    pub fn parse(bytes: &[u8]) -> Outcome<Self> {
        if bytes.len() < Self::SIZE {
            return Err(Error::short("hello ack", Self::SIZE, bytes.len()));
        }
        Ok(Self {
            protocol_version: u16::from_le_bytes([bytes[0], bytes[1]]),
            granted: StreamMask(u32::from_le_bytes(
                bytes[2..6].try_into().expect("bounds checked"),
            )),
            session_id: u64::from_le_bytes(bytes[6..14].try_into().expect("bounds checked")),
            codec: Codec::decode(bytes[14]),
            keepalive_ms: u16::from_le_bytes([bytes[16], bytes[17]]),
        })
    }
}

/// The node refused, or is closing the connection.
#[derive(Clone, Debug)]
pub struct Refusal {
    /// Why.
    pub code: ErrorCode,
    /// A human-readable explanation.
    pub detail: String,
}

impl Refusal {
    /// Parses an error message.
    pub fn parse(bytes: &[u8]) -> Outcome<Self> {
        if bytes.len() < 4 {
            return Err(Error::short("error message", 4, bytes.len()));
        }
        let len = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
        let end = (4 + len).min(bytes.len());
        Ok(Self {
            code: ErrorCode::decode(u16::from_le_bytes([bytes[0], bytes[1]])),
            detail: String::from_utf8_lossy(&bytes[4..end]).into_owned(),
        })
    }
}

/// Frames this connection missed, and where the stream resumes.
#[derive(Clone, Copy, Debug)]
pub struct Lag {
    /// How many frames were dropped.
    pub dropped: u64,
    /// The sequence number the stream continues from.
    pub resume_seq: u64,
}

impl Lag {
    /// Encoded width.
    pub const SIZE: usize = 16;

    /// Parses a lag report.
    pub fn parse(bytes: &[u8]) -> Outcome<Self> {
        if bytes.len() < Self::SIZE {
            return Err(Error::short("lag report", Self::SIZE, bytes.len()));
        }
        Ok(Self {
            dropped: u64::from_le_bytes(bytes[0..8].try_into().expect("bounds checked")),
            resume_seq: u64::from_le_bytes(bytes[8..16].try_into().expect("bounds checked")),
        })
    }
}

/// The node's verdict on a submitted filter.
#[derive(Clone, Debug)]
pub struct FilterAck {
    /// Whether the filter is now in force.
    pub accepted: bool,
    /// Measured cost, whether or not it was accepted.
    pub cost: u32,
    /// Why it was refused, when it was.
    pub detail: String,
}

impl FilterAck {
    /// Parses a filter acknowledgement.
    pub fn parse(bytes: &[u8]) -> Outcome<Self> {
        if bytes.len() < 8 {
            return Err(Error::short("filter ack", 8, bytes.len()));
        }
        let len = u16::from_le_bytes([bytes[6], bytes[7]]) as usize;
        let end = (8 + len).min(bytes.len());
        Ok(Self {
            accepted: bytes[0] != 0,
            cost: u32::from_le_bytes(bytes[2..6].try_into().expect("bounds checked")),
            detail: String::from_utf8_lossy(&bytes[8..end]).into_owned(),
        })
    }
}
