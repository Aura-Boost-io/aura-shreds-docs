//! The subscriber session: connect, authenticate, then read events.

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::ToSocketAddrs,
};

use crate::{
    auth::{ChannelBinding, KeyRef, Transcript, fresh_nonce},
    config::{Config, NamedFilter, filter_document},
    error::{Error, Outcome},
    records::{Duplicate, Entry, RawShred, SlotEnd, SlotStart},
    tx::Transaction,
    wire::{
        self, Codec, FilterAck, FilterMask, FrameKind, Hello, HelloAck, Lag,
        MAX_PRE_AUTH_BYTES, PROTOCOL_VERSION, Prove, append_frame, parse_header,
    },
};

/// Something the node sent.
#[derive(Debug)]
#[non_exhaustive]
pub enum Event<'a> {
    /// A decoded transaction, and which of this connection's named filters it matched.
    Transaction {
        /// The transaction.
        tx: Transaction<'a>,
        /// Which named filters it matched. Empty when the connection named none.
        ///
        /// A transaction matching several filters arrives once, with every match recorded, rather
        /// than once per filter.
        matched: FilterMask,
    },
    /// A proof-of-history entry.
    Entry(Entry),
    /// The first shred of a slot arrived.
    SlotStart(SlotStart),
    /// A slot finished.
    SlotEnd(SlotEnd),
    /// A leader equivocated.
    Duplicate(Duplicate),
    /// A shred republished exactly as it arrived. Needs the `raw_shreds` stream.
    ///
    /// Delivered before the node verified or decoded anything, so nothing on it is claimed to be
    /// leader-signed — see [`RawShred`].
    RawShred(RawShred<'a>),
    /// Frames this connection missed.
    Lag(Lag),
    /// The node's verdict on a submitted filter.
    FilterAck(FilterAck),
    /// A liveness probe, already answered.
    Ping,
    /// The answer to a probe this subscriber sent.
    Pong,
    /// A frame kind this build does not know.
    ///
    /// Carried rather than dropped so a newer node does not break an older subscriber.
    Other {
        /// The kind byte as it arrived.
        kind: u8,
        /// The frame's payload.
        payload: &'a [u8],
    },
}

/// Bytes read from the socket that do not yet form a whole frame.
///
/// Whole frames are consumed from the front; whatever trails is moved to the front of the storage
/// once the consumer is done with it. Compacting in place keeps the steady-state allocation at one
/// buffer instead of growing without bound behind a slow consumer.
struct RecvBuffer {
    storage: Vec<u8>,
    /// Bytes at the front of `storage` that belong to the frame being assembled.
    filled: usize,
}

impl RecvBuffer {
    fn new() -> Self {
        Self {
            storage: Vec::with_capacity(64 * 1024),
            filled: 0,
        }
    }

    /// Bytes currently held.
    #[inline]
    fn len(&self) -> usize {
        self.filled
    }

    /// The held bytes.
    #[inline]
    fn as_slice(&self) -> &[u8] {
        &self.storage[..self.filled]
    }

    /// Grows the storage so `need` bytes can be held.
    fn make_room(&mut self, need: usize) {
        if self.storage.len() < need {
            self.storage.resize(need, 0);
        }
    }

    /// Reads more from the socket, or fails once the peer is done.
    async fn fill(&mut self, socket: &mut tokio::net::TcpStream) -> Outcome<()> {
        if self.filled == self.storage.len() {
            self.storage.resize(self.filled + 64 * 1024, 0);
        }
        let read = socket
            .read(&mut self.storage[self.filled..])
            .await?;
        if read == 0 {
            return Err(Error::Disconnected);
        }
        self.filled += read;
        Ok(())
    }

    /// Consumes `count` leading bytes, moving whatever trails them to the front.
    fn consume(&mut self, count: usize) {
        self.storage.copy_within(count..self.filled, 0);
        self.filled -= count;
    }
}

/// A live subscription.
///
/// # Compression is not optional
///
/// This client offers only zstd. An aura-shreds node streams several hundred megabits of
/// transaction data per second uncompressed, and a compressed stream is roughly a third of that.
/// Letting a subscriber quietly negotiate its way to an uncompressed stream costs the operator
/// bandwidth they did not agree to, so a node can be configured to refuse it — and this client
/// refuses it too, rather than connecting and silently costing more than it should.
pub struct Client {
    socket: tokio::net::TcpStream,
    ack: HelloAck,
    max_message_bytes: usize,
    inbox: RecvBuffer,
    /// The current frame's payload, decompressed.
    frame: Vec<u8>,
    last_seq: Option<u64>,
    dropped: u64,
    wire_bytes: u64,
    decoded_bytes: u64,
}

impl Client {
    /// Connects, authenticates and negotiates compression.
    ///
    /// `addr` may be anything resolvable — `"ams.auraboost.wtf:9000"` or a
    /// [`std::net::SocketAddr`]. The transport is TCP.
    pub async fn connect(addr: impl ToSocketAddrs + ToString, config: Config) -> Outcome<Self> {
        let socket = tokio::time::timeout(
            config.connect_timeout,
            async { tokio::net::TcpStream::connect(addr).await },
        )
        .await
        .map_err(|_| Error::Auth("connecting timed out".to_string()))??;
        Self::over(socket, config).await
    }

    /// Completes the handshake over an already-connected socket.
    pub async fn over(mut socket: tokio::net::TcpStream, config: Config) -> Outcome<Self> {
        socket.set_nodelay(true)?;

        // Your key never leaves this process. It names itself by a one-way reference, and
        // possession is proved below over nonces bound to this session.
        let key_ref = KeyRef::derive(&config.secret);
        let client_nonce = fresh_nonce();

        let mut greeting = Vec::new();
        Hello {
            streams: config.streams,
            codecs: config.codecs,
            key_ref,
            client_nonce,
            filter: config.filter.clone(),
        }
        .append(&mut greeting);
        let mut frame = Vec::with_capacity(wire::HEADER_LEN + greeting.len());
        append_frame(&mut frame, FrameKind::Hello, 0, &greeting);
        socket.write_all(&frame).await?;

        let deadline = tokio::time::Instant::now() + config.connect_timeout;
        let mut inbox = RecvBuffer::new();

        // The node answers with its nonce and its proof. That proof is checked *before* one of your
        // own is sent, so a peer that does not hold your key is abandoned having learned nothing.
        let challenge = {
            let body = Self::await_frame(
                &mut socket,
                &mut inbox,
                deadline,
                FrameKind::Challenge,
                MAX_PRE_AUTH_BYTES,
            )
            .await?;
            match body {
                Ok(bytes) => wire::Challenge::parse(&bytes)?,
                Err(refusal) => return Err(Error::Rejected {
                    code: refusal.code as u16,
                    detail: refusal.detail,
                }),
            }
        };

        let transcript = Transcript {
            key_ref,
            client_nonce,
            server_nonce: challenge.server_nonce,
            // TCP presents no certificate, so there is nothing to bind a proof to. The key still
            // never crosses the wire.
            binding: ChannelBinding::NONE,
        };
        if !transcript.accepts_node(&config.secret, &challenge.proof) {
            return Err(Error::Auth(
                "the node did not prove it holds this key; the connection is not to the node it \
                 claims to be"
                    .to_string(),
            ));
        }

        let mut proof_body = Vec::with_capacity(Prove::SIZE);
        Prove {
            proof: transcript.subscriber_proof(&config.secret),
        }
        .append(&mut proof_body);
        let mut frame = Vec::with_capacity(wire::HEADER_LEN + proof_body.len());
        append_frame(&mut frame, FrameKind::Prove, 0, &proof_body);
        socket.write_all(&frame).await?;

        let ack = {
            let body = Self::await_frame(
                &mut socket,
                &mut inbox,
                deadline,
                FrameKind::HelloAck,
                MAX_PRE_AUTH_BYTES,
            )
            .await?;
            match body {
                Ok(bytes) => HelloAck::parse(&bytes)?,
                Err(refusal) => return Err(Error::Rejected {
                    code: refusal.code as u16,
                    detail: refusal.detail,
                }),
            }
        };
        if ack.protocol_version != PROTOCOL_VERSION {
            return Err(Error::Version {
                theirs: ack.protocol_version,
                ours: PROTOCOL_VERSION,
            });
        }
        if ack.codec != Codec::Zstd {
            return Err(Error::Auth(format!(
                "the node negotiated {ack:?}, but this client requires zstd; the node has zstd \
                 disabled"
            )));
        }

        Ok(Self {
            socket,
            ack,
            max_message_bytes: config.max_message_bytes,
            inbox,
            frame: Vec::new(),
            last_seq: None,
            dropped: 0,
            wire_bytes: 0,
            decoded_bytes: 0,
        })
    }

    /// Waits for one frame of the handshake, bounded by `deadline`.
    ///
    /// Returns the payload bytes, or the node's refusal. Anything other than `expected` — or a
    /// refusal — is an error; the node has proved nothing yet, so nothing here is trusted with the
    /// stream's own limits.
    async fn await_frame(
        socket: &mut tokio::net::TcpStream,
        inbox: &mut RecvBuffer,
        deadline: tokio::time::Instant,
        expected: FrameKind,
        limit: usize,
    ) -> Outcome<std::result::Result<Vec<u8>, wire::Refusal>> {
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(Error::Auth("the handshake did not complete in time".to_string()));
            }
            if inbox.len() >= wire::HEADER_LEN {
                let header = parse_header(inbox.as_slice())?;
                if header.len > limit {
                    return Err(Error::Oversized {
                        message: "handshake frame",
                        declared: header.len,
                        limit,
                    });
                }
                if inbox.len() >= wire::HEADER_LEN + header.len {
                    let payload =
                        inbox.as_slice()[wire::HEADER_LEN..wire::HEADER_LEN + header.len].to_vec();
                    inbox.consume(wire::HEADER_LEN + header.len);
                    if header.kind == FrameKind::Error {
                        return Ok(Err(wire::Refusal::parse(&payload)?));
                    }
                    if header.kind != expected {
                        return Err(Error::Auth(format!(
                            "expected {expected:?} during the handshake, got {:?}",
                            header.kind
                        )));
                    }
                    return Ok(Ok(payload));
                }
                inbox.make_room(wire::HEADER_LEN + header.len);
            }
            let read = tokio::time::timeout(remaining, inbox.fill(socket)).await;
            match read {
                Ok(result) => result?,
                Err(_) => {
                    return Err(Error::Auth("the handshake did not complete in time".to_string()))
                }
            }
        }
    }

    /// Streams the node actually granted.
    #[inline]
    pub const fn granted(&self) -> crate::wire::StreamMask {
        self.ack.granted
    }

    /// This connection's node-assigned id, which the operator's logs are keyed by.
    #[inline]
    pub const fn session_id(&self) -> u64 {
        self.ack.session_id
    }

    /// How often the node pings an idle connection.
    #[inline]
    pub const fn keepalive_ms(&self) -> u16 {
        self.ack.keepalive_ms
    }

    /// Compressed bytes received.
    #[inline]
    pub const fn wire_bytes(&self) -> u64 {
        self.wire_bytes
    }

    /// Bytes after decompression. Against [`Self::wire_bytes`], this is the achieved ratio.
    #[inline]
    pub const fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes
    }

    /// Frames dropped because this client could not keep up.
    #[inline]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Replaces the node-side filter.
    ///
    /// Returns once the request is written, not once it is in force: the node applies it
    /// asynchronously and confirms with [`Event::FilterAck`]. Frames already in flight still arrive
    /// under the previous filter, so a consumer that needs certainty should wait for the ack.
    pub async fn set_filter(&mut self, spec_json: &str) -> Outcome<()> {
        self.submit_filters(&[NamedFilter {
            name: "",
            spec_json,
        }])
        .await
    }

    /// Replaces this connection's filters with a named set, up to sixteen.
    ///
    /// Every transaction reports which of them it matched — see [`Event::Transaction`] — so one
    /// connection can carry several interests and still tell them apart on arrival. The set is
    /// accepted or refused together, so a connection never ends up holding part of what was asked
    /// for.
    pub async fn submit_filters(&mut self, filters: &[NamedFilter<'_>]) -> Outcome<()> {
        let document = filter_document(filters);
        let mut frame = Vec::with_capacity(wire::HEADER_LEN + document.len());
        append_frame(&mut frame, FrameKind::SetFilter, 0, document.as_bytes());
        self.socket.write_all(&frame).await?;
        Ok(())
    }

    /// Sends a liveness probe. The node answers with [`Event::Pong`].
    pub async fn ping(&mut self) -> Outcome<()> {
        let mut frame = Vec::with_capacity(wire::HEADER_LEN);
        append_frame(&mut frame, FrameKind::Ping, 0, &[]);
        self.socket.write_all(&frame).await?;
        Ok(())
    }

    /// Shuts the connection down in both directions.
    ///
    /// Dropping the client also closes the socket; this is for closing without dropping, so a
    /// consumer can keep the session's counters after the connection is done.
    pub async fn close(&mut self) -> Outcome<()> {
        self.socket.shutdown().await?;
        Ok(())
    }

    /// Waits for the next event.
    ///
    /// The returned event borrows this client's frame buffer, so it must be dropped — or what is
    /// needed from it copied out — before the next call.
    pub async fn next_event(&mut self) -> Outcome<Event<'_>> {
        let header = self.read_header().await?;
        self.wire_bytes += (wire::HEADER_LEN + header.len) as u64;

        self.frame.clear();
        if header.compressed {
            match header.codec {
                Codec::Zstd => {
                    let input = self.inbox.as_slice()[..header.len].to_vec();
                    self.inbox.consume(header.len);
                    let decoded = zstd::bulk::decompress(&input, self.max_message_bytes)
                        .map_err(|err| Error::Inflate(err.to_string()))?;
                    self.frame = decoded;
                }
                other => {
                    self.inbox.consume(header.len);
                    return Err(Error::Codec(other));
                }
            }
        } else {
            self.frame.extend_from_slice(&self.inbox.as_slice()[..header.len]);
            self.inbox.consume(header.len);
        }
        self.decoded_bytes += self.frame.len() as u64;

        // A sequence gap means the node dropped frames for this connection. It is reported by the
        // lag frame too, but counting here catches a gap even if that frame is itself lost.
        if let Some(last) = self.last_seq {
            if header.seq > last + 1 {
                self.dropped += header.seq - last - 1;
            }
        }
        self.last_seq = Some(header.seq);

        // Answered here so a consumer that is slow to poll is not disconnected for being idle.
        if header.kind == FrameKind::Ping {
            self.pong().await?;
            return Ok(Event::Ping);
        }
        if header.kind == FrameKind::Error {
            let refusal = wire::Refusal::parse(&self.frame)?;
            return Err(Error::Rejected {
                code: refusal.code as u16,
                detail: refusal.detail,
            });
        }
        if header.kind == FrameKind::Lag {
            let lag = Lag::parse(&self.frame)?;
            self.dropped += lag.dropped;
            self.last_seq = Some(lag.resume_seq.wrapping_sub(1));
            return Ok(Event::Lag(lag));
        }

        let body: &[u8] = &self.frame;
        Ok(match header.kind {
            FrameKind::Transaction => Event::Transaction {
                tx: Transaction::read(body)?,
                matched: header.matched,
            },
            FrameKind::Entry => Event::Entry(Entry::parse(body)?),
            FrameKind::SlotStart => Event::SlotStart(SlotStart::parse(body)?),
            FrameKind::SlotEnd => Event::SlotEnd(SlotEnd::parse(body)?),
            FrameKind::Duplicate => Event::Duplicate(Duplicate::parse(body)?),
            FrameKind::RawShred => Event::RawShred(RawShred::parse(body)?),
            FrameKind::FilterAck => Event::FilterAck(FilterAck::parse(body)?),
            FrameKind::Pong => Event::Pong,
            _ => Event::Other {
                kind: header.raw_kind,
                payload: body,
            },
        })
    }

    async fn pong(&mut self) -> Outcome<()> {
        let mut frame = Vec::with_capacity(wire::HEADER_LEN);
        append_frame(&mut frame, FrameKind::Pong, 0, &[]);
        self.socket.write_all(&frame).await?;
        Ok(())
    }

    /// Waits for a frame header whose payload fits `limit`.
    async fn read_header(&mut self) -> Outcome<wire::Header> {
        loop {
            if self.inbox.len() >= wire::HEADER_LEN {
                let header = parse_header(self.inbox.as_slice())?;
                if header.len > self.max_message_bytes {
                    return Err(Error::Oversized {
                        message: "frame",
                        declared: header.len,
                        limit: self.max_message_bytes,
                    });
                }
                if self.inbox.len() >= wire::HEADER_LEN + header.len {
                    // The header is consumed here, so the caller's payload slice starts at zero.
                    self.inbox.consume(wire::HEADER_LEN);
                    return Ok(header);
                }
                self.inbox.make_room(wire::HEADER_LEN + header.len);
            }
            self.inbox.fill(&mut self.socket).await?;
        }
    }
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("session_id", &self.ack.session_id)
            .field("granted", &self.ack.granted)
            .field("wire_bytes", &self.wire_bytes)
            .field("decoded_bytes", &self.decoded_bytes)
            .field("dropped", &self.dropped)
            .finish()
    }
}
