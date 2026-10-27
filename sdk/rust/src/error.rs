//! Failure modes of the subscriber protocol.



/// Alias used throughout the crate for results that fail with [`Error`].
pub type Outcome<T> = std::result::Result<T, Error>;

/// Every way a subscription can fail.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The socket misbehaved.
    #[error("socket: {0}")]
    Socket(#[from] std::io::Error),

    /// The node sent a refusal, or disconnected us with a reason.
    #[error("refused by node [{code}]: {detail}")]
    Rejected {
        /// Machine-readable reason, as sent.
        code: u16,
        /// Human-readable explanation, as sent.
        detail: String,
    },

    /// A message stopped short of its declared size.
    #[error("{message} truncated: expected {expected} bytes, got {actual}")]
    Short {
        /// Which message.
        message: &'static str,
        /// Bytes required.
        expected: usize,
        /// Bytes available.
        actual: usize,
    },

    /// A length field exceeded what this connection accepts.
    #[error("{message} of {declared} bytes exceeds the {limit} byte allowance")]
    Oversized {
        /// Which message.
        message: &'static str,
        /// The declared length.
        declared: usize,
        /// The allowance it exceeded.
        limit: usize,
    },

    /// A table entry reached past the end of its own region.
    #[error("{region} entry {entry} reaches outside its byte region")]
    Region {
        /// Which region.
        region: &'static str,
        /// Which entry.
        entry: usize,
    },

    /// The node speaks a protocol version this build does not.
    #[error("protocol version mismatch: node speaks {theirs}, this build speaks {ours}")]
    Version {
        /// What the node offered.
        theirs: u16,
        /// What this build speaks.
        ours: u16,
    },

    /// The authentication exchange failed.
    #[error("authentication: {0}")]
    Auth(String),

    /// The node compressed a frame with a codec that was not offered.
    #[error("node used codec {0:?}, which was not offered")]
    Codec(crate::wire::Codec),

    /// A compressed body would not expand.
    #[error("decompression failed: {0}")]
    Inflate(String),

    /// The peer went away.
    #[error("connection closed by the node")]
    Disconnected,
}

impl Error {
    /// Convenience constructor for [`Error::Short`].
    pub(crate) fn short(message: &'static str, expected: usize, actual: usize) -> Self {
        Self::Short {
            message,
            expected,
            actual,
        }
    }
}
