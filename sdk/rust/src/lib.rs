//! Subscriber client for the aura-shreds Solana shred stream.
//!
//! aura-shreds ingests raw shreds from the cluster, recovers what the network lost, decodes them to
//! transactions, and streams the result to authenticated subscribers ahead of any RPC. This crate
//! is the client side of that stream.
//!
//! ```no_run
//! use aura_shreds_sdk::{Client, Config, Event, StreamMask};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Config::new(std::env::var("AURA_SHREDS_SECRET")?)
//!     .streams(StreamMask(StreamMask::TRANSACTIONS));
//! let mut client = Client::connect("ams.auraboost.wtf:9000", config).await?;
//!
//! loop {
//!     match client.next_event().await? {
//!         Event::Transaction { tx, .. } => {
//!             println!("{} {:?}", tx.slot(), tx.signature());
//!         }
//!         Event::Lag(lag) => eprintln!("dropped {} frames", lag.dropped),
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Compression is not optional
//!
//! This client offers only zstd, and refuses a connection the node would hand it uncompressed.
//! See [`Client`] for why.
//!
//! # What this crate does not do
//!
//! Nothing here talks to a validator, submits transactions, or resolves address lookup tables —
//! resolving those needs account state a shred pipeline does not have, so lookups are carried
//! unresolved and left to the consumer.

#![forbid(unsafe_code)]

pub mod auth;
pub mod config;
pub mod error;
pub mod records;
pub mod session;
pub mod tx;
pub mod wire;

pub use config::{Config, NamedFilter};
pub use error::{Error, Outcome};
pub use records::{Duplicate, Entry, RawShred, SlotEnd, SlotStart};
pub use session::{Client, Event};
pub use tx::{AddressLookup, Instruction, Transaction};
pub use wire::{
    Codec, ErrorCode, FilterMask, FrameKind, Header as FrameHeader, StreamMask, Verification,
    codec_bit,
};
pub use auth::{ChannelBinding, KeyRef, Proof, Transcript, fresh_nonce};

/// Connects to `addr` with your credentials and nothing else to decide.
///
/// The address is yours to supply: this build carries no endpoint, so one archive serves every
/// node and none of them can go stale when an operator moves or adds one. `addr` is `host:port`.
///
/// There is nothing else to configure, and no key id to go with the secret. The greeting names your
/// key by `SHA-256(domain ‖ secret)` and never carries the secret itself, so the node finds it by
/// that reference rather than by a name. The node authenticates itself with the same key during the
/// handshake, so there is no certificate to pin.
///
/// ```no_run
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let mut client = aura_shreds_sdk::connect(
///     "ams.auraboost.wtf:9000",
///     std::env::var("AURA_SHREDS_SECRET")?,
/// ).await?;
/// # Ok(())
/// # }
/// ```
///
/// To subscribe to a subset of streams or filter at connect, build a [`Config`] with
/// [`Config::new`] and call [`Client::connect`].
///
/// # Errors
///
/// Whatever [`Client::connect`] returns.
pub async fn connect(
    addr: impl tokio::net::ToSocketAddrs + std::fmt::Display + Clone,
    secret: impl Into<Vec<u8>>,
) -> error::Outcome<Client> {
    Client::connect(addr, Config::new(secret)).await
}
