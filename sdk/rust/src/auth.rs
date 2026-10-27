//! Authenticating without disclosing the key.
//!
//! The key is one value that serves as both identifier and credential, so a handshake that sends it
//! would hand a working credential to every observer of the link. Instead each side computes an
//! HMAC over a transcript both can reconstruct, and the key itself stays local:
//!
//! ```text
//! subscriber → node   reference = SHA-256(domain ‖ key), subscriber nonce
//! node       → subscriber   node nonce, HMAC(key, server domain ‖ transcript)
//! subscriber checks it, then answers with HMAC(key, client domain ‖ transcript)
//! ```
//!
//! The node proves first. A subscriber that checked nothing would be talking to whatever answers
//! the dial; checking before sending anything of its own means an impostor learns nothing.
//!
//! TCP presents no certificate, so the transcript's binding field is the all-zero sentinel. The
//! key still never travels; what plain TCP gives up is relay detection, which is why it suits a
//! subscriber on a network it trusts.

use hmac::Mac as _;
use std::fmt;
use sha2::{Digest, Sha256};

/// Domain string mixed into every key reference.
const REFERENCE_DOMAIN: &[u8] = b"aura-shreds/key-ref/v1";
/// Domain string mixed into the node's proof.
const NODE_DOMAIN: &[u8] = b"aura-shreds/server-proof/v1";
/// Domain string mixed into the subscriber's proof.
const SUBSCRIBER_DOMAIN: &[u8] = b"aura-shreds/client-proof/v1";

type HmacSha256 = hmac::Hmac<Sha256>;

/// A non-reversible stand-in for a key, safe to log or quote.
///
/// `SHA-256` of the key under a domain separator. The greeting carries it; the node uses it to find
/// which key to prove against.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyRef(pub [u8; 32]);

impl KeyRef {
    /// Width on the wire.
    pub const SIZE: usize = 32;

    /// Computes the reference of `key`.
    pub fn derive(key: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(REFERENCE_DOMAIN);
        hasher.update(key);
        Self(hasher.finalize().into())
    }

    /// Full lowercase hex.
    pub fn hex(self) -> String {
        let mut out = String::with_capacity(2 * Self::SIZE);
        for byte in self.0 {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    /// Enough hex to tell two keys apart in a log line.
    pub fn prefix(self) -> String {
        self.hex().chars().take(16).collect()
    }
}

impl fmt::Debug for KeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyRef({})", self.prefix())
    }
}

impl fmt::Display for KeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.prefix())
    }
}

/// Hash of whatever the transport presented, when it presents anything.
///
/// Plain TCP presents nothing, so [`ChannelBinding::NONE`] is the only value this crate produces.
/// The field exists because the proof mixes it in either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelBinding(pub [u8; 32]);

impl ChannelBinding {
    /// The sentinel for a transport with no session material.
    pub const NONE: Self = Self([0u8; 32]);

    /// Binds to a presented certificate.
    pub fn from_certificate(der: &[u8]) -> Self {
        Self(Sha256::digest(der).into())
    }

    /// True when the binding carries no session material.
    #[inline]
    pub fn is_none(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

/// An HMAC output proving possession of a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof(pub [u8; 32]);

impl Proof {
    /// Width on the wire.
    pub const SIZE: usize = 32;
}

/// The material both sides hash to produce their proofs.
#[derive(Clone, Copy, Debug)]
pub struct Transcript {
    /// Reference of the key being claimed.
    pub key_ref: KeyRef,
    /// Chosen by the subscriber.
    pub client_nonce: [u8; 32],
    /// Chosen by the node.
    pub server_nonce: [u8; 32],
    /// Session material, or the zero sentinel over TCP.
    pub binding: ChannelBinding,
}

impl Transcript {
    /// What the node must produce to authenticate itself.
    pub fn node_proof(&self, key: &[u8]) -> Proof {
        self.mac(key, NODE_DOMAIN)
    }

    /// What the subscriber must produce to authenticate itself.
    pub fn subscriber_proof(&self, key: &[u8]) -> Proof {
        self.mac(key, SUBSCRIBER_DOMAIN)
    }

    fn mac(&self, key: &[u8], domain: &[u8]) -> Proof {
        let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(key)
            .expect("hmac accepts keys of any length");
        mac.update(domain);
        mac.update(&self.key_ref.0);
        mac.update(&self.client_nonce);
        mac.update(&self.server_nonce);
        mac.update(&self.binding.0);
        Proof(mac.finalize().into_bytes().into())
    }

    /// Whether `presented` matches the node's expected proof.
    ///
    /// The comparison runs in constant time; an early exit would grade a forger's guess byte by
    /// byte.
    pub fn accepts_node(&self, key: &[u8], presented: &Proof) -> bool {
        self.accepts(key, presented, NODE_DOMAIN)
    }

    /// Whether `presented` matches the subscriber's expected proof.
    pub fn accepts_subscriber(&self, key: &[u8], presented: &Proof) -> bool {
        self.accepts(key, presented, SUBSCRIBER_DOMAIN)
    }

    fn accepts(&self, key: &[u8], presented: &Proof, domain: &[u8]) -> bool {
        let mut mac = match HmacSha256::new_from_slice(key) {
            Ok(mac) => mac,
            // Unreachable: HMAC accepts a key of any length.
            Err(_) => return false,
        };
        mac.update(domain);
        mac.update(&self.key_ref.0);
        mac.update(&self.client_nonce);
        mac.update(&self.server_nonce);
        mac.update(&self.binding.0);
        // Constant time, and it rejects a mismatched length, which a peer controls.
        mac.verify_slice(&presented.0).is_ok()
    }
}

/// A fresh nonce for one exchange.
///
/// Sourced from the operating system's generator: uniqueness is not enough. A predictable nonce
/// would let an attacker obtain a proof over a transcript chosen in advance.
pub fn fresh_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rand::TryRngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut nonce)
        .expect("the operating system generator is available");
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_reveal_nothing() {
        let key = b"9d8e7f6a-0000-0000-0000-000000000001";
        let reference = KeyRef::derive(key);
        assert_eq!(reference, KeyRef::derive(key));
        assert_ne!(reference, KeyRef::derive(b"other"));
        assert!(!reference.hex().contains("0000-0000"));
    }

    #[test]
    fn directions_are_not_interchangeable() {
        let session = Transcript {
            key_ref: KeyRef::derive(b"k"),
            client_nonce: [1u8; 32],
            server_nonce: [2u8; 32],
            binding: ChannelBinding::from_certificate(b"c"),
        };
        assert!(session.accepts_node(b"k", &session.node_proof(b"k")));
        assert!(
            !session.accepts_node(b"k", &session.subscriber_proof(b"k")),
            "a subscriber proof authenticated a node"
        );
    }

    #[test]
    fn nonces_differ() {
        assert_ne!(fresh_nonce(), fresh_nonce());
    }
}
