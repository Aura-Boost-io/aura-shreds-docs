//! How to connect, and the filter document format.

/// How to connect.
#[derive(Clone, Debug)]
pub struct Config {
    /// The key issued to this subscriber, and the only credential there is.
    ///
    /// The greeting names it by `SHA-256(domain ‖ secret)` and never carries the secret itself, so
    /// the node finds a key by that reference rather than by any name. There is no separate key id
    /// to supply.
    pub secret: Vec<u8>,
    /// Streams to subscribe to.
    ///
    /// The node grants the intersection of this and what the key permits, so asking for more than
    /// the key allows is not an error — check [`crate::Client::granted`] for what was given.
    pub streams: crate::wire::StreamMask,
    /// Codecs this build can inflate, as a bitmask — see [`crate::wire::codec_bit`].
    ///
    /// This build inflates zstd only, and refuses a connection the node would hand it
    /// uncompressed: see [`crate::Client`].
    pub codecs: u8,
    /// How long to wait for the handshake.
    pub connect_timeout: std::time::Duration,
    /// Largest message to accept, compressed or not.
    ///
    /// Bounds both the frame read off the socket and what a compressed one is expanded into, so
    /// lowering it actually bounds what a node can make this process allocate. A compressed body is
    /// smaller than what it becomes, so nothing legitimate is lost by checking it in both places.
    /// Handshake frames are bounded separately, by what each of them can be.
    pub max_message_bytes: usize,
    /// A filter document installed before the stream starts, if any.
    ///
    /// Set through [`Config::filters`] or [`Config::filter`] rather than directly.
    pub filter: Option<String>,
}

impl Config {
    /// A configuration for `secret`, subscribing to every published stream.
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        Self {
            secret: secret.into(),
            streams: crate::wire::StreamMask::ALL,
            codecs: crate::wire::codec_bit::ZSTD,
            connect_timeout: std::time::Duration::from_secs(10),
            max_message_bytes: 16 << 20,
            filter: None,
        }
    }

    /// Subscribes to `streams` instead of everything.
    #[must_use]
    pub fn streams(mut self, streams: crate::wire::StreamMask) -> Self {
        self.streams = streams;
        self
    }

    /// Installs `filters` in the greeting, so the stream is narrowed before it starts.
    ///
    /// [`crate::Client::set_filters`] leaves a window — a round trip at least — during which the
    /// connection is unfiltered and everything subscribed to arrives. On a busy node that window is
    /// thousands of transactions nobody asked for, and it is billed. Naming the filters here closes
    /// it: the node installs them before the first frame is sent.
    ///
    /// A filter that does not compile, or that exceeds the key's budgets, refuses the connection
    /// rather than falling back to an unfiltered stream.
    #[must_use]
    pub fn filters(mut self, filters: &[NamedFilter<'_>]) -> Self {
        self.filter = Some(filter_document(filters));
        self
    }

    /// Installs a single unnamed filter in the greeting.
    #[must_use]
    pub fn filter(self, spec_json: &str) -> Self {
        self.filters(&[NamedFilter {
            name: "",
            spec_json,
        }])
    }
}

/// One filter, with the name the subscriber chose for it.
///
/// The spec is passed as JSON rather than as a typed tree: this crate deliberately carries no
/// serialization dependency, and a filter is written once at startup where a string literal is as
/// readable as a builder would be.
#[derive(Clone, Copy, Debug)]
pub struct NamedFilter<'a> {
    /// What you call it. Comes back in a refusal so you know which one was at fault.
    pub name: &'a str,
    /// The filter itself, as JSON.
    pub spec_json: &'a str,
}

/// Builds the `{"filters":[…]}` document, quoting names as it goes.
///
/// The document is assembled at the byte level rather than through a string builder: a filter name
/// is data, not syntax, and every character below `0x20` is forbidden raw in a JSON string — so a
/// name containing a newline or a tab must be escaped, not just the quote and the backslash that
/// are the tempting cases. A name that produced invalid JSON would be refused by the node as a
/// malformed *filter*, pointing the subscriber at the filter language instead of at the name.
pub(crate) fn filter_document(filters: &[NamedFilter<'_>]) -> String {
    let mut out = Vec::with_capacity(16 + filters.iter().map(|f| f.spec_json.len() + 24).sum::<usize>());
    out.extend_from_slice(b"{\"filters\":[");
    for (index, filter) in filters.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(b"{\"name\":");
        write_json_string(&mut out, filter.name);
        out.extend_from_slice(b",\"spec\":");
        out.extend_from_slice(filter.spec_json.as_bytes());
        out.push(b'}');
    }
    out.extend_from_slice(b"]}");
    // Every byte written above is ASCII or came from valid JSON, so this cannot fail.
    String::from_utf8(out).expect("filter document is ascii-safe")
}

/// Writes `value` into `out` as a quoted JSON string.
fn write_json_string(out: &mut Vec<u8>, value: &str) {
    out.push(b'"');
    for character in value.chars() {
        match character {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            control if (control as u32) < 0x20 => {
                use std::fmt::Write as _;
                let mut escape = String::new();
                let _ = write!(escape, "\\u{:04x}", control as u32);
                out.extend_from_slice(escape.as_bytes());
            }
            other => {
                let mut buffer = [0u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod documents {
    use super::*;

    fn document(filters: &[NamedFilter<'_>]) -> String {
        filter_document(filters)
    }

    #[test]
    fn a_plain_name_passes_through() {
        assert_eq!(
            document(&[NamedFilter {
                name: "desk",
                spec_json: r#"{"is_vote":{"value":false}}"#
            }]),
            r#"{"filters":[{"name":"desk","spec":{"is_vote":{"value":false}}}]}"#
        );
    }

    #[test]
    fn control_characters_stay_valid_json() {
        let built = document(&[NamedFilter {
            name: &format!("two{}lines{}apart", '\n', '\t'),
            spec_json: "{}",
        }]);
        assert!(built.contains("two\\nlines\\tapart"));
        // And the document still parses.
        assert!(serde_json::from_str::<serde_json::Value>(&built).is_ok());
    }

    #[test]
    fn a_control_character_without_a_short_form_takes_the_unicode_escape() {
        let built = document(&[NamedFilter {
            name: &format!("bell{}", '\u{7}'),
            spec_json: "{}",
        }]);
        assert!(built.contains("bell\\u0007"));
    }

    #[test]
    fn several_filters_are_comma_separated() {
        let built = document(&[
            NamedFilter {
                name: "a",
                spec_json: "{}",
            },
            NamedFilter {
                name: "",
                spec_json: "{}",
            },
        ]);
        assert_eq!(built, r#"{"filters":[{"name":"a","spec":{}},{"name":"","spec":{}}]}"#);
    }
}
