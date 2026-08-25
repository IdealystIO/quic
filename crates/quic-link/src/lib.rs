//! A real-time link: unreliable datagrams for media, reliable streams for
//! control, over one QUIC connection.
//!
//! # Why not the WebSocket this replaces
//!
//! TCP guarantees delivery, ordering, and exactly-once. For a voice call all
//! three are the wrong guarantee. A lost audio packet gets retransmitted and
//! arrives ~100 ms late, by which point playback has already moved past it —
//! so it is worthless *and* it blocked every fresh packet behind it while it
//! was in flight. One loss becomes a multi-hundred-millisecond gap. That is
//! head-of-line blocking, and it is TCP working correctly.
//!
//! QUIC datagrams (RFC 9221) withdraw all three guarantees deliberately. A
//! lost packet is simply lost, the ones behind it arrive on time, and the
//! receiver conceals the hole — which is what `jitter` and the codec are for.
//!
//! # Two channels, because a call needs both kinds
//!
//! Audio wants speed and can afford to lose. "This node does not own the room,
//! reconnect over there" cannot afford to lose at all. So:
//!
//! - **Datagrams** carry media. Unreliable, unordered, single-packet.
//! - **Unidirectional streams** carry control. Reliable and ordered, one
//!   message per stream so a slow control message cannot delay the next one —
//!   which would be head-of-line blocking reintroduced by hand.
//!
//! # The size limit is not a suggestion
//!
//! A datagram must fit in one QUIC packet — [`Link::max_datagram`], typically
//! a bit over a kilobyte. This is the constraint that forces a codec: 85 ms of
//! raw 48 kHz mono i16 is 8160 bytes and cannot be sent at all, at any tuning.
//! A 20 ms Opus frame is about sixty. [`Link::send`] reports an oversized
//! payload rather than dropping it silently, because silently is how that
//! becomes "voice works on my machine".
//!
//! # Certificates, and self-hosting
//!
//! WebTransport needs TLS, which for a self-hosted instance means either a CA
//! certificate or a pinned self-signed one. Browsers accept the latter through
//! `serverCertificateHashes`, capped at a short validity — so [`Identity`]
//! generates one and hands back the SHA-256 the client must pin. That keeps a
//! loopback prototype honest about what a deployment will have to do, rather
//! than disabling verification and discovering the difference later.

#![forbid(unsafe_code)]

use bytes::Bytes;
use futures::FutureExt;

/// Hex back to bytes — the inverse of [`Identity::hash_hex`], for a client that
/// was handed one and has to pin it.
///
/// `None` for anything that is not an even run of hex digits. A hash that does
/// not parse is a node saying something we do not understand, and pinning a
/// truncated one fails at the handshake with a message about certificates
/// rather than about the node that sent nonsense.
pub fn parse_hash(hex: &str) -> Option<Vec<u8>> {
    if hex.is_empty() || hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod hash_tests {
    use super::parse_hash;

    #[test]
    fn a_hash_round_trips() {
        assert_eq!(parse_hash("00ff10"), Some(vec![0x00, 0xff, 0x10]));
    }

    #[test]
    fn a_hash_that_is_not_a_hash_is_refused_rather_than_truncated() {
        // Pinning half a hash fails at the TLS handshake, where the message
        // names certificates rather than the node that sent nonsense — so the
        // refusal has to happen here, where the caller can say what it saw.
        assert_eq!(parse_hash("abc"), None, "odd length");
        assert_eq!(parse_hash(""), None, "empty");
        assert_eq!(parse_hash("zz"), None, "not hex");
        assert_eq!(parse_hash("00 ff"), None, "spaces are not hex either");
    }
}

/// Whether a page at `page_host` could plausibly open a session to `endpoint`.
///
/// `None` means go ahead. `Some(reason)` means do not bother, and the reason is
/// worth saying out loud.
///
/// This exists because a QUIC session **cannot be reverse-proxied** — it
/// terminates at whoever holds the certificate — so a node behind a gateway
/// publishes its own address, unchanged, and that address is frequently one the
/// client cannot reach. The common case is a tunnel: the page is served from
/// `https://something.ngrok.app` and the node publishes `https://127.0.0.1:8798`,
/// which is either unroutable or blocked outright by the browser's
/// private-network rules.
///
/// Checking is worth more than it looks. Without it the client dials anyway and
/// waits out a QUIC handshake timeout — on the order of ten seconds, on the join
/// path, with somebody watching — before falling back to a transport that was
/// always going to be the answer.
pub fn unreachable_from(page_host: &str, endpoint: &str) -> Option<String> {
    let host = url_host(endpoint)?;
    if !is_loopback(&host) {
        // A routable address, or a private one on a network the page may well
        // share. Only a dial can settle those.
        return None;
    }
    // Through the same parser as the endpoint: an IPv6 page host is bracketed
    // and full of colons, so splitting on the first one yields "[".
    let page = authority_host(page_host).unwrap_or_else(|| page_host.to_string());
    if is_loopback(&page) || page.eq_ignore_ascii_case(&host) {
        // The page is on the same machine, so loopback is exactly right.
        return None;
    }
    Some(format!(
        "node published {endpoint}, which is loopback and unreachable from {page}; a QUIC \
         session cannot be proxied, so a tunnelled deployment stays on the WebSocket",
    ))
}

/// The host of a URL, without scheme, port, path or credentials.
fn url_host(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next()?;
    authority_host(authority)
}

/// The host out of a `host`, `host:port`, `[v6]:port` or `user@host` authority.
///
/// Shared by both sides of [`unreachable_from`] on purpose. They were two
/// different parsers for one afternoon, and the page-host one split
/// `[::1]:8091` on the first colon and decided the host was `[`.
fn authority_host(authority: &str) -> Option<String> {
    let authority = authority.rsplit('@').next()?;
    // IPv6 literals are bracketed, and contain the colons a port split would
    // otherwise chop in half.
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return Some(rest[..end].to_string());
        }
    }
    let host = authority.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn is_loopback(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host == "::1"
        || host.starts_with("127.")
}

#[cfg(test)]
mod reach_tests {
    use super::unreachable_from;

    #[test]
    fn a_tunnelled_page_is_told_not_to_bother_with_a_loopback_node() {
        // The case that sent this whole check into existence: sharing the app
        // over ngrok, where the WebSocket proxies fine and the QUIC endpoint is
        // the node's own 127.0.0.1.
        let why = unreachable_from("abc123.ngrok.app", "https://127.0.0.1:8798/ws")
            .expect("a public page cannot reach loopback");
        assert!(why.contains("127.0.0.1"), "and names the address: {why}");
        assert!(why.contains("ngrok.app"), "and who could not reach it: {why}");
    }

    #[test]
    fn a_page_on_the_same_machine_dials_it() {
        // The loopback demo, and every test in this repo. Skipping here would
        // turn the feature off for the only setup that exercises it.
        assert_eq!(unreachable_from("localhost:8091", "https://127.0.0.1:8798/ws"), None);
        assert_eq!(unreachable_from("127.0.0.1:8091", "https://127.0.0.1:8798/ws"), None);
        assert_eq!(unreachable_from("[::1]:8091", "https://[::1]:8798/ws"), None);
    }

    #[test]
    fn a_routable_node_is_always_worth_dialling() {
        // Including a LAN address from another LAN address: this check is about
        // what is IMPOSSIBLE, not about what is likely. Only a dial settles the
        // rest, and guessing would disable the feature on real deployments.
        assert_eq!(unreachable_from("chat.example.com", "https://voice.example.com:8798/ws"), None);
        assert_eq!(unreachable_from("192.168.1.10", "https://192.168.1.5:8798/ws"), None);
    }

    #[test]
    fn a_url_it_cannot_read_is_left_to_the_dial() {
        // Refusing on a parse failure would make an unfamiliar URL shape look
        // like an unreachable node, which is a much harder thing to diagnose
        // than a dial that simply fails.
        assert_eq!(unreachable_from("example.com", "not a url at all"), None);
    }

    #[test]
    fn a_host_is_read_out_of_the_awkward_shapes_too() {
        use super::url_host;
        assert_eq!(url_host("https://127.0.0.1:8798/ws"), Some("127.0.0.1".into()));
        assert_eq!(url_host("https://[::1]:8798/ws"), Some("::1".into()));
        assert_eq!(url_host("https://user@host.example:443/x?y=1"), Some("host.example".into()));
    }

    #[test]
    fn a_bracketed_page_host_is_parsed_by_the_same_rule_as_the_endpoint() {
        // Two parsers for one job is how `[::1]:8091` came out as the host "[",
        // which then failed to match anything and would have disabled the
        // transport for a setup that works perfectly.
        use super::authority_host;
        assert_eq!(authority_host("[::1]:8091"), Some("::1".into()));
        assert_eq!(authority_host("localhost:8091"), Some("localhost".into()));
        assert_eq!(authority_host("example.com"), Some("example.com".into()));
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod host;
#[cfg(not(target_arch = "wasm32"))]
pub use host::{Identity, Listener, Request};

/// The datagram size assumed where the real one cannot be read — see
/// [`Link::max_datagram`].
///
/// A conservative floor rather than a guess: 1200 bytes is what fits inside a
/// QUIC packet on a 1280-byte path, which is the minimum IPv6 MTU and
/// therefore the number every QUIC implementation is safe to assume.
pub const CONSERVATIVE_DATAGRAM: usize = 1200;

/// What arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// One media datagram. May have been reordered, may be missing the one
    /// before it — that is the point.
    Data(Vec<u8>),
    /// One control message, delivered reliably and in order relative to other
    /// control messages.
    Control(String),
    /// The far end went away.
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// The payload is larger than a datagram can carry. Carries the limit, so
    /// the caller can say something useful rather than "send failed".
    TooLarge { size: usize, limit: usize },
    Transport(String),
}

impl core::fmt::Display for LinkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LinkError::TooLarge { size, limit } => write!(
                f,
                "{size} bytes will not fit in a {limit}-byte datagram — this needs a codec, \
                 not a smaller buffer",
            ),
            LinkError::Transport(e) => write!(f, "{e}"),
        }
    }
}

/// One live connection.
///
/// Cheap to clone, and every method takes `&self`, so the capture callback can
/// hold one and publish from it without any locking of ours — the session
/// underneath is already shareable.
#[derive(Clone)]
pub struct Link {
    session: web_transport::Session,
}

impl Link {
    /// Dial `url`, pinning `cert_hash` if the server is using a self-signed
    /// certificate.
    ///
    /// `None` means "verify against the system roots", which is what a real
    /// deployment behind a CA certificate does.
    pub async fn connect(url: &str, cert_hash: Option<Vec<u8>>) -> Result<Link, LinkError> {
        let url = url.parse().map_err(|e| LinkError::Transport(format!("{url}: {e}")))?;
        let builder = web_transport::ClientBuilder::new();
        let client = match cert_hash {
            Some(hash) => builder.with_server_certificate_hashes(vec![hash]),
            None => builder.with_system_roots(),
        }
        .map_err(|e| LinkError::Transport(e.to_string()))?;
        let session = client.connect(url).await.map_err(|e| LinkError::Transport(e.to_string()))?;
        Ok(Link { session })
    }

    /// Wrap a session that was accepted rather than dialled.
    pub fn from_session(session: web_transport::Session) -> Link {
        Link { session }
    }

    /// The largest payload [`Link::send`] will accept right now.
    ///
    /// On native this follows the path MTU the connection has discovered, so
    /// it can change mid-call.
    ///
    /// In the browser it is [`CONSERVATIVE_DATAGRAM`], and not because the
    /// number is unavailable: `web-transport-wasm` exposes
    /// `max_datagram_size()` and the browser's own
    /// `WebTransportDatagramDuplexStream` has `maxDatagramSize`, but the
    /// `web-transport` 0.12 facade does not forward it on the wasm path and
    /// keeps the inner session private, so there is no way through. Erring
    /// small only ever refuses a datagram that might have fit, and at sixty
    /// bytes a frame nothing this app sends comes close.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn max_datagram(&self) -> usize {
        self.session.max_datagram_size().await
    }

    /// See the native counterpart for why this is a constant here.
    #[cfg(target_arch = "wasm32")]
    pub async fn max_datagram(&self) -> usize {
        CONSERVATIVE_DATAGRAM
    }

    /// Send one media datagram. Unreliable by design.
    ///
    /// Returning `Ok` means the datagram was handed to the network, not that
    /// anybody received it. That is the contract the whole design is built on.
    pub async fn send(&self, bytes: &[u8]) -> Result<(), LinkError> {
        let limit = self.max_datagram().await;
        if bytes.len() > limit {
            return Err(LinkError::TooLarge { size: bytes.len(), limit });
        }
        self.session
            .send_datagram(Bytes::copy_from_slice(bytes))
            .await
            .map_err(|e| LinkError::Transport(e.to_string()))
    }

    /// Send one control message, reliably.
    ///
    /// One stream per message, deliberately. Sharing a stream would put every
    /// control message behind the slowest one — head-of-line blocking, hand
    /// built, in the transport chosen to avoid it.
    pub async fn control(&self, text: &str) -> Result<(), LinkError> {
        let mut stream =
            self.session.open_uni().await.map_err(|e| LinkError::Transport(e.to_string()))?;
        stream
            .write(text.as_bytes())
            .await
            .map_err(|e| LinkError::Transport(e.to_string()))?;
        stream.finish().map_err(|e| LinkError::Transport(e.to_string()))?;
        Ok(())
    }

    /// Wait for whatever comes next, from either channel.
    ///
    /// Racing the two rather than draining one then the other: polling
    /// datagrams first would let a busy call starve a redirect, and polling
    /// control first would let a chatty peer stall the audio.
    pub async fn recv(&self) -> Event {
        let datagram = self.session.recv_datagram().fuse();
        let stream = self.session.accept_uni().fuse();
        futures::pin_mut!(datagram, stream);

        futures::select! {
            d = datagram => match d {
                Ok(bytes) => Event::Data(bytes.to_vec()),
                Err(_) => Event::Closed,
            },
            s = stream => match s {
                Ok(mut recv) => {
                    // Control messages are short by construction. The cap is a
                    // guard against a peer that opens a stream and never stops
                    // writing, not a real size limit.
                    match recv.read(64 * 1024).await {
                        Ok(Some(bytes)) => Event::Control(
                            String::from_utf8_lossy(&bytes).into_owned(),
                        ),
                        _ => Event::Closed,
                    }
                }
                Err(_) => Event::Closed,
            },
        }
    }

    /// Hang up.
    pub fn close(&self, code: u32, reason: &str) {
        self.session.close(code, reason);
    }
}
