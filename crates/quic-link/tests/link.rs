//! The link over a real QUIC connection: a datagram crosses it, control is
//! reliable and ordered beside it, and an oversized payload is refused.
//!
//! Native rather than in a browser on purpose: `web-transport` switches
//! backends by `#[path]`, so this proves the link's own behaviour without two
//! tabs. What it cannot prove is the browser's WebTransport implementation.

use std::time::Duration;

use quic_link::{Event, Identity, Link, Listener};

/// Bring up a listener on a loopback port and return it with what a client
/// needs to reach it.
async fn fleet() -> (Listener, String, Vec<u8>) {
    // Both names: `localhost` resolves to ::1 before 127.0.0.1 on this
    // machine, and a client that dials the address nothing is bound to just
    // times out — which looks exactly like a broken handshake.
    let identity = Identity::self_signed(&["localhost", "127.0.0.1"]).expect("certificate");
    let hash = identity.hash.clone();
    // Port 0: the OS picks a free one, so tests can run concurrently.
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &identity).expect("bind");
    let addr = listener.local_addr().expect("addr");
    (listener, format!("https://{addr}/room"), hash)
}

/// A session really is established, and a datagram really crosses it.
#[tokio::test]
async fn a_datagram_crosses_a_real_quic_connection() {
    let (mut listener, url, hash) = fleet().await;
    let server = tokio::spawn(async move {
        let link = listener.accept().await.expect("request").accept().await.expect("session");
        match link.recv().await {
            Event::Data(bytes) => bytes,
            other => panic!("expected a datagram, got {other:?}"),
        }
    });

    let client = Link::connect(&url, Some(hash)).await.expect("connect");
    // A retry loop rather than one send: the datagram is unreliable by
    // definition, and the very first one can be dropped while the connection
    // is still settling. Re-sending is what a media path does anyway.
    for _ in 0..20 {
        let _ = client.send(b"hello").await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let got = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server timed out")
        .expect("server panicked");
    assert_eq!(got, b"hello");
}

/// Control messages arrive reliably, and separately from media.
#[tokio::test]
async fn control_is_reliable_alongside_datagrams() {
    let (mut listener, url, hash) = fleet().await;
    let server = tokio::spawn(async move {
        let link = listener.accept().await.expect("request").accept().await.expect("session");
        let mut control = Vec::new();
        while control.len() < 3 {
            if let Event::Control(text) = link.recv().await {
                control.push(text);
            }
        }
        control
    });

    let client = Link::connect(&url, Some(hash)).await.expect("connect");
    for text in ["redirect:node-b", "info:suppress=client", "error:duplicate-id"] {
        client.control(text).await.expect("control");
    }
    let got = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server timed out")
        .expect("server panicked");
    // Ordered as well as delivered: one stream per message, but QUIC still
    // opens them in order.
    assert_eq!(got, vec!["redirect:node-b", "info:suppress=client", "error:duplicate-id"]);
}

/// The constraint that forced the codec, enforced rather than discovered.
#[tokio::test]
async fn an_oversized_payload_is_refused_with_the_limit() {
    let (mut listener, url, hash) = fleet().await;
    tokio::spawn(async move {
        let link = listener.accept().await.expect("request").accept().await.expect("session");
        // Hold the session open for the duration of the test.
        loop {
            if link.recv().await == Event::Closed {
                break;
            }
        }
    });
    let client = Link::connect(&url, Some(hash)).await.expect("connect");

    let limit = client.max_datagram().await;
    assert!(limit > 0 && limit < 2000, "implausible datagram limit: {limit}");

    // One 85 ms block of raw 48 kHz mono i16 — what this project used to send
    // per packet, and what cannot be sent at all over datagrams.
    let raw_pcm_block = vec![0u8; 4080 * 2];
    assert!(raw_pcm_block.len() > limit, "the point of this test has evaporated");
    match client.send(&raw_pcm_block).await {
        Err(quic_link::LinkError::TooLarge { size, limit: reported }) => {
            assert_eq!(size, raw_pcm_block.len());
            assert_eq!(reported, limit);
        }
        other => panic!("oversized datagram was not refused: {other:?}"),
    }
}
