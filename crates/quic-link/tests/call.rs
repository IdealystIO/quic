//! The whole chain, over a real QUIC connection: Opus in, datagrams across a
//! socket, jitter buffer out.
//!
//! Native rather than in a browser on purpose. Every piece here is the same
//! code the browser runs — `web-transport` switches backends by `#[path]`, and
//! `jitter` and `audio-codec` are target-independent — so this proves the
//! assembly without needing two tabs and a fake microphone. What it cannot
//! prove is the browser's own WebTransport implementation, which is why the
//! end-to-end browser suites still exist.

use std::sync::Arc;
use std::time::Duration;

use audio_codec::{Encoder, MAX_PACKET, Settings};
use datagram::{Event, Identity, Link, Listener};

const RATE: u32 = 48_000;

/// Speech-shaped: a fundamental with harmonics, modulated at syllable rate.
fn speech(n: usize, from: usize) -> Vec<f32> {
    (0..n)
        .map(|i| {
            let t = (from + i) as f32 / RATE as f32;
            let env = 0.5 + 0.5 * (t * 4.0 * std::f32::consts::TAU).sin();
            let mut v = 0.0;
            for h in 1..=6 {
                v += (t * 140.0 * h as f32 * std::f32::consts::TAU).sin() / h as f32;
            }
            v * 0.25 * env
        })
        .collect()
}

fn rms(x: &[f32]) -> f32 {
    (x.iter().map(|s| s * s).sum::<f32>() / x.len().max(1) as f32).sqrt()
}

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
        let link = listener.accept().await.expect("session");
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
        let link = listener.accept().await.expect("session");
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
        let link = listener.accept().await.expect("session");
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
        Err(datagram::LinkError::TooLarge { size, limit: reported }) => {
            assert_eq!(size, raw_pcm_block.len());
            assert_eq!(reported, limit);
        }
        other => panic!("oversized datagram was not refused: {other:?}"),
    }
}

/// The prototype, end to end: encode, cross a real network, play out through
/// the jitter buffer, with loss actually happening.
#[tokio::test]
async fn a_call_survives_loss_over_quic() {
    let settings = Settings { dtx: false, ..Settings::default() };
    let frame_ms = settings.frame.ms() as f64;
    let (mut listener, url, hash) = fleet().await;

    // The listener: everything that arrives goes into the jitter buffer, and a
    // steady pull drains it — which is what a playback device does.
    let received = Arc::new(std::sync::Mutex::new(Vec::<f32>::new()));
    let stats = Arc::new(std::sync::Mutex::new(jitter::Stats::default()));
    let (sink, tally) = (received.clone(), stats.clone());
    let server = tokio::spawn(async move {
        let link = listener.accept().await.expect("session");
        let decoder = audio_codec::Decoder::new(settings.frame, RATE, 1).expect("decoder");
        let mut buffer = jitter::Buffer::new(jitter::Tuning::default(), decoder, RATE, 1);
        let frame = settings.frame.frames(RATE);
        let mut out = vec![0.0; frame];
        let start = std::time::Instant::now();
        let mut pulled = 0u32;

        loop {
            // Pull on a clock, push on arrival — the two are independent, which
            // is the entire reason a jitter buffer exists.
            let due = Duration::from_micros((pulled as f64 * frame_ms * 1000.0) as u64);
            let elapsed = start.elapsed();
            // Zero rather than a synthesised timeout error: `timeout` with a
            // zero duration fires immediately, which is exactly "the pull clock
            // is already due".
            let wait = due.saturating_sub(elapsed);
            match tokio::time::timeout(wait, link.recv()).await {
                Ok(Event::Data(bytes)) => {
                    let seq = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    let at = start.elapsed().as_secs_f64() * 1000.0;
                    let _ = buffer.push(seq, &bytes[4..], at);
                }
                Ok(Event::Closed) => break,
                Ok(Event::Control(_)) => {}
                // The pull clock came due.
                Err(_) => {
                    buffer.pull(&mut out);
                    sink.lock().unwrap().extend_from_slice(&out);
                    pulled += 1;
                    // Comfortably more than the sender will produce. Stopping
                    // at exactly the frame count is a race: the playout clock
                    // runs slightly ahead of a sender that sleeps between
                    // frames, so the session would drop while the client was
                    // still sending — which presents as a transport failure
                    // rather than as the test's own bookkeeping.
                    if pulled >= 130 {
                        break;
                    }
                }
            }
        }
        *tally.lock().unwrap() = buffer.stats();
    });

    let client = Link::connect(&url, Some(hash)).await.expect("connect");
    let mut encoder = Encoder::new(settings, RATE, 1).expect("encoder");
    let frame = encoder.frame();
    let mut scratch = vec![0u8; MAX_PACKET];
    for seq in 0..90u32 {
        let pcm = speech(frame, seq as usize * frame);
        let packet = encoder.encode(&pcm, &mut scratch).expect("encode");
        // Deliberate loss, on top of whatever the network does. Every ninth
        // packet never leaves — which on a reliable transport would be
        // impossible to simulate without a proxy.
        if seq % 9 != 4 {
            let mut framed = seq.to_be_bytes().to_vec();
            framed.extend_from_slice(packet);
            client.send(&framed).await.expect("send");
        }
        tokio::time::sleep(Duration::from_millis(settings.frame.ms() as u64)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    client.close(0, "done");

    let _ = tokio::time::timeout(Duration::from_secs(10), server).await;

    let played = received.lock().unwrap().clone();
    let stats = *stats.lock().unwrap();
    println!("  {stats:?}");
    println!("  played {} frames, rms {:.4}", played.len() / frame, rms(&played));

    assert!(stats.received > 60, "not enough arrived to judge anything: {stats:?}");
    assert!(stats.concealed >= 5, "the deliberate drops were not concealed: {stats:?}");
    // The claim: continuous audio came out despite one in nine never arriving.
    let audible = &played[frame * 8..];
    assert!(rms(audible) > 0.01, "silence came out the far end: {}", rms(audible));
    assert!(audible.iter().all(|s| s.is_finite() && s.abs() <= 1.5));
}
