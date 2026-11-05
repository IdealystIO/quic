//! One end of a call against `examples/relay.rs`.
//!
//! ```text
//! cargo run -p datagram --example client -- <URL> [CERT_HASH_HEX]
//! ```
//!
//! Leave the hash off for a relay with a CA-issued certificate.
//!
//! Type a line to send it as a **datagram** (unreliable). Start it with `/c ` to
//! send it as a **control** message (reliable). `/burst N` sends N numbered
//! datagrams back to back, which is the quickest way to see loss and
//! reordering: the other client prints any gap it notices. `/quit` hangs up.

use std::time::Duration;

use datagram::{Event, Link};
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let Some(url) = args.next() else {
        eprintln!("usage: client <URL> [CERT_HASH_HEX]   (the relay prints both)");
        std::process::exit(2);
    };
    let hash = args.next().map(|h| datagram::parse_hash(&h).expect("certificate hash is not hex"));

    // A handshake nothing answers does not fail on its own for a long time, so
    // give up quickly and say so rather than sitting there looking connected.
    let link = match tokio::time::timeout(Duration::from_secs(5), Link::connect(&url, hash)).await {
        Ok(Ok(link)) => link,
        Ok(Err(e)) => {
            eprintln!("connect {url}: {e}");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("connect {url}: no answer in 5 s — is the relay running, and is this an address it can be reached on (not 0.0.0.0)?");
            std::process::exit(1);
        }
    };
    println!("connected (max datagram {} bytes)", link.max_datagram().await);
    println!("type to send a datagram, `/c text` for control, `/burst N`, `/quit`");

    let reader = link.clone();
    tokio::spawn(async move {
        // Per-sender last burst sequence number, to report gaps and reordering,
        // and (received, highest) for the summary once the burst goes quiet.
        let mut last: std::collections::HashMap<u32, u32> = Default::default();
        let mut tally: std::collections::HashMap<u32, (u32, u32)> = Default::default();
        loop {
            let event = match tokio::time::timeout(Duration::from_millis(300), reader.recv()).await {
                Ok(event) => event,
                Err(_) => {
                    for (from, (got, high)) in tally.drain() {
                        println!("[#{from}] burst: {got} of {} received", high + 1);
                    }
                    last.clear();
                    continue;
                }
            };
            match event {
                Event::Data(bytes) if bytes.len() >= 4 => {
                    let from = u32::from_be_bytes(bytes[..4].try_into().unwrap());
                    let body = &bytes[4..];
                    if let Some(seq) = body.strip_prefix(b"burst ").and_then(parse_u32) {
                        let t = tally.entry(from).or_default();
                        t.0 += 1;
                        t.1 = t.1.max(seq);
                        let prev = last.insert(from, seq);
                        match prev {
                            Some(p) if seq == p + 1 => {}
                            Some(p) if seq <= p => println!("[#{from}] burst {seq} arrived after {p} (reordered)"),
                            Some(p) => println!("[#{from}] burst {seq}: {} lost before it", seq - p - 1),
                            None if seq > 0 => println!("[#{from}] burst starts at {seq}: {seq} lost"),
                            None => {}
                        }
                    } else {
                        println!("[#{from}] datagram: {}", String::from_utf8_lossy(body));
                    }
                }
                Event::Data(bytes) => println!("[?] datagram: {bytes:?}"),
                Event::Control(text) => println!("[control] {text}"),
                Event::Closed => {
                    println!("relay closed the link");
                    std::process::exit(0);
                }
            }
        }
    });

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if line == "/quit" {
            break;
        } else if let Some(text) = line.strip_prefix("/c ") {
            if let Err(e) = link.control(text).await {
                eprintln!("control: {e}");
            }
        } else if let Some(n) = line.strip_prefix("/burst ").and_then(|n| n.trim().parse::<u32>().ok()) {
            let mut sent = 0;
            for i in 0..n {
                if link.send(format!("burst {i}").as_bytes()).await.is_ok() {
                    sent += 1;
                }
            }
            println!("sent {sent}/{n} datagrams");
        } else if let Err(e) = link.send(line.as_bytes()).await {
            eprintln!("send: {e}");
        }
    }
    link.close(0, "bye");
}

fn parse_u32(b: &[u8]) -> Option<u32> {
    std::str::from_utf8(b).ok()?.trim().parse().ok()
}
