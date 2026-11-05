//! A relay with nothing on top: every datagram and control message one client
//! sends is forwarded to every other client. No rooms, no tickets, no codec —
//! just enough to watch `datagram` carry traffic between two processes.
//!
//! ```text
//! cargo run -p datagram --example relay            # 127.0.0.1:4433, self-signed
//! cargo run -p datagram --example relay -- 0.0.0.0:4433
//! cargo run -p datagram --example relay -- 10.77.0.2:4433 \
//!     --cert fullchain.pem --key privkey.pem --host example.com
//! ```
//!
//! With `--cert`/`--key` it serves a CA-issued certificate, and clients dial
//! `https://<host>:<port>/` with no hash. Without, it makes a self-signed one
//! and prints the hash clients must pin — a new one on every start.
//!
//! Prints the command to start a client with; run it in two more terminals.

use std::sync::{Arc, Mutex};

use datagram::{Event, Identity, Link, Listener};

type Peers = Arc<Mutex<Vec<(u32, Link)>>>;

const USAGE: &str = "usage: relay [ADDR:PORT] [--cert FULLCHAIN.pem --key PRIVKEY.pem] [--host NAME]";

#[tokio::main]
async fn main() {
    let (mut addr, mut cert, mut key, mut host) = (None, None, None, None);
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| panic!("{arg} needs a value\n{USAGE}"));
        match arg.as_str() {
            "--cert" => cert = Some(value()),
            "--key" => key = Some(value()),
            "--host" => host = Some(value()),
            _ if addr.is_none() => addr = Some(arg.parse::<std::net::SocketAddr>().expect(USAGE)),
            _ => panic!("{USAGE}"),
        }
    }
    let addr = addr.unwrap_or_else(|| "127.0.0.1:4433".parse().unwrap());

    let identity = match (&cert, &key) {
        (Some(cert), Some(key)) => {
            let read = |p: &str| std::fs::read(p).unwrap_or_else(|e| panic!("{p}: {e}"));
            Identity::from_pem(&read(cert), &read(key)).expect("certificate")
        }
        (None, None) => {
            // Both names, for the same reason as the tests: `localhost` may
            // resolve to ::1 first, and the certificate has to cover whichever
            // one is dialled.
            Identity::self_signed(&["localhost", "127.0.0.1"]).expect("certificate")
        }
        _ => panic!("--cert and --key go together\n{USAGE}"),
    };
    let pinned = cert.is_none();
    let mut listener = Listener::bind(addr, &identity).expect("bind");
    let bound = listener.local_addr().expect("addr");

    // `0.0.0.0` is where to listen, not somewhere a client can dial — a QUIC
    // handshake sent there just goes unanswered until it times out. Print the
    // loopback address instead, on the bound port.
    let dial = match &host {
        Some(host) => format!("{host}:{}", bound.port()),
        None if bound.ip().is_unspecified() => format!("127.0.0.1:{}", bound.port()),
        None => bound.to_string(),
    };
    let hash = if pinned { identity.hash_hex() } else { String::new() };
    println!("[relay] listening on {bound}");
    println!("[relay] start a client with:");
    println!("    cargo run -p datagram --example client -- https://{dial}/ {hash}");
    println!("[relay] or open the quic-call page (`idealyst dev --web --local crates/quic-call`) at:");
    if pinned {
        println!("    http://localhost:8080/?url=https://{dial}/&hash={hash}");
    } else {
        println!("    http://localhost:8080/?url=https://{dial}/");
    }
    if host.is_none() && bound.ip().is_unspecified() {
        println!("[relay] from another machine, put this machine's IP in place of 127.0.0.1");
    }

    let peers: Peers = Arc::default();
    let mut next_id = 1u32;
    while let Some(request) = listener.accept().await {
        let from = request.remote_addr();
        let link = match request.accept().await {
            Ok(link) => link,
            Err(e) => {
                eprintln!("[relay] {from}: {e}");
                continue;
            }
        };
        let id = next_id;
        next_id += 1;
        println!("[relay] #{id} joined from {from} (max datagram {})", link.max_datagram().await);
        peers.lock().unwrap().push((id, link.clone()));
        tokio::spawn(serve(id, link, peers.clone()));
    }
}

async fn serve(id: u32, link: Link, peers: Peers) {
    let _ = link.control(&format!("you are #{id}")).await;
    // Datagrams are counted and reported every few seconds rather than logged
    // one by one: a voice call is fifty a second per person.
    let (mut count, mut bytes_in, mut since) = (0u64, 0u64, std::time::Instant::now());
    loop {
        let event = link.recv().await;
        if since.elapsed() >= std::time::Duration::from_secs(5) && count > 0 {
            println!("[relay] #{id}: {count} datagrams, {bytes_in} bytes in the last {:.0?}", since.elapsed());
            (count, bytes_in, since) = (0, 0, std::time::Instant::now());
        }
        if event == Event::Closed {
            break;
        }
        // Snapshot rather than holding the lock across the sends.
        let others: Vec<Link> = peers
            .lock()
            .unwrap()
            .iter()
            .filter(|(other, _)| *other != id)
            .map(|(_, l)| l.clone())
            .collect();
        match event {
            Event::Data(bytes) => {
                count += 1;
                bytes_in += bytes.len() as u64;
                // Prefix the sender so a client can tell who it heard.
                let mut out = id.to_be_bytes().to_vec();
                out.extend_from_slice(&bytes);
                for other in others {
                    if let Err(e) = other.send(&out).await {
                        eprintln!("[relay] forward from #{id}: {e}");
                    }
                }
            }
            Event::Control(text) => {
                println!("[relay] #{id} control: {text}");
                for other in others {
                    let _ = other.control(&format!("#{id}: {text}")).await;
                }
            }
            Event::Closed => unreachable!(),
        }
    }
    let others: Vec<Link> = {
        let mut peers = peers.lock().unwrap();
        peers.retain(|(other, _)| *other != id);
        peers.iter().map(|(_, l)| l.clone()).collect()
    };
    for other in others {
        let _ = other.control(&format!("#{id} left")).await;
    }
    println!("[relay] #{id} left");
}
