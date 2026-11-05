//! `call-relay`: serve rooms, and act as a minimal issuer for them.
//!
//! ```text
//! call-relay [ADDR:PORT] [--cert FULLCHAIN.pem --key PRIVKEY.pem] [--host NAME]
//!            [--secret-file FILE] [--max-ttl SECS] [--grace SECS] [--throttle on|off]
//!            [--loss PERCENT] [--cap KBPS] [--loss-to N]
//! call-relay mint   --secret-file FILE --room ROOM --user USER [--send avs] [--ttl SECS]
//! call-relay revoke --secret-file FILE --relay URL [--hash HEX] --user USER
//!                   [--room ROOM] [--send CODE]
//! ```
//!
//! **Serving.** With `--cert`/`--key` it serves a CA-issued certificate and
//! clients dial `https://<host>:<port>/` with no hash; without, it makes a
//! self-signed one and prints the hash clients must pin — a new one on every
//! start. With `--secret-file` it checks `call-auth` grants: nobody gets in
//! without one, and nobody sends what theirs does not allow. Without, anyone
//! may join any room. `--throttle on` holds back video from clients whose
//! download cannot take it all — more work for the relay, a steadier call
//! for them. For testing: `--loss` drops that share of datagrams at random —
//! a bad link on demand, for bitrate control — and `--cap` forwards at most
//! that many kb/s to each client — a slow download, for throttling; with
//! `--loss-to N`, either applies only to what goes to client N.
//!
//! **Issuing.** `mint` prints a grant; `revoke` signs a revocation and hands
//! it to a running relay — a kick, or with `--send` a limit (`--send -` for
//! listen-only); without `--room`, for every room. Any issuer holding the
//! secret can do the same through `call-auth` — Hearth's API server, for one.

use std::time::Duration;

use call_auth::{Action, Grant, Revocation, Send};
use call_proto::relay::{Connect, FromRelay};
use call_relay::{now_ms, Auth, Config};
use datagram::{Event, Identity, Link, Listener};

const USAGE: &str = "usage:
  call-relay [ADDR:PORT] [--cert FULLCHAIN.pem --key PRIVKEY.pem] [--host NAME]
             [--secret-file FILE] [--max-ttl SECS] [--grace SECS] [--throttle on|off]
             [--loss PERCENT] [--cap KBPS] [--loss-to N]
  call-relay mint   --secret-file FILE --room ROOM --user USER [--send avs] [--ttl SECS]
  call-relay revoke --secret-file FILE --relay URL [--hash HEX] --user USER [--room ROOM] [--send CODE]";

/// Flags as name → value, and the positional arguments.
fn flags(args: impl Iterator<Item = String>) -> (std::collections::HashMap<String, String>, Vec<String>) {
    let (mut named, mut positional) = (std::collections::HashMap::new(), Vec::new());
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        match arg.strip_prefix("--") {
            Some(name) => {
                let value = args.next().unwrap_or_else(|| fail(&format!("--{name} needs a value")));
                named.insert(name.to_string(), value);
            }
            None => positional.push(arg),
        }
    }
    (named, positional)
}

fn fail(why: &str) -> ! {
    eprintln!("{why}\n{USAGE}");
    std::process::exit(2)
}

fn secret(flags: &std::collections::HashMap<String, String>) -> Option<Vec<u8>> {
    let path = flags.get("secret-file")?;
    let bytes = std::fs::read(path).unwrap_or_else(|e| fail(&format!("{path}: {e}")));
    let trimmed = String::from_utf8_lossy(&bytes).trim().as_bytes().to_vec();
    if trimmed.len() < 16 {
        fail(&format!("{path}: a secret this short can be guessed — use 32 random bytes or more"));
    }
    Some(trimmed)
}

fn secs(flags: &std::collections::HashMap<String, String>, name: &str, default: u64) -> Duration {
    Duration::from_secs(flags.get(name).map(|v| v.parse().unwrap_or_else(|_| fail(&format!("--{name}: seconds")))).unwrap_or(default))
}

fn need<'a>(flags: &'a std::collections::HashMap<String, String>, name: &str) -> &'a str {
    flags.get(name).map(String::as_str).unwrap_or_else(|| fail(&format!("--{name} is required")))
}

fn id(flags: &std::collections::HashMap<String, String>, name: &str) -> String {
    let v = need(flags, name);
    if !call_auth::valid_id(v) {
        fail(&format!("--{name} {v:?}: ids are letters, digits, _ ~ -"));
    }
    v.to_string()
}

fn send(flags: &std::collections::HashMap<String, String>) -> Option<Send> {
    flags.get("send").map(|c| Send::parse(c).unwrap_or_else(|| fail("--send: any of a v s, or - for nothing")))
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1).peekable();
    match args.peek().map(String::as_str) {
        Some("mint") => {
            args.next();
            let (f, _) = flags(args);
            let secret = secret(&f).unwrap_or_else(|| fail("--secret-file is required"));
            let ttl = secs(&f, "ttl", 120);
            println!(
                "{}",
                Grant::mint(&secret, &id(&f, "room"), &id(&f, "user"), send(&f).unwrap_or(Send::ALL), now_ms(), ttl.as_millis() as u64)
            );
        }
        Some("revoke") => {
            args.next();
            let (f, _) = flags(args);
            let secret = secret(&f).unwrap_or_else(|| fail("--secret-file is required"));
            let room = f.contains_key("room").then(|| id(&f, "room"));
            let action = send(&f).map(Action::Limit).unwrap_or(Action::Kick);
            let token = Revocation::mint(&secret, room.as_deref(), &id(&f, "user"), action, now_ms());
            let hash = f.get("hash").map(|h| datagram::parse_hash(h).unwrap_or_else(|| fail("--hash: 64 hex characters")));
            let url = Connect { revoke: Some(token), ..Default::default() }.url(need(&f, "relay"));
            let link = Link::connect(&url, hash).await.unwrap_or_else(|e| {
                eprintln!("the relay did not take it: {e}");
                std::process::exit(1)
            });
            let answer = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    match link.recv().await {
                        Event::Control(t) if FromRelay::parse(&t) == FromRelay::Applied => return true,
                        Event::Closed => return false,
                        _ => {}
                    }
                }
            })
            .await;
            if answer != Ok(true) {
                eprintln!("the relay did not confirm the revocation");
                std::process::exit(1);
            }
            println!("revoked");
        }
        _ => serve(args).await,
    }
}

async fn serve(args: impl Iterator<Item = String>) {
    let (f, positional) = flags(args);
    let addr: std::net::SocketAddr = positional
        .first()
        .map(|a| a.parse().unwrap_or_else(|_| fail(&format!("{a}: not ADDR:PORT"))))
        .unwrap_or_else(|| "127.0.0.1:4433".parse().unwrap());
    let identity = match (f.get("cert"), f.get("key")) {
        (Some(cert), Some(key)) => {
            let read = |p: &str| std::fs::read(p).unwrap_or_else(|e| fail(&format!("{p}: {e}")));
            Identity::from_pem(&read(cert), &read(key)).expect("certificate")
        }
        // Both names: `localhost` may resolve to ::1 first, and the
        // certificate has to cover whichever one is dialled.
        (None, None) => Identity::self_signed(&["localhost", "127.0.0.1"]).expect("certificate"),
        _ => fail("--cert and --key go together"),
    };
    let pinned = !f.contains_key("cert");
    let auth = secret(&f).map(|secret| Auth { secret, max_ttl: secs(&f, "max-ttl", 600) });
    let authed = auth.is_some();
    let listener = Listener::bind(addr, &identity).expect("bind");
    let bound = listener.local_addr().expect("addr");

    // `0.0.0.0` is where to listen, not somewhere a client can dial. Print the
    // loopback address instead, on the bound port.
    let dial = match f.get("host") {
        Some(host) => format!("{host}:{}", bound.port()),
        None if bound.ip().is_unspecified() => format!("127.0.0.1:{}", bound.port()),
        None => bound.to_string(),
    };
    let hash = if pinned { format!("&hash={}", identity.hash_hex()) } else { String::new() };
    println!("[relay] listening on {bound}");
    if authed {
        println!("[relay] checking grants; mint one with `call-relay mint --secret-file … --room R --user U`");
        println!("[relay] open the quic-call page at:");
        println!("    http://localhost:8080/?url=https://{dial}/{hash}&room=R&grant=<grant>");
    } else {
        println!("[relay] no --secret-file: anyone may join any room");
        println!("[relay] open the quic-call page (`idealyst dev --web --local crates/quic-call`) at:");
        println!("    http://localhost:8080/?url=https://{dial}/{hash}");
    }
    if f.get("host").is_none() && bound.ip().is_unspecified() {
        println!("[relay] from another machine, put this machine's IP in place of 127.0.0.1");
    }
    let loss = f.get("loss").map(|v| {
        v.parse::<f64>().ok().filter(|p| (0.0..=100.0).contains(p)).unwrap_or_else(|| fail("--loss: a percentage, 0 to 100"))
            / 100.0
    });
    if let Some(loss) = loss.filter(|&l| l > 0.0) {
        println!("[relay] dropping {:.0}% of datagrams at random (--loss), for testing", loss * 100.0);
    }
    let cap_bps = f.get("cap").map(|v| v.parse::<u32>().unwrap_or_else(|_| fail("--cap: kb/s")) * 1000);
    if let Some(bps) = cap_bps {
        println!("[relay] capping what each client is sent at {} kb/s (--cap), for testing", bps / 1000);
    }
    let loss_to = f.get("loss-to").map(|v| v.trim_start_matches('#').parse().unwrap_or_else(|_| fail("--loss-to: a client number")));
    let throttle = f.get("throttle").map(|v| match v.as_str() {
        "on" => true,
        "off" => false,
        _ => fail("--throttle: on or off"),
    });
    if throttle == Some(true) {
        println!("[relay] throttling: holding back video from clients whose download cannot take it");
    }
    call_relay::serve(
        listener,
        Config {
            auth,
            grace: secs(&f, "grace", 15),
            loss: loss.unwrap_or(0.0),
            cap_bps,
            loss_to,
            throttle: throttle.unwrap_or(false),
        },
    )
    .await;
}
