//! The relay's authorisation, over real QUIC connections: who gets in, whose
//! datagrams are forwarded, and how fast a revocation or a lapsed grant takes
//! effect.

use std::time::Duration;

use call_auth::{Action, Grant, Revocation, Send};
use call_proto::relay::{untag, Connect, FromRelay, LossReport};
use call_proto::{audio, video, TRACK_MAIN};
use call_relay::{now_ms, Auth, Config};
use datagram::{Event, Identity, Link, Listener};

const SECRET: &[u8] = b"a test secret of reasonable length";

struct Relay {
    base: String,
    hash: Vec<u8>,
}

async fn relay(grace: Duration) -> Relay {
    relay_with(Config { grace, ..Default::default() }).await
}

async fn relay_with(config: Config) -> Relay {
    let identity = Identity::self_signed(&["localhost", "127.0.0.1"]).expect("certificate");
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &identity).expect("bind");
    let base = format!("https://{}/", listener.local_addr().unwrap());
    let auth = Auth { secret: SECRET.to_vec(), max_ttl: Duration::from_secs(600) };
    tokio::spawn(call_relay::serve(listener, Config { auth: Some(auth), ..config }));
    Relay { base, hash: identity.hash }
}

fn grant(room: &str, user: &str, send: Send, ttl_ms: u64) -> String {
    Grant::mint(SECRET, room, user, send, now_ms(), ttl_ms)
}

impl Relay {
    async fn join(&self, room: &str, grant: Option<String>) -> Result<Link, String> {
        let url = Connect { room: room.into(), grant, revoke: None }.url(&self.base);
        Link::connect(&url, Some(self.hash.clone())).await.map_err(|e| e.to_string())
    }

    async fn revoke(&self, room: Option<&str>, user: &str, action: Action) {
        let token = Revocation::mint(SECRET, room, user, action, now_ms());
        let url = Connect { revoke: Some(token), ..Default::default() }.url(&self.base);
        let admin = Link::connect(&url, Some(self.hash.clone())).await.expect("admin session");
        assert_eq!(control(&admin, |m| matches!(m, FromRelay::Applied)).await, Some(FromRelay::Applied));
    }
}

/// The next control message `want` accepts, skipping others, within 3 s.
async fn control(link: &Link, want: impl Fn(&FromRelay) -> bool) -> Option<FromRelay> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match link.recv().await {
                Event::Control(t) => {
                    let m = FromRelay::parse(&t);
                    if want(&m) {
                        return Some(m);
                    }
                }
                Event::Closed => return None,
                Event::Data(_) => {}
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// Whether a datagram arrives within `ms`, skipping control messages.
async fn hears(link: &Link, ms: u64) -> bool {
    tokio::time::timeout(Duration::from_millis(ms), async {
        loop {
            match link.recv().await {
                Event::Data(bytes) => return untag(&bytes).is_some(),
                Event::Closed => return false,
                Event::Control(_) => {}
            }
        }
    })
    .await
    .unwrap_or(false)
}

/// Whether the link is closed within `ms`.
async fn closed(link: &Link, ms: u64) -> bool {
    tokio::time::timeout(Duration::from_millis(ms), async {
        loop {
            if link.recv().await == Event::Closed {
                return true;
            }
        }
    })
    .await
    .unwrap_or(false)
}

fn voice() -> Vec<u8> {
    audio::encode(TRACK_MAIN, 0, 48_000, 0, &[1, 2, 3])
}

fn picture() -> Vec<u8> {
    video::fragment(TRACK_MAIN, 0, 0, true, &[7; 50], 1000).unwrap().remove(0)
}

/// Keep sending one datagram until the other end hears it (the first may beat
/// the receiver's session), or give up.
async fn gets_through(from: &Link, to: &Link, datagram: &[u8]) -> bool {
    for _ in 0..10 {
        let _ = from.send(datagram).await;
        if hears(to, 150).await {
            return true;
        }
    }
    false
}

#[tokio::test]
async fn nobody_gets_in_without_a_good_grant() {
    let r = relay(Duration::from_secs(5)).await;
    assert!(r.join("porch", None).await.is_err(), "no grant");
    let forged = Grant::mint(b"not the secret at all, no", "porch", "eve", Send::ALL, now_ms(), 60_000);
    assert!(r.join("porch", Some(forged)).await.is_err(), "wrong secret");
    assert!(r.join("attic", Some(grant("porch", "eve", Send::ALL, 60_000))).await.is_err(), "another room's");
    assert!(r.join("porch", Some(grant("porch", "alice", Send::ALL, 60_000))).await.is_ok());
}

#[tokio::test]
async fn granted_clients_are_named_and_hear_each_other_within_their_room() {
    let r = relay(Duration::from_secs(5)).await;
    let alice = r.join("porch", Some(grant("porch", "alice", Send::ALL, 60_000))).await.unwrap();
    let bob = r.join("porch", Some(grant("porch", "bob", Send::ALL, 60_000))).await.unwrap();
    let carol = r.join("attic", Some(grant("attic", "carol", Send::ALL, 60_000))).await.unwrap();
    assert!(control(&alice, |m| matches!(m, FromRelay::Joined(_))).await.is_some(), "alice is told someone joined");
    let named = control(&alice, |m| matches!(m, FromRelay::Named { user, .. } if user == "bob")).await;
    assert!(named.is_some(), "alice is told who bob is");
    assert!(gets_through(&alice, &bob, &voice()).await);
    assert!(!hears(&carol, 300).await, "the attic hears nothing from the porch");
}

#[tokio::test]
async fn a_ping_is_answered_to_the_sender_only() {
    let r = relay(Duration::from_secs(5)).await;
    let alice = r.join("porch", Some(grant("porch", "alice", Send::ALL, 60_000))).await.unwrap();
    let bob = r.join("porch", Some(grant("porch", "bob", Send::ALL, 60_000))).await.unwrap();
    alice.control("ping 7").await.unwrap();
    assert_eq!(control(&alice, |m| matches!(m, FromRelay::Pong(_))).await, Some(FromRelay::Pong(7)));
    assert!(control(&bob, |m| matches!(m, FromRelay::Pong(_) | FromRelay::Said { .. })).await.is_none());
}

#[tokio::test]
async fn a_listen_only_grant_cannot_send() {
    let r = relay(Duration::from_secs(5)).await;
    let alice = r.join("porch", Some(grant("porch", "alice", Send::NONE, 60_000))).await.unwrap();
    let bob = r.join("porch", Some(grant("porch", "bob", Send::ALL, 60_000))).await.unwrap();
    assert!(gets_through(&bob, &alice, &voice()).await, "she can listen");
    assert!(!gets_through(&alice, &bob, &voice()).await, "but not speak");
}

#[tokio::test]
async fn a_kick_cuts_someone_off_at_once_and_keeps_them_out() {
    let r = relay(Duration::from_secs(5)).await;
    let old = grant("porch", "alice", Send::ALL, 60_000);
    let alice = r.join("porch", Some(old.clone())).await.unwrap();
    let bob = r.join("porch", Some(grant("porch", "bob", Send::ALL, 60_000))).await.unwrap();
    assert!(gets_through(&alice, &bob, &voice()).await);

    r.revoke(Some("porch"), "alice", Action::Kick).await;
    assert_eq!(control(&alice, |m| matches!(m, FromRelay::Revoked)).await, Some(FromRelay::Revoked));
    assert!(control(&bob, |m| matches!(m, FromRelay::Left(_))).await.is_some(), "bob is told she left");
    assert!(closed(&alice, 2000).await, "and disconnected");
    assert!(r.join("porch", Some(old)).await.is_err(), "the grant she had is void");
    // Issued after the kick: the issuer has let her back.
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert!(r.join("porch", Some(grant("porch", "alice", Send::ALL, 60_000))).await.is_ok());
}

#[tokio::test]
async fn an_issuer_in_the_same_process_revokes_through_the_handle() {
    let identity = Identity::self_signed(&["localhost", "127.0.0.1"]).expect("certificate");
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &identity).expect("bind");
    let base = format!("https://{}/", listener.local_addr().unwrap());
    let auth = Auth { secret: SECRET.to_vec(), max_ttl: Duration::from_secs(600) };
    let handle = call_relay::spawn(listener, Config { auth: Some(auth), grace: Duration::from_secs(5), ..Default::default() });
    let r = Relay { base, hash: identity.hash };
    let alice = r.join("porch", Some(grant("porch", "alice", Send::ALL, 60_000))).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(handle.connected(), 1);
    let token = Revocation::mint(SECRET, Some("porch"), "alice", Action::Kick, now_ms());
    assert_eq!(handle.revoke(&token).await, Ok(1));
    assert_eq!(control(&alice, |m| matches!(m, FromRelay::Revoked)).await, Some(FromRelay::Revoked));
    assert!(handle.revoke("r1.nonsense").await.is_err());
}

#[tokio::test]
async fn a_ban_covers_every_room() {
    let r = relay(Duration::from_secs(5)).await;
    let porch = r.join("porch", Some(grant("porch", "alice", Send::ALL, 60_000))).await.unwrap();
    let attic = r.join("attic", Some(grant("attic", "alice", Send::ALL, 60_000))).await.unwrap();
    r.revoke(None, "alice", Action::Kick).await;
    assert!(closed(&porch, 2000).await && closed(&attic, 2000).await);
}

#[tokio::test]
async fn end_to_end_encrypted_media_is_forwarded_and_still_gated() {
    // The relay holds no key: it routes sealed datagrams on their clear kind
    // and track, and a grant's limits apply to them as to any.
    let r = relay(Duration::from_secs(5)).await;
    let alice = r.join("porch", Some(grant("porch", "alice", Send::parse("a").unwrap(), 60_000))).await.unwrap();
    let bob = r.join("porch", Some(grant("porch", "bob", Send::ALL, 60_000))).await.unwrap();
    let mut seal = call_e2ee::Sealer::new(&call_e2ee::RoomKey::from_text("k").unwrap(), 0, 1);
    assert!(gets_through(&alice, &bob, &seal.seal(&voice()).unwrap()).await, "sealed voice goes");
    assert!(!gets_through(&alice, &bob, &seal.seal(&picture()).unwrap()).await, "sealed video is still video");
}

#[tokio::test]
async fn a_throttling_relay_holds_back_layers_from_a_losing_download() {
    let r = relay_with(Config { throttle: true, ..Default::default() }).await;
    let alice = r.join("porch", Some(grant("porch", "alice", Send::ALL, 60_000))).await.unwrap();
    let Some(FromRelay::You(alice_id)) = control(&alice, |m| matches!(m, FromRelay::You(_))).await else {
        panic!("alice was not numbered");
    };
    let bob = r.join("porch", Some(grant("porch", "bob", Send::ALL, 60_000))).await.unwrap();
    let layer = |n: u8| {
        let deps = video::Deps { key: false, layer: n, back: 1 };
        video::fragment_layered(TRACK_MAIN, 5, 0, deps, &[7; 50], 1000).unwrap().remove(0)
    };
    assert!(gets_through(&alice, &bob, &layer(2)).await, "everything, to start with");

    // Bob says he is losing 30% of alice — and the relay saw none of it go
    // missing on the way in, so it is his download.
    bob.control(&LossReport(vec![(alice_id, 300)]).to_text()).await.unwrap();
    assert_eq!(control(&bob, |m| matches!(m, FromRelay::Throttled(_))).await, Some(FromRelay::Throttled(1)));
    assert!(!gets_through(&alice, &bob, &layer(2)).await, "the top layer is held back");
    assert!(gets_through(&alice, &bob, &layer(0)).await, "the base layer is not");
    assert!(gets_through(&alice, &bob, &voice()).await, "nor is voice");
}

#[tokio::test]
async fn a_relay_that_does_not_throttle_forwards_everything_whatever_is_reported() {
    let r = relay(Duration::from_secs(5)).await;
    let alice = r.join("porch", Some(grant("porch", "alice", Send::ALL, 60_000))).await.unwrap();
    let bob = r.join("porch", Some(grant("porch", "bob", Send::ALL, 60_000))).await.unwrap();
    bob.control(&LossReport(vec![(1, 900)]).to_text()).await.unwrap();
    let top = video::fragment_layered(TRACK_MAIN, 5, 0, video::Deps { key: false, layer: 2, back: 1 }, &[7; 50], 1000)
        .unwrap()
        .remove(0);
    assert!(gets_through(&alice, &bob, &top).await);
}

#[tokio::test]
async fn a_limit_filters_what_someone_may_send() {
    let r = relay(Duration::from_secs(5)).await;
    let alice = r.join("porch", Some(grant("porch", "alice", Send::ALL, 60_000))).await.unwrap();
    let bob = r.join("porch", Some(grant("porch", "bob", Send::ALL, 60_000))).await.unwrap();
    assert!(gets_through(&alice, &bob, &picture()).await);
    r.revoke(Some("porch"), "alice", Action::Limit(Send::parse("a").unwrap())).await;
    assert_eq!(control(&alice, |m| matches!(m, FromRelay::MaySend(_))).await, Some(FromRelay::MaySend("a".into())));
    assert!(!gets_through(&alice, &bob, &picture()).await, "no more video");
    assert!(gets_through(&alice, &bob, &voice()).await, "voice still");
}

#[tokio::test]
async fn an_unrenewed_grant_stops_sending_then_is_closed_and_a_renewal_keeps_it_going() {
    let r = relay(Duration::from_millis(1000)).await;
    let bob = r.join("porch", Some(grant("porch", "bob", Send::ALL, 60_000))).await.unwrap();
    let alice = r.join("porch", Some(grant("porch", "alice", Send::ALL, 1500))).await.unwrap();
    let carol = r.join("porch", Some(grant("porch", "carol", Send::ALL, 1500))).await.unwrap();
    assert!(gets_through(&alice, &bob, &voice()).await);

    // Carol renews before hers runs out; alice does not.
    let fresh = grant("porch", "carol", Send::ALL, 60_000);
    carol.control(&format!("renew {fresh}")).await.unwrap();
    assert!(control(&carol, |m| matches!(m, FromRelay::Expires { secs } if *secs > 30)).await.is_some());

    tokio::time::sleep(Duration::from_millis(1600)).await;
    assert!(!gets_through(&alice, &bob, &voice()).await, "alice's lapsed grant sends nothing");
    assert!(gets_through(&carol, &bob, &voice()).await, "carol's renewed one does");
    assert!(closed(&alice, 2000).await, "and alice is closed after the grace");

    // Renewing with someone else's grant is refused.
    carol.control(&format!("renew {}", grant("porch", "bob", Send::ALL, 60_000))).await.unwrap();
    assert!(control(&carol, |m| matches!(m, FromRelay::Refused(_))).await.is_some());
}
