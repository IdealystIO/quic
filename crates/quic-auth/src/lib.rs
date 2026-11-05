//! Who may send what in a quic-call room, and how that is taken back.
//!
//! Three parties. An **issuer** — whatever decides membership: Hearth's API
//! server, a CLI, anything holding the room's secret — signs **grants** and
//! **revocations**. A **client** presents a grant when it connects. The
//! **relay** checks both with the same secret and asks nobody, and enforces
//! them on every datagram.
//!
//! # Grants
//!
//! "`user` may be in `room` and send `send`, from `issued` until `expires`."
//! A client puts one in its connect URL (`?room=R&grant=…`); the relay
//! refuses the connection outright if it does not check out, so nothing
//! unauthorised ever gets a session.
//!
//! Grants are short — minutes — and the client renews before one runs out by
//! sending a fresh one over the control channel (`renew <grant>`), which it
//! gets from the issuer however that issuer likes. When a grant lapses
//! unrenewed, the relay stops forwarding the client's datagrams at once, and
//! closes the connection after a short grace. Renewal is the backstop for
//! revocation: an issuer that stops issuing has removed someone within one
//! grant's lifetime, even if nothing else reaches the relay.
//!
//! # Revocations
//!
//! "As of `at`, `user`'s grants for `room` (or every room) issued before then
//! are void" (`kick`) — or "capped to sending `send`" (a limit: listen-only, no
//! screen). The issuer delivers one by connecting to the relay with it
//! (`?revoke=…`). The relay applies it to everyone connected straight away —
//! a kicked client is told and disconnected; a limited one is told and its
//! datagrams filtered — and refuses the voided grants until they would have
//! expired anyway. Grants issued *after* `at` are untouched, so the issuer
//! lets someone back in simply by issuing them a new one.
//!
//! A relay holds revocations in memory, for at most [`Gate::max_ttl_ms`] each
//! (no grant it accepts lives longer). If it restarts it forgets them — and
//! renewal still removes the person within a grant's lifetime.
//!
//! # Why datagrams need no signature
//!
//! QUIC authenticates every packet of a connection to whoever completed its
//! handshake, so the relay checks a grant once per connection and then only
//! looks up what that connection may send. It tags each forwarded datagram
//! with the sender's number itself, so no client can speak as another.
//!
//! # Token formats
//!
//! ```text
//! grant:      g1.<room>.<user>.<send>.<issued ms>.<expires ms>.<hmac>
//! revocation: r1.<room or *>.<user>.<kick | send:<send>>.<at ms>.<hmac>
//! send:       any of a (audio), v (video), s (screen and its audio); - for none
//! ```
//!
//! Room and user ids are `[A-Za-z0-9_~-]`, so a token goes in a URL as it
//! is. The HMAC is SHA-256 over the fields NUL-separated behind a label per
//! kind, so neither kind of token can be passed off as the other.

use call_proto::Media;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Clocks disagree: a grant issued this far in the future is still taken.
pub const CLOCK_SKEW_MS: u64 = 30_000;

/// What a holder may send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Send {
    pub audio: bool,
    pub video: bool,
    pub screen: bool,
}

impl Send {
    pub const ALL: Send = Send { audio: true, video: true, screen: true };
    pub const NONE: Send = Send { audio: false, video: false, screen: false };

    pub fn allows(self, media: Media) -> bool {
        match media {
            Media::Audio => self.audio,
            Media::Video => self.video,
            Media::Screen => self.screen,
        }
    }

    /// Only what both allow.
    pub fn cap(self, to: Send) -> Send {
        Send { audio: self.audio && to.audio, video: self.video && to.video, screen: self.screen && to.screen }
    }

    pub fn to_code(self) -> String {
        let code: String = [(self.audio, 'a'), (self.video, 'v'), (self.screen, 's')]
            .iter()
            .filter(|(on, _)| *on)
            .map(|(_, c)| *c)
            .collect();
        if code.is_empty() { "-".to_string() } else { code }
    }

    pub fn parse(code: &str) -> Option<Send> {
        if code == "-" {
            return Some(Send::NONE);
        }
        let mut s = Send::NONE;
        for c in code.chars() {
            let slot = match c {
                'a' => &mut s.audio,
                'v' => &mut s.video,
                's' => &mut s.screen,
                _ => return None,
            };
            if *slot {
                return None; // "aa" is not a way to write anything
            }
            *slot = true;
        }
        (!code.is_empty()).then_some(s)
    }
}

/// Why a token was not accepted. Coarse on purpose: a client is told to get
/// a new grant, not which byte was wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Malformed,
    /// Signed with another secret, for another room, or altered.
    BadSignature,
    Expired,
    /// Valid, but a revocation voids it.
    Revoked,
    /// Lives longer than this relay accepts, or was issued too far ahead.
    OutOfBounds,
    /// A renewal for someone else, or another room.
    NotYours,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Refusal::Malformed => "malformed",
            Refusal::BadSignature => "bad signature",
            Refusal::Expired => "expired",
            Refusal::Revoked => "revoked",
            Refusal::OutOfBounds => "out of bounds",
            Refusal::NotYours => "not yours",
        })
    }
}

impl std::error::Error for Refusal {}

/// A room or user id, as tokens and URLs carry them.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b"_~-".contains(&b))
}

fn sign(secret: &[u8], label: &str, fields: &[&str]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac takes a key of any length");
    mac.update(label.as_bytes());
    for f in fields {
        mac.update(&[0]);
        mac.update(f.as_bytes());
    }
    mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// Compare without leaking where the first difference is.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A checked grant: who, where, what, until when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub room: String,
    pub user: String,
    /// What the grant says, capped by any revocation that limits it.
    pub send: Send,
    pub issued_ms: u64,
    pub expires_ms: u64,
}

impl Grant {
    /// Sign a grant. Ids must pass [`valid_id`].
    pub fn mint(secret: &[u8], room: &str, user: &str, send: Send, now_ms: u64, ttl_ms: u64) -> String {
        assert!(valid_id(room) && valid_id(user), "room and user ids are [A-Za-z0-9_~-]");
        let (send, issued, expires) = (send.to_code(), now_ms.to_string(), (now_ms + ttl_ms).to_string());
        let sig = sign(secret, "call-auth grant v1", &[room, user, &send, &issued, &expires]);
        format!("g1.{room}.{user}.{send}.{issued}.{expires}.{sig}")
    }

    /// Check a grant's signature and shape — not the clock, nor revocations;
    /// [`Gate`] does those.
    pub fn verify(secret: &[u8], token: &str) -> Result<Grant, Refusal> {
        let parts: Vec<&str> = token.split('.').collect();
        let ["g1", room, user, send, issued, expires, sig] = parts[..] else { return Err(Refusal::Malformed) };
        if !valid_id(room) || !valid_id(user) {
            return Err(Refusal::Malformed);
        }
        let parsed = (Send::parse(send), issued.parse::<u64>().ok(), expires.parse::<u64>().ok());
        let (Some(send_v), Some(issued_ms), Some(expires_ms)) = parsed else { return Err(Refusal::Malformed) };
        // Signature before anything else is judged, so a forger learns nothing.
        if !same(&sign(secret, "call-auth grant v1", &[room, user, send, issued, expires]), sig) {
            return Err(Refusal::BadSignature);
        }
        Ok(Grant { room: room.into(), user: user.into(), send: send_v, issued_ms, expires_ms })
    }

    pub fn may_send(&self, media: Media, now_ms: u64) -> bool {
        now_ms < self.expires_ms && self.send.allows(media)
    }
}

/// What a revocation does to the grants it covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Void them: the holder is disconnected and refused.
    Kick,
    /// Cap them to sending this.
    Limit(Send),
}

/// A checked revocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    /// `None` for every room.
    pub room: Option<String>,
    pub user: String,
    pub action: Action,
    /// Grants issued at or before this are covered.
    pub at_ms: u64,
}

impl Revocation {
    /// Sign one. `room` `None` covers every room the relay hosts — a ban.
    pub fn mint(secret: &[u8], room: Option<&str>, user: &str, action: Action, now_ms: u64) -> String {
        assert!(room.is_none_or(valid_id) && valid_id(user), "room and user ids are [A-Za-z0-9_~-]");
        let room = room.unwrap_or("*");
        let action = match action {
            Action::Kick => "kick".to_string(),
            Action::Limit(s) => format!("send:{}", s.to_code()),
        };
        let at = now_ms.to_string();
        let sig = sign(secret, "call-auth revocation v1", &[room, user, &action, &at]);
        format!("r1.{room}.{user}.{action}.{at}.{sig}")
    }

    pub fn verify(secret: &[u8], token: &str) -> Result<Revocation, Refusal> {
        let parts: Vec<&str> = token.split('.').collect();
        let ["r1", room, user, action, at, sig] = parts[..] else { return Err(Refusal::Malformed) };
        if !(room == "*" || valid_id(room)) || !valid_id(user) {
            return Err(Refusal::Malformed);
        }
        let parsed_action = match action {
            "kick" => Some(Action::Kick),
            _ => action.strip_prefix("send:").and_then(Send::parse).map(Action::Limit),
        };
        let (Some(parsed_action), Some(at_ms)) = (parsed_action, at.parse::<u64>().ok()) else {
            return Err(Refusal::Malformed);
        };
        if !same(&sign(secret, "call-auth revocation v1", &[room, user, action, at]), sig) {
            return Err(Refusal::BadSignature);
        }
        Ok(Revocation { room: (room != "*").then(|| room.to_string()), user: user.into(), action: parsed_action, at_ms })
    }

    /// Whether `grant` is one this revokes.
    pub fn covers(&self, grant: &Grant) -> bool {
        grant.user == self.user
            && self.room.as_deref().is_none_or(|r| r == grant.room)
            && grant.issued_ms <= self.at_ms
    }
}

/// What applying a revocation did to one grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Untouched,
    Kicked,
    /// Its holder may now send only this.
    Limited(Send),
}

/// The relay's side: checks grants and renewals, and keeps the revocations
/// it has been given for as long as any grant they cover could live.
pub struct Gate {
    secret: Vec<u8>,
    max_ttl_ms: u64,
    revocations: Vec<Revocation>,
}

impl Gate {
    /// `max_ttl_ms` is the longest grant accepted, and so how long a
    /// revocation must be remembered.
    pub fn new(secret: Vec<u8>, max_ttl_ms: u64) -> Gate {
        Gate { secret, max_ttl_ms, revocations: Vec::new() }
    }

    pub fn max_ttl_ms(&self) -> u64 {
        self.max_ttl_ms
    }

    /// A grant presented on connecting to `room`.
    pub fn admit(&self, room: &str, token: &str, now_ms: u64) -> Result<Grant, Refusal> {
        let mut grant = Grant::verify(&self.secret, token)?;
        if grant.room != room {
            // Signed for another room: as good as a forgery here.
            return Err(Refusal::BadSignature);
        }
        if grant.expires_ms.saturating_sub(grant.issued_ms) > self.max_ttl_ms
            || grant.issued_ms > now_ms + CLOCK_SKEW_MS
        {
            return Err(Refusal::OutOfBounds);
        }
        if now_ms >= grant.expires_ms {
            return Err(Refusal::Expired);
        }
        for r in &self.revocations {
            if Gate::apply(r, &mut grant) == Outcome::Kicked {
                return Err(Refusal::Revoked);
            }
        }
        Ok(grant)
    }

    /// A fresh grant for a connection that holds `current`: same room, same
    /// user.
    pub fn renew(&self, current: &Grant, token: &str, now_ms: u64) -> Result<Grant, Refusal> {
        let next = self.admit(&current.room, token, now_ms)?;
        if next.user != current.user {
            return Err(Refusal::NotYours);
        }
        Ok(next)
    }

    /// Take a revocation. Returns it checked, for the relay to apply to who is
    /// connected (see [`Gate::apply`]).
    pub fn revoke(&mut self, token: &str, now_ms: u64) -> Result<Revocation, Refusal> {
        let r = Revocation::verify(&self.secret, token)?;
        // Nothing it could cover is still alive: no grant lives longer than
        // max_ttl, and it covers only grants issued before `at`.
        if r.at_ms + self.max_ttl_ms + CLOCK_SKEW_MS <= now_ms {
            return Err(Refusal::Expired);
        }
        if r.at_ms > now_ms + CLOCK_SKEW_MS {
            return Err(Refusal::OutOfBounds);
        }
        let max_ttl = self.max_ttl_ms;
        self.revocations.retain(|old| old.at_ms + max_ttl + CLOCK_SKEW_MS > now_ms);
        self.revocations.push(r.clone());
        Ok(r)
    }

    /// Apply a revocation to a connected client's grant.
    pub fn apply(r: &Revocation, grant: &mut Grant) -> Outcome {
        if !r.covers(grant) {
            return Outcome::Untouched;
        }
        match r.action {
            Action::Kick => Outcome::Kicked,
            Action::Limit(s) => {
                grant.send = grant.send.cap(s);
                Outcome::Limited(grant.send)
            }
        }
    }

    /// Revocations held now — for logs and tests.
    pub fn held(&self) -> usize {
        self.revocations.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"room secret";
    const MIN: u64 = 60_000;

    fn gate() -> Gate {
        Gate::new(SECRET.to_vec(), 10 * MIN)
    }

    #[test]
    fn send_codes_round_trip() {
        for s in [Send::ALL, Send::NONE, Send { audio: true, video: false, screen: true }] {
            assert_eq!(Send::parse(&s.to_code()), Some(s));
        }
        assert_eq!(Send::parse(""), None);
        assert_eq!(Send::parse("aa"), None);
        assert_eq!(Send::parse("x"), None);
    }

    #[test]
    fn a_grant_admits_its_holder_to_its_room_only() {
        let t = Grant::mint(SECRET, "porch", "alice", Send::ALL, 1_000, 2 * MIN);
        let g = gate().admit("porch", &t, 2_000).unwrap();
        assert_eq!((g.user.as_str(), g.send), ("alice", Send::ALL));
        assert_eq!(gate().admit("attic", &t, 2_000), Err(Refusal::BadSignature));
    }

    #[test]
    fn forged_altered_and_foreign_grants_are_refused() {
        let t = Grant::mint(SECRET, "porch", "alice", Send::NONE, 1_000, 2 * MIN);
        // Promoting yourself to a sender breaks the signature.
        let promoted = t.replacen(".-.", ".avs.", 1);
        assert_eq!(gate().admit("porch", &promoted, 2_000), Err(Refusal::BadSignature));
        let other = Grant::mint(b"another secret", "porch", "alice", Send::ALL, 1_000, MIN);
        assert_eq!(gate().admit("porch", &other, 2_000), Err(Refusal::BadSignature));
        assert_eq!(gate().admit("porch", "g1.porch", 2_000), Err(Refusal::Malformed));
        // A revocation is not a grant, whatever it is signed with.
        let r = Revocation::mint(SECRET, Some("porch"), "alice", Action::Kick, 1_000);
        assert_eq!(gate().admit("porch", &r, 2_000), Err(Refusal::Malformed));
    }

    #[test]
    fn grants_expire_and_cannot_outlive_the_relays_limit() {
        let t = Grant::mint(SECRET, "porch", "alice", Send::ALL, 0, MIN);
        assert_eq!(gate().admit("porch", &t, MIN), Err(Refusal::Expired));
        let long = Grant::mint(SECRET, "porch", "alice", Send::ALL, 0, 60 * MIN);
        assert_eq!(gate().admit("porch", &long, 1), Err(Refusal::OutOfBounds));
        let future = Grant::mint(SECRET, "porch", "alice", Send::ALL, 10 * MIN, MIN);
        assert_eq!(gate().admit("porch", &future, 0), Err(Refusal::OutOfBounds));
    }

    #[test]
    fn a_grant_only_lets_its_holder_send_what_it_says_while_it_lasts() {
        let t = Grant::mint(SECRET, "porch", "alice", Send::parse("a").unwrap(), 0, MIN);
        let g = gate().admit("porch", &t, 1).unwrap();
        assert!(g.may_send(Media::Audio, 1));
        assert!(!g.may_send(Media::Video, 1));
        assert!(!g.may_send(Media::Audio, MIN), "not once it has expired");
    }

    #[test]
    fn a_kick_voids_earlier_grants_and_spares_later_ones() {
        let mut gate = gate();
        let old = Grant::mint(SECRET, "porch", "alice", Send::ALL, 1_000, 5 * MIN);
        let mut held = gate.admit("porch", &old, 1_500).unwrap();
        let r = gate.revoke(&Revocation::mint(SECRET, Some("porch"), "alice", Action::Kick, 2_000), 2_000).unwrap();
        assert_eq!(Gate::apply(&r, &mut held), Outcome::Kicked);
        assert_eq!(gate.admit("porch", &old, 3_000), Err(Refusal::Revoked), "no coming back on the old grant");
        let new = Grant::mint(SECRET, "porch", "alice", Send::ALL, 2_001, 5 * MIN);
        assert!(gate.admit("porch", &new, 3_000).is_ok(), "a grant issued after lets them back");
        let bob = Grant::mint(SECRET, "porch", "bob", Send::ALL, 1_000, 5 * MIN);
        assert!(gate.admit("porch", &bob, 3_000).is_ok(), "and nobody else is touched");
    }

    #[test]
    fn a_ban_covers_every_room() {
        let mut gate = gate();
        gate.revoke(&Revocation::mint(SECRET, None, "alice", Action::Kick, 2_000), 2_000).unwrap();
        for room in ["porch", "attic"] {
            let t = Grant::mint(SECRET, room, "alice", Send::ALL, 1_000, 5 * MIN);
            assert_eq!(gate.admit(room, &t, 3_000), Err(Refusal::Revoked));
        }
    }

    #[test]
    fn a_limit_caps_what_earlier_grants_may_send() {
        let mut gate = gate();
        let old = Grant::mint(SECRET, "porch", "alice", Send::ALL, 1_000, 5 * MIN);
        let mut held = gate.admit("porch", &old, 1_500).unwrap();
        let listen = Revocation::mint(SECRET, Some("porch"), "alice", Action::Limit(Send::NONE), 2_000);
        let r = gate.revoke(&listen, 2_000).unwrap();
        assert_eq!(Gate::apply(&r, &mut held), Outcome::Limited(Send::NONE));
        assert!(!held.may_send(Media::Audio, 2_500));
        assert_eq!(gate.admit("porch", &old, 3_000).unwrap().send, Send::NONE, "and on reconnecting");
    }

    #[test]
    fn renewal_is_for_the_same_person_and_room() {
        let gate = gate();
        let held = gate.admit("porch", &Grant::mint(SECRET, "porch", "alice", Send::ALL, 0, MIN), 1).unwrap();
        let next = Grant::mint(SECRET, "porch", "alice", Send::ALL, 30_000, MIN);
        assert_eq!(gate.renew(&held, &next, 30_000).unwrap().expires_ms, 90_000);
        let bobs = Grant::mint(SECRET, "porch", "bob", Send::ALL, 30_000, MIN);
        assert_eq!(gate.renew(&held, &bobs, 30_000), Err(Refusal::NotYours));
        let attic = Grant::mint(SECRET, "attic", "alice", Send::ALL, 30_000, MIN);
        assert_eq!(gate.renew(&held, &attic, 30_000), Err(Refusal::BadSignature));
    }

    #[test]
    fn revocations_are_forgotten_once_nothing_they_cover_can_be_alive() {
        let mut gate = gate();
        gate.revoke(&Revocation::mint(SECRET, Some("porch"), "alice", Action::Kick, 0), 0).unwrap();
        assert_eq!(gate.held(), 1);
        let later = 10 * MIN + CLOCK_SKEW_MS + 1;
        gate.revoke(&Revocation::mint(SECRET, Some("porch"), "bob", Action::Kick, later), later).unwrap();
        assert_eq!(gate.held(), 1, "alice's has aged out");
        let stale = Revocation::mint(SECRET, Some("porch"), "carol", Action::Kick, 0);
        assert_eq!(gate.revoke(&stale, later), Err(Refusal::Expired), "and a stale one is not taken");
    }
}
