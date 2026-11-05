//! What the relay adds to the datagrams it forwards, and what it says over
//! the control channel.
//!
//! The relay gives each client a number when it connects and tells it which
//! (`you are #N`). It forwards every datagram to everyone else with the
//! sender's number in front, and every control message prefixed the same way
//! (`#N: …`); when someone disconnects it tells the rest (`#N left`).
//!
//! It also tells a room when someone arrives (`#N joined`), so the others can
//! tell the newcomer whatever state they announce — see [`Announce`].
//!
//! Clients use the forwarded control messages to ask each other for
//! keyframes: [`KeyRequest`] goes out as `key #T/track`, and arrives at
//! everyone as `#S: key #T/track` — the sender named `T` answers. And to say
//! how much of each other they are losing, once a second ([`LossReport`],
//! `rx 3:12 5:0`), which each sender reads its own entry from to set its
//! bitrate.
//!
//! # Authorisation
//!
//! A relay that checks who may send (see `call-auth`) takes a grant in the
//! connect URL ([`Connect`]: `?room=R&grant=…`) and refuses the connection —
//! 401 with none, 403 with a bad one — before any session exists. Once in:
//!
//! - it names everyone by the grant's user (`#N is alice`), and says when our
//!   grant runs out (`grant expires in 90 s`);
//! - the client renews before then ([`ToRelay::Renew`]: `renew <grant>`); a
//!   renewal that does not check out is answered `refused: <reason>`, and the
//!   old grant runs out as it would have;
//! - an expired grant stops the client's datagrams being forwarded at once,
//!   and the connection is closed after a grace;
//! - a revocation arriving for a client ends its session (`revoked`) or caps
//!   what it may send (`you may send a`), datagrams outside it dropped.
//!
//! An issuer delivers a revocation by connecting with it (`?revoke=…`); the
//! relay answers `revocation applied` and closes.
//!
//! # Throttling
//!
//! A relay started with throttling on watches what each client loses on the
//! way down — the loss it reports for everyone, less what the relay itself
//! saw go missing on the way in — and holds back video layers, then whole
//! cameras, for a client whose download cannot take everything
//! ([`FromRelay::Throttled`]: `download limited: 2`).
//!
//! # Round trips
//!
//! A client measures its latency to the relay with [`ToRelay::Ping`]
//! (`ping <n>`), which the relay answers at once, to that client only, with
//! [`FromRelay::Pong`] carrying the same `n` — typically the client's clock
//! when it sent it.

/// The sender's number in front of a relayed datagram.
pub const TAG: usize = 4;

/// A datagram as the relay forwards it: `sender` in front.
pub fn tag(sender: u32, datagram: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(TAG + datagram.len());
    out.extend_from_slice(&sender.to_be_bytes());
    out.extend_from_slice(datagram);
    out
}

/// Who sent a relayed datagram, and what they sent.
pub fn untag(bytes: &[u8]) -> Option<(u32, &[u8])> {
    if bytes.len() <= TAG {
        return None;
    }
    let (id, rest) = bytes.split_at(TAG);
    Some((u32::from_be_bytes([id[0], id[1], id[2], id[3]]), rest))
}

/// A control message from the relay, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FromRelay {
    /// Our number in this room.
    You(u32),
    /// Who number `id` is, by their grant.
    Named { id: u32, user: String },
    /// Our grant runs out in this many seconds; renew before then.
    Expires { secs: u64 },
    /// What we may send now, as `call-auth` writes it (`av`, `-` for nothing).
    MaySend(String),
    /// Our grant was revoked; the session is ending.
    Revoked,
    /// A renewal was not accepted, and why.
    Refused(String),
    /// To an issuer: its revocation is in force.
    Applied,
    /// The answer to our `ping <n>`.
    Pong(u64),
    /// Someone connected to our room.
    Joined(u32),
    /// Someone disconnected.
    Left(u32),
    /// Another client's control message, passed on.
    Said { from: u32, text: String },
    /// A relay that throttles (see `call-relay`) is holding back this much of
    /// what it forwards to us, our download being unable to take it all — 0
    /// for nothing held back. See `call_rate::Throttle` for the levels.
    Throttled(u8),
    /// Anything else — shown, not acted on.
    Other(String),
}

impl FromRelay {
    pub fn parse(text: &str) -> FromRelay {
        let number = |s: &str| s.parse::<u32>().ok();
        if let Some(id) = text.strip_prefix("you are #").and_then(number) {
            return FromRelay::You(id);
        }
        if let Some(secs) = text.strip_prefix("grant expires in ").and_then(|t| t.strip_suffix(" s")) {
            if let Ok(secs) = secs.parse() {
                return FromRelay::Expires { secs };
            }
        }
        if let Some(n) = text.strip_prefix("pong ").and_then(|n| n.parse().ok()) {
            return FromRelay::Pong(n);
        }
        if let Some(code) = text.strip_prefix("you may send ") {
            return FromRelay::MaySend(code.to_string());
        }
        if let Some(reason) = text.strip_prefix("refused: ") {
            return FromRelay::Refused(reason.to_string());
        }
        if let Some(level) = text.strip_prefix("download limited: ").and_then(|l| l.parse().ok()) {
            return FromRelay::Throttled(level);
        }
        match text {
            "revoked" => return FromRelay::Revoked,
            "revocation applied" => return FromRelay::Applied,
            _ => {}
        }
        if let Some(rest) = text.strip_prefix('#') {
            if let Some(id) = rest.strip_suffix(" left").and_then(number) {
                return FromRelay::Left(id);
            }
            if let Some(id) = rest.strip_suffix(" joined").and_then(number) {
                return FromRelay::Joined(id);
            }
            if let Some((id, user)) = rest.split_once(" is ") {
                if let (Some(id), false) = (number(id), user.contains(' ')) {
                    return FromRelay::Named { id, user: user.to_string() };
                }
            }
            if let Some((id, said)) = rest.split_once(": ") {
                if let Some(from) = number(id) {
                    return FromRelay::Said { from, text: said.to_string() };
                }
            }
        }
        FromRelay::Other(text.to_string())
    }

    /// As the relay sends it.
    pub fn to_text(&self) -> String {
        match self {
            FromRelay::You(id) => format!("you are #{id}"),
            FromRelay::Named { id, user } => format!("#{id} is {user}"),
            FromRelay::Expires { secs } => format!("grant expires in {secs} s"),
            FromRelay::MaySend(code) => format!("you may send {code}"),
            FromRelay::Revoked => "revoked".to_string(),
            FromRelay::Refused(reason) => format!("refused: {reason}"),
            FromRelay::Applied => "revocation applied".to_string(),
            FromRelay::Pong(n) => format!("pong {n}"),
            FromRelay::Left(id) => format!("#{id} left"),
            FromRelay::Joined(id) => format!("#{id} joined"),
            FromRelay::Said { from, text } => format!("#{from}: {text}"),
            FromRelay::Throttled(level) => format!("download limited: {level}"),
            FromRelay::Other(text) => text.clone(),
        }
    }
}

/// A control message from a client to the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToRelay {
    /// A fresh grant for this connection; see `call-auth`.
    Renew(String),
    /// Answer with `pong <n>`, to measure the round trip.
    Ping(u64),
    /// Anything else, for the relay to pass on to the room.
    Say(String),
}

impl ToRelay {
    pub fn parse(text: &str) -> ToRelay {
        if let Some(grant) = text.strip_prefix("renew ") {
            return ToRelay::Renew(grant.to_string());
        }
        if let Some(n) = text.strip_prefix("ping ").and_then(|n| n.parse().ok()) {
            return ToRelay::Ping(n);
        }
        ToRelay::Say(text.to_string())
    }

    pub fn to_text(&self) -> String {
        match self {
            ToRelay::Renew(grant) => format!("renew {grant}"),
            ToRelay::Ping(n) => format!("ping {n}"),
            ToRelay::Say(text) => text.clone(),
        }
    }
}

/// What a client puts in its connect URL's query.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Connect {
    /// Which room. Empty for the relay's one room when it has no rooms.
    pub room: String,
    /// A grant, for a relay that checks them.
    pub grant: Option<String>,
    /// A revocation, from an issuer; see the module docs.
    pub revoke: Option<String>,
}

impl Connect {
    /// `base` with this in its query — after any query `base` already has.
    pub fn url(&self, base: &str) -> String {
        let mut pairs: Vec<String> = Vec::new();
        if !self.room.is_empty() {
            pairs.push(format!("room={}", self.room));
        }
        if let Some(g) = &self.grant {
            pairs.push(format!("grant={g}"));
        }
        if let Some(r) = &self.revoke {
            pairs.push(format!("revoke={r}"));
        }
        if pairs.is_empty() {
            return base.to_string();
        }
        let joiner = if base.contains('?') { '&' } else { '?' };
        format!("{base}{joiner}{}", pairs.join("&"))
    }

    /// Read from a connect URL. Tokens and ids are URL-safe as written, so
    /// nothing is decoded; anything that needed decoding is not one of ours.
    pub fn parse(url: &str) -> Connect {
        let mut c = Connect::default();
        let query = url.split_once('?').map(|(_, q)| q).unwrap_or("");
        let query = query.split('#').next().unwrap_or("");
        for pair in query.split('&') {
            match pair.split_once('=') {
                Some(("room", v)) => c.room = v.to_string(),
                Some(("grant", v)) if !v.is_empty() => c.grant = Some(v.to_string()),
                Some(("revoke", v)) if !v.is_empty() => c.revoke = Some(v.to_string()),
                _ => {}
            }
        }
        c
    }
}

/// What a client says about itself to the room, passed on by the relay like
/// any control message (`#N: mic off`). Said when it changes, and again
/// whenever someone joins, so a newcomer learns it without the relay keeping
/// anyone's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Announce {
    /// Whether the microphone is on.
    Mic(bool),
    /// Whether we are talking, by the sender's own voice detection — the
    /// one place that knows speech from a keyboard. Plaintext to the relay,
    /// which can already tell from when our audio packets come.
    Speaking(bool),
}

impl Announce {
    pub fn to_text(self) -> String {
        match self {
            Announce::Mic(on) => format!("mic {}", if on { "on" } else { "off" }),
            Announce::Speaking(on) => format!("speaking {}", if on { "on" } else { "off" }),
        }
    }

    pub fn parse(text: &str) -> Option<Announce> {
        match text {
            "mic on" => Some(Announce::Mic(true)),
            "mic off" => Some(Announce::Mic(false)),
            "speaking on" => Some(Announce::Speaking(true)),
            "speaking off" => Some(Announce::Speaking(false)),
            _ => None,
        }
    }
}

/// "Send a keyframe": a receiver lost part of `target`'s `track` and cannot
/// decode it again until one comes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyRequest {
    pub target: u32,
    pub track: u8,
}

impl KeyRequest {
    pub fn to_text(self) -> String {
        format!("key #{}/{}", self.target, self.track)
    }

    pub fn parse(text: &str) -> Option<KeyRequest> {
        let (id, track) = text.strip_prefix("key #")?.split_once('/')?;
        Some(KeyRequest { target: id.parse().ok()?, track: track.parse().ok()? })
    }
}

/// What a receiver lost of each sender's audio in the last second, for their
/// bitrate control (see `call-rate`): `rx 3:12 5:0`, sender number and loss in
/// thousandths. One message for everyone it hears, so a room of `n` costs `n`
/// messages a second, not `n²`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LossReport(pub Vec<(u32, u16)>);

impl LossReport {
    pub fn to_text(&self) -> String {
        let mut out = String::from("rx");
        for (id, permille) in &self.0 {
            out.push_str(&format!(" {id}:{permille}"));
        }
        out
    }

    pub fn parse(text: &str) -> Option<LossReport> {
        let rest = text.strip_prefix("rx")?;
        let entries = rest
            .split_whitespace()
            .map(|e| {
                let (id, permille) = e.split_once(':')?;
                Some((id.parse().ok()?, permille.parse::<u16>().ok()?.min(1000)))
            })
            .collect::<Option<Vec<_>>>()?;
        (rest.is_empty() || rest.starts_with(' ')).then_some(LossReport(entries))
    }

    /// What it says about `sender`'s stream, as a fraction.
    pub fn loss_of(&self, sender: u32) -> Option<f64> {
        self.0.iter().find(|(id, _)| *id == sender).map(|&(_, p)| p as f64 / 1000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loss_reports_round_trip() {
        let r = LossReport(vec![(3, 12), (5, 0), (70_000, 1000)]);
        assert_eq!(r.to_text(), "rx 3:12 5:0 70000:1000");
        assert_eq!(LossReport::parse(&r.to_text()), Some(r.clone()));
        assert_eq!(r.loss_of(3), Some(0.012));
        assert_eq!(r.loss_of(4), None);
        assert_eq!(LossReport::parse("rx"), Some(LossReport(vec![])));
        assert_eq!(LossReport::parse("rx 3:2000"), Some(LossReport(vec![(3, 1000)])), "capped at all of it");
        assert_eq!(LossReport::parse("rx 3"), None);
        assert_eq!(LossReport::parse("rxx 3:1"), None);
        assert_eq!(LossReport::parse("key #1/0"), None);
    }

    #[test]
    fn tags_round_trip() {
        assert_eq!(untag(&tag(7, &[1, 2])), Some((7, &[1u8, 2][..])));
        assert_eq!(untag(&[0, 0, 0, 7]), None, "a tag with nothing behind it");
    }

    #[test]
    fn control_messages_round_trip() {
        for m in [
            FromRelay::You(3),
            FromRelay::Left(12),
            FromRelay::Said { from: 4, text: "key #5/1".into() },
            FromRelay::Named { id: 2, user: "alice".into() },
            FromRelay::Expires { secs: 90 },
            FromRelay::MaySend("a".into()),
            FromRelay::Revoked,
            FromRelay::Refused("expired".into()),
            FromRelay::Applied,
            FromRelay::Pong(123),
            FromRelay::Joined(5),
            FromRelay::Throttled(2),
            FromRelay::Other("hello".into()),
        ] {
            assert_eq!(FromRelay::parse(&m.to_text()), m);
        }
    }

    #[test]
    fn announcements_ride_inside_a_forwarded_message() {
        let arrived = FromRelay::Said { from: 3, text: Announce::Mic(false).to_text() }.to_text();
        let FromRelay::Said { from, text } = FromRelay::parse(&arrived) else { panic!("{arrived}") };
        assert_eq!((from, Announce::parse(&text)), (3, Some(Announce::Mic(false))));
        assert_eq!(Announce::parse(&Announce::Mic(true).to_text()), Some(Announce::Mic(true)));
        assert_eq!(Announce::parse("mic maybe"), None);
        assert_eq!(Announce::parse(&Announce::Speaking(true).to_text()), Some(Announce::Speaking(true)));
        assert_eq!(Announce::parse(&Announce::Speaking(false).to_text()), Some(Announce::Speaking(false)));
    }

    #[test]
    fn renewals_are_told_apart_from_chatter() {
        assert_eq!(ToRelay::parse("renew g1.x"), ToRelay::Renew("g1.x".into()));
        assert_eq!(ToRelay::parse("key #5/1"), ToRelay::Say("key #5/1".into()));
        assert_eq!(ToRelay::parse(&ToRelay::Renew("g".into()).to_text()), ToRelay::Renew("g".into()));
        assert_eq!(ToRelay::parse("ping 42"), ToRelay::Ping(42));
    }

    #[test]
    fn connect_urls_round_trip() {
        let c = Connect { room: "porch".into(), grant: Some("g1.a.b".into()), revoke: None };
        let url = c.url("https://relay:4433/");
        assert_eq!(url, "https://relay:4433/?room=porch&grant=g1.a.b");
        assert_eq!(Connect::parse(&url), c);
        assert_eq!(c.url("https://relay:4433/?x=1"), "https://relay:4433/?x=1&room=porch&grant=g1.a.b");
        assert_eq!(Connect::default().url("https://r/"), "https://r/");
        assert_eq!(Connect::parse("https://r/?revoke=r1.z"), Connect { revoke: Some("r1.z".into()), ..Default::default() });
    }

    #[test]
    fn key_requests_ride_inside_a_forwarded_message() {
        let sent = KeyRequest { target: 5, track: 1 }.to_text();
        let arrived = FromRelay::Said { from: 3, text: sent }.to_text();
        let FromRelay::Said { from, text } = FromRelay::parse(&arrived) else { panic!("{arrived}") };
        assert_eq!(from, 3);
        assert_eq!(KeyRequest::parse(&text), Some(KeyRequest { target: 5, track: 1 }));
        assert_eq!(KeyRequest::parse("key #x/1"), None);
    }
}
