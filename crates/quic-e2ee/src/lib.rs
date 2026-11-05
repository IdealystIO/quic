//! End-to-end encryption for a call's media, so the relay forwards what it
//! cannot read.
//!
//! Every client in a room holds the same [`RoomKey`]. Each one seals its
//! datagrams with [SFrame](sframe) under a key of its own, derived from the
//! room key and a [`Kid`] it picks at random when it joins; receivers derive
//! the same key from the KID in each datagram's header. The relay holds no
//! key: it reads the clear call-proto header it needs (kind and track, for
//! `call-auth`) and forwards the rest.
//!
//! ```text
//! sealed: [call-proto header, SEALED set][SFrame header][ciphertext][tag: 10]
//! ```
//!
//! The call-proto header stays in the clear and is authenticated as SFrame
//! metadata, so the relay can route on it but not change it. Its kind byte
//! carries [`call_proto::SEALED`], so a client without a key knows to leave
//! it alone, and one with a key can tell someone not encrypting
//! ([`Refusal::NotSealed`]) from someone with another key. Audio is sealed
//! per packet; video per fragment, so each datagram stands alone and a lost
//! piece costs only itself. [`OVERHEAD`] is the most sealing adds.
//!
//! # What it protects, and what it does not
//!
//! - **The relay** — or anyone who gets into it — sees who is talking, when,
//!   and how much (sizes and timing), but not what is said or shown. It
//!   cannot alter media, pass one person's off as another's ([`Opener`] binds
//!   each KID to the relay number it first arrived from), or replay it (a
//!   64-datagram window per KID).
//! - **Everyone holding the room key** can read everything, and could forge
//!   media as anyone. That is the nature of a shared key.
//! - **Control messages** (names, mic on/off, keyframe requests) are not
//!   media and are not sealed.
//! - **Getting the key to people** is not this crate's business. Whoever
//!   hands it out must not be the relay's operator, or this is only transport
//!   encryption with extra steps. [`Kid`] carries an epoch so keys can later
//!   be rotated — on someone leaving, say — without a gap.
//!
//! # Why SFrame with these parameters
//!
//! SFrame is the IETF's format for exactly this: media end-to-end encrypted
//! through a forwarding server. Its suite 0x0001 — AES-CTR then HMAC-SHA256,
//! cut to an 80-bit tag — exists for small media frames. Each KID's key and
//! salt are distinct, so two senders never share a (key, nonce) pair however
//! their counters line up; the one way to collide is two senders drawing the
//! same 32-bit id in the same epoch, about one in 10⁸ for a room of ten.

pub mod sframe;

use std::collections::HashMap;

use call_proto::{audio, video, KIND_AUDIO, KIND_VIDEO, SEALED};
use sframe::{Header, Keys};

/// The most sealing adds to a datagram: a config byte, a 5-byte KID, an
/// 8-byte counter and the tag. Typically 17: a 4-byte KID, a 2-byte counter.
pub const OVERHEAD: usize = 1 + 5 + 8 + sframe::NT;

/// The secret everyone in a room shares. Any text works — the key schedule
/// takes any length — but a [generated](RoomKey::generate) one is 128 random
/// bits; a phrase people can guess is a phrase the relay can try offline.
#[derive(Clone, PartialEq, Eq)]
pub struct RoomKey(Vec<u8>);

impl std::fmt::Debug for RoomKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RoomKey(…)")
    }
}

impl RoomKey {
    /// The key as typed or pasted, surrounding whitespace aside. `None` for
    /// nothing.
    pub fn from_text(text: &str) -> Option<RoomKey> {
        let text = text.trim();
        (!text.is_empty()).then(|| RoomKey(text.as_bytes().to_vec()))
    }

    /// A fresh key from 16 random bytes, as 22 URL-safe characters — fit for
    /// a link's `#fragment`, which browsers never send to the server.
    pub fn generate(random: [u8; 16]) -> (RoomKey, String) {
        let text = base64url(&random);
        (RoomKey(text.as_bytes().to_vec()), text)
    }
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, &b)| n | (b as u32) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// Which key a datagram was sealed under: the room key's epoch, and the
/// sender's own random id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Kid {
    pub epoch: u8,
    pub sender: u32,
}

impl Kid {
    fn to_u64(self) -> u64 {
        (self.epoch as u64) << 32 | self.sender as u64
    }

    fn from_u64(kid: u64) -> Option<Kid> {
        (kid >> 40 == 0).then_some(Kid { epoch: (kid >> 32) as u8, sender: kid as u32 })
    }
}

/// Where a datagram's clear header ends, by its kind byte.
fn clear_header(datagram: &[u8]) -> Option<usize> {
    match *datagram.first()? & !SEALED {
        KIND_AUDIO => Some(audio::HEADER),
        KIND_VIDEO => Some(video::HEADER),
        _ => None,
    }
    .filter(|&n| datagram.len() >= n)
}

/// One client's outgoing media, sealed. One per call, shared by its audio and
/// video, so they count on the same counter.
pub struct Sealer {
    kid: u64,
    keys: Keys,
    ctr: u64,
}

impl Sealer {
    /// Seal under `key` at `epoch`, as `sender` — a random id this client
    /// draws for the call and never reuses with this key.
    pub fn new(key: &RoomKey, epoch: u8, sender: u32) -> Sealer {
        let kid = Kid { epoch, sender }.to_u64();
        Sealer { kid, keys: Keys::derive(kid, &key.0), ctr: 0 }
    }

    /// A call-proto datagram, sealed. `None` for one that is not audio or
    /// video.
    pub fn seal(&mut self, datagram: &[u8]) -> Option<Vec<u8>> {
        if call_proto::sealed(datagram) {
            return None;
        }
        let at = clear_header(datagram)?;
        let mut out = Vec::with_capacity(datagram.len() + OVERHEAD);
        out.extend_from_slice(&datagram[..at]);
        out[0] |= SEALED;
        let sealed = sframe::encrypt(&self.keys, Header { kid: self.kid, ctr: self.ctr }, &out, &datagram[at..]);
        // 2⁶⁴ datagrams is not a call anyone will make.
        self.ctr += 1;
        out.extend_from_slice(&sealed);
        Some(out)
    }
}

/// Why a datagram was not opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Media in the clear: a sender with no key.
    NotSealed,
    /// Not media, or cut short.
    Malformed,
    /// Sealed under an epoch we hold no key for.
    UnknownEpoch,
    /// The tag does not check out: a different room key, or tampering.
    Forged,
    /// A KID first seen from one relay number, now arriving from another.
    WrongSender,
    /// Already opened, or too far behind to tell.
    Replayed,
}

/// The replay window: how far behind the newest counter a datagram may still
/// arrive. Datagrams reorder by a few, not by dozens.
const WINDOW: u64 = 64;
/// Senders remembered at once. A sender is only remembered once one of its
/// datagrams has opened, so only key holders can fill this.
const MAX_SENDERS: usize = 256;

struct Incoming {
    from: u32,
    keys: Keys,
    /// The newest counter opened, and which of the `WINDOW` below it have
    /// been (bit n: `top - n`).
    top: u64,
    seen: u64,
    /// When last used, on the opener's own clock, for eviction.
    used: u64,
}

impl Incoming {
    fn fresh(&self, ctr: u64) -> bool {
        ctr > self.top || (self.top - ctr < WINDOW && self.seen & 1 << (self.top - ctr) == 0)
    }

    fn mark(&mut self, ctr: u64) {
        if ctr > self.top {
            let shift = ctr - self.top;
            self.seen = if shift >= WINDOW { 0 } else { self.seen << shift };
            self.top = ctr;
        }
        self.seen |= 1 << (self.top - ctr);
    }
}

/// Everyone else's media, opened.
pub struct Opener {
    keys: HashMap<u8, RoomKey>,
    senders: HashMap<u64, Incoming>,
    clock: u64,
}

impl Opener {
    /// Open what was sealed under `key` at `epoch`.
    pub fn new(key: RoomKey, epoch: u8) -> Opener {
        Opener { keys: HashMap::from([(epoch, key)]), senders: HashMap::new(), clock: 0 }
    }

    /// Accept another epoch's key too — the next one, ahead of senders moving
    /// to it.
    pub fn add(&mut self, epoch: u8, key: RoomKey) {
        self.keys.insert(epoch, key);
    }

    /// Stop accepting an epoch, and forget its senders.
    pub fn remove(&mut self, epoch: u8) {
        self.keys.remove(&epoch);
        self.senders.retain(|&kid, _| Kid::from_u64(kid).is_some_and(|k| k.epoch != epoch));
    }

    /// Someone hung up: forget their KIDs.
    pub fn left(&mut self, from: u32) {
        self.senders.retain(|_, s| s.from != from);
    }

    /// A datagram the relay forwarded from relay number `from`, opened back
    /// into the call-proto datagram its sender sealed.
    pub fn open(&mut self, from: u32, datagram: &[u8]) -> Result<Vec<u8>, Refusal> {
        if !call_proto::sealed(datagram) {
            return Err(if call_proto::parse(datagram).is_some() { Refusal::NotSealed } else { Refusal::Malformed });
        }
        let at = clear_header(datagram).ok_or(Refusal::Malformed)?;
        let (clear, sealed) = datagram.split_at(at);
        let (header, len) = Header::decode(sealed).ok_or(Refusal::Malformed)?;
        let kid = Kid::from_u64(header.kid).ok_or(Refusal::Malformed)?;
        self.clock += 1;

        let pt = if let Some(known) = self.senders.get_mut(&header.kid) {
            if known.from != from {
                return Err(Refusal::WrongSender);
            }
            if !known.fresh(header.ctr) {
                return Err(Refusal::Replayed);
            }
            let pt = known.keys.open(header.ctr, &[&sealed[..len], clear], &sealed[len..]).ok_or(Refusal::Forged)?;
            known.mark(header.ctr);
            known.used = self.clock;
            pt
        } else {
            let key = self.keys.get(&kid.epoch).ok_or(Refusal::UnknownEpoch)?;
            let keys = Keys::derive(header.kid, &key.0);
            let pt = keys.open(header.ctr, &[&sealed[..len], clear], &sealed[len..]).ok_or(Refusal::Forged)?;
            if self.senders.len() >= MAX_SENDERS {
                if let Some(&oldest) = self.senders.iter().min_by_key(|(_, s)| s.used).map(|(k, _)| k) {
                    self.senders.remove(&oldest);
                }
            }
            let mut incoming = Incoming { from, keys, top: header.ctr, seen: 0, used: self.clock };
            incoming.mark(header.ctr);
            self.senders.insert(header.kid, incoming);
            pt
        };

        let mut out = Vec::with_capacity(clear.len() + pt.len());
        out.extend_from_slice(clear);
        out[0] &= !SEALED;
        out.extend_from_slice(&pt);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use call_proto::{Datagram, TRACK_MAIN, TRACK_SCREEN};

    fn key(text: &str) -> RoomKey {
        RoomKey::from_text(text).unwrap()
    }

    fn opus(seq: u32) -> Vec<u8> {
        audio::encode(TRACK_MAIN, seq, 48_000, seq * 20, &[seq as u8; 60])
    }

    #[test]
    fn audio_and_video_come_back_as_sent() {
        let mut alice = Sealer::new(&key("k"), 0, 0xdead_beef);
        let mut bob = Opener::new(key("k"), 0);
        let a = opus(7);
        let sealed = alice.seal(&a).unwrap();
        assert!(sealed.len() <= a.len() + OVERHEAD);
        assert_eq!(sealed.len(), a.len() + 15, "a 4-byte KID; a counter under 8 rides in the config byte");
        assert_eq!(bob.open(3, &sealed).unwrap(), a);

        for piece in video::fragment(TRACK_SCREEN, 9, 99, true, &[5; 3000], 1200 - OVERHEAD).unwrap() {
            let sealed = alice.seal(&piece).unwrap();
            assert!(sealed.len() <= 1200);
            let opened = bob.open(3, &sealed).unwrap();
            assert!(matches!(call_proto::parse(&opened), Some(Datagram::Video(f)) if f.track == TRACK_SCREEN));
            assert_eq!(opened, piece);
        }
    }

    #[test]
    fn the_relay_still_reads_what_it_needs() {
        let mut s = Sealer::new(&key("k"), 0, 1);
        let screen_audio = s.seal(&audio::encode(TRACK_SCREEN, 0, 48_000, 0, &[1; 60])).unwrap();
        assert_eq!(call_proto::media(&screen_audio), Some(call_proto::Media::Screen));
        let camera = s.seal(&video::fragment(TRACK_MAIN, 0, 0, true, &[1; 10], 1000).unwrap()[0]).unwrap();
        assert_eq!(call_proto::media(&camera), Some(call_proto::Media::Video));
    }

    #[test]
    fn the_media_is_not_in_the_clear() {
        let mut s = Sealer::new(&key("k"), 0, 1);
        let plain = audio::encode(TRACK_MAIN, 0, 48_000, 0, b"a secret said aloud, as opus");
        let sealed = s.seal(&plain).unwrap();
        assert_eq!(sealed[0], plain[0] | SEALED, "marked sealed");
        assert_eq!(sealed[1..audio::HEADER], plain[1..audio::HEADER], "the header is clear");
        assert_eq!(call_proto::parse(&sealed), None, "and not mistaken for plain media");
        assert!(!sealed.windows(6).any(|w| w == b"secret"), "the payload is not");
    }

    #[test]
    fn the_wrong_key_opens_nothing() {
        let mut alice = Sealer::new(&key("right"), 0, 1);
        let mut eve = Opener::new(key("wrong"), 0);
        assert_eq!(eve.open(1, &alice.seal(&opus(0)).unwrap()), Err(Refusal::Forged));
    }

    #[test]
    fn plaintext_is_refused() {
        // An unencrypted client in an encrypted room, or a relay injecting.
        let mut bob = Opener::new(key("k"), 0);
        assert_eq!(bob.open(1, &opus(0)), Err(Refusal::NotSealed));
        assert_eq!(bob.open(1, &[9, 9, 9]), Err(Refusal::Malformed));
        // Plain media with the flag forged on, by a relay that has no key.
        let mut fake = opus(0);
        fake[0] |= SEALED;
        assert!(bob.open(1, &fake).is_err());
        let mut alice = Sealer::new(&key("k"), 0, 1);
        assert_eq!(alice.seal(&fake), None, "nothing is sealed twice");
    }

    #[test]
    fn the_relay_cannot_change_the_header() {
        let mut alice = Sealer::new(&key("k"), 0, 1);
        let mut bob = Opener::new(key("k"), 0);
        let mut sealed = alice.seal(&opus(0)).unwrap();
        sealed[1] = TRACK_SCREEN;
        assert_eq!(bob.open(1, &sealed), Err(Refusal::Forged), "the track is authenticated");
        let mut sealed = alice.seal(&opus(1)).unwrap();
        sealed[0] = KIND_VIDEO | SEALED;
        assert!(bob.open(1, &sealed).is_err(), "so is the kind");
    }

    #[test]
    fn replays_are_refused_and_reordering_is_not() {
        let mut alice = Sealer::new(&key("k"), 0, 1);
        let mut bob = Opener::new(key("k"), 0);
        let sealed: Vec<Vec<u8>> = (0..100).map(|n| alice.seal(&opus(n)).unwrap()).collect();
        assert!(bob.open(1, &sealed[0]).is_ok());
        assert_eq!(bob.open(1, &sealed[0]), Err(Refusal::Replayed));
        assert!(bob.open(1, &sealed[3]).is_ok());
        assert!(bob.open(1, &sealed[2]).is_ok(), "a little late is fine");
        assert_eq!(bob.open(1, &sealed[2]), Err(Refusal::Replayed));
        assert!(bob.open(1, &sealed[99]).is_ok());
        assert_eq!(bob.open(1, &sealed[1]), Err(Refusal::Replayed), "too far behind to tell");
        assert!(bob.open(1, &sealed[50]).is_ok(), "within the window, never seen");
    }

    #[test]
    fn a_sender_cannot_be_passed_off_as_another() {
        let mut alice = Sealer::new(&key("k"), 0, 1);
        let mut bob = Opener::new(key("k"), 0);
        assert!(bob.open(4, &alice.seal(&opus(0)).unwrap()).is_ok());
        assert_eq!(bob.open(5, &alice.seal(&opus(1)).unwrap()), Err(Refusal::WrongSender));
        // Once they have left, their KID is forgotten with them.
        bob.left(4);
        assert!(bob.open(5, &alice.seal(&opus(2)).unwrap()).is_ok());
    }

    #[test]
    fn senders_with_one_key_do_not_share_a_keystream() {
        // Same room key, same counter, same plaintext: different ciphertext.
        let (mut a, mut b) = (Sealer::new(&key("k"), 0, 1), Sealer::new(&key("k"), 0, 2));
        let (x, y) = (a.seal(&opus(0)).unwrap(), b.seal(&opus(0)).unwrap());
        assert_ne!(x[audio::HEADER + 5..], y[audio::HEADER + 5..]);
    }

    #[test]
    fn epochs_overlap_while_keys_change() {
        let mut bob = Opener::new(key("old"), 0);
        let mut moved = Sealer::new(&key("new"), 1, 7);
        assert_eq!(bob.open(2, &moved.seal(&opus(0)).unwrap()), Err(Refusal::UnknownEpoch));
        bob.add(1, key("new"));
        assert!(bob.open(2, &moved.seal(&opus(1)).unwrap()).is_ok());
        let mut stayed = Sealer::new(&key("old"), 0, 8);
        assert!(bob.open(3, &stayed.seal(&opus(0)).unwrap()).is_ok());
        bob.remove(0);
        assert_eq!(bob.open(3, &stayed.seal(&opus(1)).unwrap()), Err(Refusal::UnknownEpoch));
    }

    #[test]
    fn generated_keys_are_url_safe_and_distinct() {
        let (k1, t1) = RoomKey::generate([0xfb; 16]);
        let (k2, t2) = RoomKey::generate([1; 16]);
        assert_eq!(t1.len(), 22);
        assert!(t1.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        assert_ne!(k1, k2);
        assert_eq!(RoomKey::from_text(&format!("  {t2}\n")), Some(k2));
        assert_eq!(RoomKey::from_text("   "), None);
        assert_eq!(base64url(b"Man"), "TWFu");
        assert_eq!(base64url(b"Ma"), "TWE");
        assert_eq!(format!("{k1:?}"), "RoomKey(…)", "never printed");
    }
}
