//! What quic-call puts in its datagrams, and what the relay between clients
//! adds and says.
//!
//! A client sends audio and video as datagrams on one [`datagram`] link; the
//! relay forwards each to everyone else in the room with the sender's id in
//! front ([`relay::tag`]), and talks to clients over the link's control
//! channel ([`relay::FromRelay`]). Everything a client sends starts with a
//! kind byte, so the two kinds share the link and the relay forwards them
//! without reading past the front:
//!
//! ```text
//! audio: [KIND_AUDIO][track: u8][seq: u32 BE][rate: u32 BE][capture: u32 BE][opus packet]
//! video: [KIND_VIDEO][track: u8][frame: u32 BE][capture: u32 BE][index: u8][count: u8][flags: u8][piece]
//! relayed: [sender: u32 BE][either of the above]
//! ```
//!
//! `track` says which of the sender's streams this is — [`TRACK_MAIN`] for the
//! microphone and camera, [`TRACK_SCREEN`] for a screen share and its audio.
//! Audio and video tracks of the same number belong together: a video track is
//! held in step with the audio track of its own number, or with the
//! microphone when it has none. Receivers keep everything — jitter buffers,
//! assemblers, decoders — per (sender, track), so tracks never mix.
//!
//! A kind byte with [`SEALED`] set marks a datagram end-to-end encrypted
//! (see `call-e2ee`): its header is as above, and the rest is ciphertext only
//! the room's key opens. The relay reads the kind and track through it; a
//! client without the key sees it is not for it, rather than decoding noise.
//!
//! `capture` is when the sound or picture was captured, in whole
//! milliseconds on the sender's clock (the page's `performance.now()`),
//! wrapping every ~49 days. Audio and video share that clock, which is what
//! lets a receiver play them in step.
//!
//! [`datagram`]: https://docs.rs/datagram

pub mod audio;
pub mod relay;
pub mod video;

pub const KIND_AUDIO: u8 = 0;
pub const KIND_VIDEO: u8 = 1;
/// Set on the kind byte of an end-to-end encrypted datagram.
pub const SEALED: u8 = 0x80;
/// The microphone, and the camera.
pub const TRACK_MAIN: u8 = 0;
/// A screen share, and the screen's (or tab's) audio when it has some.
pub const TRACK_SCREEN: u8 = 1;

/// What a datagram carries, for deciding whether its sender may send it —
/// see `call-auth`. A screen share's audio counts as the screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Media {
    Audio,
    Video,
    Screen,
}

/// What a datagram carries, from its first two bytes alone — cheap enough for
/// a relay to ask of every one. `None` for anything that is not ours.
pub fn media(bytes: &[u8]) -> Option<Media> {
    let kind = bytes.first()? & !SEALED;
    match (kind, bytes.get(1)?) {
        (KIND_AUDIO | KIND_VIDEO, &TRACK_SCREEN) => Some(Media::Screen),
        (KIND_AUDIO, _) => Some(Media::Audio),
        (KIND_VIDEO, _) => Some(Media::Video),
        _ => None,
    }
}

/// Whether a datagram is end-to-end encrypted — readable only by
/// `call-e2ee` with the room's key; [`parse`] gives `None` for it.
pub fn sealed(bytes: &[u8]) -> bool {
    bytes.first().is_some_and(|k| k & SEALED != 0)
}

/// One datagram as a client sent it, read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Datagram<'a> {
    Audio(audio::Packet<'a>),
    Video(video::Fragment<'a>),
}

/// Read a datagram from its kind byte on. `None` for an unknown kind, or one
/// that does not add up.
pub fn parse(bytes: &[u8]) -> Option<Datagram<'_>> {
    match *bytes.first()? {
        KIND_AUDIO => audio::parse(bytes).map(Datagram::Audio),
        KIND_VIDEO => video::parse(bytes).map(Datagram::Video),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kind_byte_picks_the_reader() {
        let a = audio::encode(TRACK_MAIN, 1, 48_000, 2, &[9, 9]);
        assert!(matches!(parse(&a), Some(Datagram::Audio(p)) if p.opus == [9, 9]));
        let v = video::fragment(TRACK_SCREEN, 3, 4, true, &[7; 10], 100).unwrap();
        assert!(matches!(parse(&v[0]), Some(Datagram::Video(f)) if f.track == TRACK_SCREEN));
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&[2, 0, 0]), None);
    }

    #[test]
    fn media_is_read_from_the_front() {
        assert_eq!(media(&audio::encode(TRACK_MAIN, 0, 48_000, 0, &[1])), Some(Media::Audio));
        assert_eq!(media(&audio::encode(TRACK_SCREEN, 0, 48_000, 0, &[1])), Some(Media::Screen));
        let v = video::fragment(TRACK_MAIN, 0, 0, true, &[1; 4], 100).unwrap();
        assert_eq!(media(&v[0]), Some(Media::Video));
        let s = video::fragment(TRACK_SCREEN, 0, 0, true, &[1; 4], 100).unwrap();
        assert_eq!(media(&s[0]), Some(Media::Screen));
        assert_eq!(media(&[9, 0]), None);
        assert_eq!(media(&[0]), None);
    }

    #[test]
    fn sealed_datagrams_are_routed_but_not_read() {
        let mut a = audio::encode(TRACK_SCREEN, 0, 48_000, 0, &[1]);
        a[0] |= SEALED;
        assert!(sealed(&a));
        assert_eq!(media(&a), Some(Media::Screen), "the relay still knows what it is");
        assert_eq!(parse(&a), None, "a client without the key does not decode it");
        let mut v = video::fragment(TRACK_MAIN, 0, 0, true, &[1; 4], 100).unwrap().remove(0);
        v[0] |= SEALED;
        assert_eq!(media(&v), Some(Media::Video));
        assert_eq!(parse(&v), None);
        assert!(!sealed(&audio::encode(TRACK_MAIN, 0, 48_000, 0, &[1])));
    }
}
