//! One Opus frame in a datagram.
//!
//! ```text
//! [KIND_AUDIO][track: u8][seq: u32 BE][rate: u32 BE][capture: u32 BE][opus packet]
//! ```
//!
//! `seq` counts frames per track, for the jitter buffer; `rate` is the
//! sender's sample rate, which the receiver opens its decoder and output at.

use crate::KIND_AUDIO;

/// An audio datagram's header, kind byte included.
pub const HEADER: usize = 14;

/// An audio datagram, borrowed from the bytes it came in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    pub track: u8,
    pub seq: u32,
    pub rate: u32,
    pub capture: u32,
    pub opus: &'a [u8],
}

/// Write one.
pub fn encode(track: u8, seq: u32, rate: u32, capture: u32, opus: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + opus.len());
    out.push(KIND_AUDIO);
    out.push(track);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&rate.to_be_bytes());
    out.extend_from_slice(&capture.to_be_bytes());
    out.extend_from_slice(opus);
    out
}

/// Read one, from its kind byte on. `None` for anything else, or one with no
/// Opus packet in it.
pub fn parse(bytes: &[u8]) -> Option<Packet<'_>> {
    if bytes.len() <= HEADER || bytes[0] != KIND_AUDIO {
        return None;
    }
    let word = |at: usize| u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    Some(Packet { track: bytes[1], seq: word(2), rate: word(6), capture: word(10), opus: &bytes[HEADER..] })
}

/// The track and sequence number of an audio datagram, sealed or not — what
/// a relay counts its arrivals by.
pub fn seq_of(bytes: &[u8]) -> Option<(u8, u32)> {
    if bytes.len() <= HEADER || bytes[0] & !crate::SEALED != KIND_AUDIO {
        return None;
    }
    Some((bytes[1], u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TRACK_SCREEN;

    #[test]
    fn round_trips() {
        let bytes = encode(TRACK_SCREEN, u32::MAX, 48_000, 123_456, &[1, 2, 3]);
        assert_eq!(bytes.len(), HEADER + 3);
        assert_eq!(
            parse(&bytes),
            Some(Packet { track: TRACK_SCREEN, seq: u32::MAX, rate: 48_000, capture: 123_456, opus: &[1, 2, 3] })
        );
    }

    #[test]
    fn a_relay_reads_the_sequence_through_the_seal() {
        let mut bytes = encode(TRACK_SCREEN, 77, 48_000, 0, &[1]);
        assert_eq!(seq_of(&bytes), Some((TRACK_SCREEN, 77)));
        bytes[0] |= crate::SEALED;
        assert_eq!(seq_of(&bytes), Some((TRACK_SCREEN, 77)));
        assert_eq!(seq_of(&[crate::KIND_VIDEO; 20]), None);
    }

    #[test]
    fn a_header_alone_is_not_a_packet() {
        let bytes = encode(0, 0, 48_000, 0, &[]);
        assert_eq!(parse(&bytes), None);
        assert_eq!(parse(&bytes[..5]), None);
    }
}
