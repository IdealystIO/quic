//! Video frames in datagrams: cutting an encoded frame into pieces that each
//! fit in one, and putting them back together on the far side.
//!
//! ```text
//! [KIND_VIDEO][track: u8][frame: u32 BE][capture: u32 BE][index: u8][count: u8][flags: u8][back: u8][piece]
//! ```
//!
//! An Opus frame is sixty bytes; a VP8 keyframe at 640×480 is tens of
//! kilobytes, and a datagram carries about twelve hundred. So a video frame
//! goes out as up to [`MAX_FRAGMENTS`] datagrams, and arrives only if every
//! one of them does.
//!
//! # Layers, and what a frame needs
//!
//! A sender may encode in temporal layers: layer 0 alone is a quarter of the
//! frame rate, layer 1 adds the frames that make it half, layer 2 the rest.
//! A frame refers only to frames of its own layer or below, so a relay can
//! drop whole layers for someone whose download cannot take them — see
//! `call-relay`'s throttling — and what is left still decodes. `flags` carries
//! the layer (bits 1–2) beside the keyframe bit; `back` says how many frames
//! earlier the frame this one needs is: the latest before it of its own layer
//! or below, 0 for a keyframe. A sender without layers sends everything as
//! layer 0 with `back` 1 — each frame needs the one before.
//!
//! # Why decoding waits for what a frame needs
//!
//! A delta frame is a difference from the frames before it. Decoding one
//! whose predecessor never arrived does not fail — it paints the difference
//! onto the wrong picture, and the smear lasts until the next keyframe. So
//! [`Assembler`] hands over a frame only once the frame it needs has been
//! handed over, and always in order. A frame nothing arrived for is skipped
//! if nothing needs it — a layer the relay dropped — and if a layer-0 frame's
//! need is lost, it hands over nothing until a keyframe, and
//! [`Assembler::needs_key`] says to ask the sender for one.

use std::collections::{BTreeMap, BTreeSet};

use crate::{KIND_VIDEO, SEALED};
/// A video datagram's header, kind byte included.
pub const HEADER: usize = 14;
pub const FLAG_KEY: u8 = 1;
const LAYER_SHIFT: u8 = 1;
const LAYER_MASK: u8 = 0b110;
/// The most layers a sender may use.
pub const LAYERS: u8 = 3;
/// The piece count is one byte. At ~1.2 kB a piece that is 300 kB, several
/// times what a keyframe at this app's bitrate comes to.
pub const MAX_FRAGMENTS: usize = 255;
/// How many complete frames may wait behind a missing one before it is
/// written off. Three: datagrams reorder by a packet or two, not by a frame
/// interval, so anything later than this is lost rather than late.
const GAP_FRAMES: usize = 3;
/// How far behind the newest frame an incomplete one may sit before it is
/// dropped, so a lost piece does not keep its frame's other pieces forever.
const STALE_FRAMES: u32 = 30;
/// Decoded frames remembered, for what later frames need. Layer 0 at a
/// quarter of 24 fps reaches back four frames; this is plenty.
const REMEMBERED: usize = 64;

/// `a` is later than `b`, across the wrap.
fn newer(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// What a frame is, beside its bytes: a keyframe or not, its layer, and how
/// far back the frame it needs is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deps {
    pub key: bool,
    pub layer: u8,
    /// Frames back to the one this needs; 0 for a keyframe.
    pub back: u8,
}

impl Deps {
    /// A frame of a stream without layers: it needs the one before.
    pub fn plain(key: bool) -> Deps {
        Deps { key, layer: 0, back: if key { 0 } else { 1 } }
    }
}

/// Cut one encoded frame of a stream without layers into datagrams of at
/// most `payload` bytes each, header included. `None` when it would take more
/// than [`MAX_FRAGMENTS`].
pub fn fragment(track: u8, frame: u32, capture: u32, key: bool, data: &[u8], payload: usize) -> Option<Vec<Vec<u8>>> {
    fragment_layered(track, frame, capture, Deps::plain(key), data, payload)
}

/// [`fragment`], for a frame of a layered stream.
pub fn fragment_layered(
    track: u8,
    frame: u32,
    capture: u32,
    deps: Deps,
    data: &[u8],
    payload: usize,
) -> Option<Vec<Vec<u8>>> {
    let piece = payload.checked_sub(HEADER).filter(|&n| n > 0)?;
    let count = data.len().div_ceil(piece).max(1);
    if count > MAX_FRAGMENTS {
        return None;
    }
    let flags = if deps.key { FLAG_KEY } else { 0 } | ((deps.layer.min(LAYERS - 1) << LAYER_SHIFT) & LAYER_MASK);
    let back = if deps.key { 0 } else { deps.back.max(1) };
    Some(
        (0..count)
            .map(|i| {
                let body = &data[i * piece..((i + 1) * piece).min(data.len())];
                let mut out = Vec::with_capacity(HEADER + body.len());
                out.push(KIND_VIDEO);
                out.push(track);
                out.extend_from_slice(&frame.to_be_bytes());
                out.extend_from_slice(&capture.to_be_bytes());
                out.extend_from_slice(&[i as u8, count as u8, flags, back]);
                out.extend_from_slice(body);
                out
            })
            .collect(),
    )
}

/// The track and layer of a video datagram, sealed or not — all a relay
/// needs to decide whether to forward it. `None` for anything else.
pub fn layer_of(bytes: &[u8]) -> Option<(u8, u8)> {
    if bytes.len() < HEADER || bytes[0] & !SEALED != KIND_VIDEO {
        return None;
    }
    Some((bytes[1], (bytes[12] & LAYER_MASK) >> LAYER_SHIFT))
}

/// The track, frame and piece count of a video datagram, sealed or not —
/// what a relay counts arrivals by.
pub fn pieces_of(bytes: &[u8]) -> Option<(u8, u32, u8)> {
    if bytes.len() < HEADER || bytes[0] & !SEALED != KIND_VIDEO || bytes[11] == 0 {
        return None;
    }
    Some((bytes[1], u32::from_be_bytes(bytes[2..6].try_into().ok()?), bytes[11]))
}

/// One piece of a frame, borrowed from the datagram it came in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fragment<'a> {
    pub track: u8,
    pub frame: u32,
    pub capture: u32,
    pub index: u8,
    pub count: u8,
    pub key: bool,
    pub layer: u8,
    pub back: u8,
    pub data: &'a [u8],
}

/// Read a video datagram — from its kind byte on, without the relay's sender
/// tag (see [`crate::relay::untag`]). `None` for anything that is not one,
/// or does not add up.
pub fn parse(bytes: &[u8]) -> Option<Fragment<'_>> {
    if bytes.len() < HEADER || bytes[0] != KIND_VIDEO {
        return None;
    }
    let (index, count, flags, back) = (bytes[10], bytes[11], bytes[12], bytes[13]);
    let key = flags & FLAG_KEY != 0;
    if count == 0 || index >= count || (!key && back == 0) {
        return None;
    }
    Some(Fragment {
        track: bytes[1],
        frame: u32::from_be_bytes(bytes[2..6].try_into().ok()?),
        capture: u32::from_be_bytes(bytes[6..10].try_into().ok()?),
        index,
        count,
        key,
        layer: (flags & LAYER_MASK) >> LAYER_SHIFT,
        back: if key { 0 } else { back },
        data: &bytes[HEADER..],
    })
}

/// A complete frame, ready for the decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub frame: u32,
    /// When the camera took it — see the wire format.
    pub capture: u32,
    pub key: bool,
    pub layer: u8,
    /// Frames back to the one it needs.
    pub back: u8,
    pub data: Vec<u8>,
}

impl Frame {
    /// The frame this one needs; `None` for a keyframe.
    fn needs(&self) -> Option<u32> {
        (!self.key).then(|| self.frame.wrapping_sub(self.back as u32))
    }
}

struct Partial {
    key: bool,
    layer: u8,
    back: u8,
    capture: u32,
    pieces: Vec<Option<Vec<u8>>>,
    got: usize,
}

/// One sender's frames, put back together and released in decodable order.
pub struct Assembler {
    partial: BTreeMap<u32, Partial>,
    /// Complete frames waiting for the frame they need.
    ready: BTreeMap<u32, Frame>,
    /// The last frame handed to the decoder.
    last: Option<u32>,
    /// Frames handed over since the last keyframe, the latest few.
    decoded: BTreeSet<u32>,
    /// Frames known never to be decodable — lost, or needing one that was —
    /// so whatever needs them is written off at once.
    lost: BTreeSet<u32>,
    newest: Option<u32>,
    needs_key: bool,
}

impl Default for Assembler {
    fn default() -> Self {
        // Nothing decoded yet, so the first thing that can be is a keyframe.
        Assembler {
            partial: BTreeMap::new(),
            ready: BTreeMap::new(),
            last: None,
            decoded: BTreeSet::new(),
            lost: BTreeSet::new(),
            newest: None,
            needs_key: true,
        }
    }
}

impl Assembler {
    /// Whether the decoder is stuck until a keyframe comes.
    pub fn needs_key(&self) -> bool {
        self.needs_key
    }

    /// The decoder lost its state (it errored, or was rebuilt): nothing but a
    /// keyframe can follow.
    pub fn reset(&mut self) {
        self.needs_key = true;
        self.ready.clear();
        self.decoded.clear();
        self.lost.clear();
    }

    /// Take one piece. Returns the frames that can now be decoded, in order.
    pub fn push(&mut self, f: Fragment<'_>) -> Vec<Frame> {
        let mut out = Vec::new();
        if self.last.is_some_and(|l| !newer(f.frame, l)) {
            return out;
        }
        if self.newest.is_none_or(|n| newer(f.frame, n)) {
            self.newest = Some(f.frame);
        }
        self.prune();

        let partial = self.partial.entry(f.frame).or_insert_with(|| Partial {
            key: f.key,
            layer: f.layer,
            back: f.back,
            capture: f.capture,
            pieces: vec![None; f.count as usize],
            got: 0,
        });
        // A piece that disagrees with its frame's others is corrupt, or from a
        // sender that restarted its count; either way the frame cannot be
        // trusted.
        if partial.pieces.len() != f.count as usize || partial.key != f.key || partial.back != f.back {
            self.partial.remove(&f.frame);
            return out;
        }
        let slot = &mut partial.pieces[f.index as usize];
        if slot.is_none() {
            *slot = Some(f.data.to_vec());
            partial.got += 1;
        }
        if partial.got < partial.pieces.len() {
            return out;
        }

        let partial = self.partial.remove(&f.frame).expect("just completed");
        let frame = Frame {
            frame: f.frame,
            capture: partial.capture,
            key: partial.key,
            layer: partial.layer,
            back: partial.back,
            data: partial.pieces.into_iter().flatten().flatten().collect(),
        };
        if frame.key {
            // Everything before a keyframe is moot.
            let at = frame.frame;
            self.ready.retain(|&n, _| newer(n, at));
            self.partial.retain(|&n, _| newer(n, at));
            self.decoded.clear();
            self.lost.clear();
            self.hand_over(frame, &mut out);
            self.needs_key = false;
        } else if !self.needs_key {
            self.ready.insert(frame.frame, frame);
        }
        self.drain(&mut out);
        out
    }

    fn hand_over(&mut self, frame: Frame, out: &mut Vec<Frame>) {
        let at = frame.frame;
        self.last = Some(at);
        self.decoded.insert(at);
        for set in [&mut self.decoded, &mut self.lost] {
            while set.len() > REMEMBERED {
                let oldest = *set.iter().max_by_key(|&&n| at.wrapping_sub(n)).expect("not empty");
                set.remove(&oldest);
            }
        }
        // Anything older still waiting can no longer go: the decoder has
        // moved past it.
        self.ready.retain(|&n, _| newer(n, at));
        out.push(frame);
    }

    fn drain(&mut self, out: &mut Vec<Frame>) {
        loop {
            if self.needs_key {
                return;
            }
            let Some(last) = self.last else { return };
            // The oldest waiting frame that can go, or that never can.
            let mut next = None;
            for (&n, frame) in &self.ready {
                let needs = frame.needs().expect("keyframes are not queued");
                if self.decoded.contains(&needs) {
                    next = Some((n, true));
                    break;
                }
                if self.lost.contains(&needs) || !newer(needs, last) {
                    // What it needs is lost, or behind the decoder and never
                    // handed over: it is not coming.
                    next = Some((n, false));
                    break;
                }
            }
            match next {
                Some((n, true)) => {
                    let frame = self.ready.remove(&n).expect("found above");
                    self.hand_over(frame, out);
                }
                Some((n, false)) => self.write_off(n),
                None => {
                    // Frames are queued behind ones that have not come. Past a
                    // few, those are lost, not late: the oldest one waited
                    // for, and so everything that needs it.
                    if self.ready.len() <= GAP_FRAMES {
                        return;
                    }
                    let oldest = self.ready.values().next().expect("more than GAP_FRAMES");
                    self.lost.insert(oldest.needs().expect("keyframes are not queued"));
                }
            }
        }
    }

    /// `n` can never be decoded. Nothing that layer 0 leads to can be either,
    /// so losing a layer-0 frame waits for a keyframe; anything above it is
    /// simply skipped.
    fn write_off(&mut self, n: u32) {
        let Some(frame) = self.ready.remove(&n) else { return };
        self.lost.insert(n);
        if frame.layer == 0 {
            self.reset();
        }
    }

    fn prune(&mut self) {
        let Some(newest) = self.newest else { return };
        self.partial.retain(|&n, _| newest.wrapping_sub(n) <= STALE_FRAMES);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KIND_AUDIO, TRACK_MAIN, TRACK_SCREEN};

    const PAYLOAD: usize = 100;

    fn frame(n: u32, key: bool, len: usize) -> Vec<Vec<u8>> {
        let data: Vec<u8> = (0..len).map(|i| (i as u32 ^ n) as u8).collect();
        fragment(TRACK_MAIN, n, n.wrapping_mul(42), key, &data, PAYLOAD).unwrap()
    }

    fn feed(a: &mut Assembler, datagrams: &[Vec<u8>]) -> Vec<u32> {
        datagrams.iter().flat_map(|d| a.push(parse(d).unwrap())).map(|f| f.frame).collect()
    }

    #[test]
    fn every_piece_fits_and_they_add_back_up() {
        let data: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let pieces = fragment(TRACK_SCREEN, 7, 123_456, true, &data, PAYLOAD).unwrap();
        assert!(pieces.iter().all(|p| parse(p).unwrap().track == TRACK_SCREEN));
        assert!(pieces.iter().all(|p| p.len() <= PAYLOAD));
        let mut a = Assembler::default();
        let out: Vec<Frame> = pieces.iter().flat_map(|p| a.push(parse(p).unwrap())).collect();
        assert_eq!(out, vec![Frame { frame: 7, capture: 123_456, key: true, layer: 0, back: 0, data }]);
    }

    #[test]
    fn a_frame_too_big_for_the_count_byte_is_refused() {
        let piece = PAYLOAD - HEADER;
        assert!(fragment(TRACK_MAIN, 0, 0, true, &vec![0; piece * MAX_FRAGMENTS], PAYLOAD).is_some());
        assert!(fragment(TRACK_MAIN, 0, 0, true, &vec![0; piece * MAX_FRAGMENTS + 1], PAYLOAD).is_none());
    }

    #[test]
    fn nothing_decodes_before_the_first_keyframe() {
        // Joining mid-call: the deltas already flowing are useless alone.
        let mut a = Assembler::default();
        assert!(feed(&mut a, &frame(10, false, 250)).is_empty());
        assert!(a.needs_key());
        assert_eq!(feed(&mut a, &frame(11, true, 250)), vec![11]);
        assert_eq!(feed(&mut a, &frame(12, false, 250)), vec![12]);
        assert!(!a.needs_key());
    }

    #[test]
    fn a_frame_arriving_out_of_order_waits_for_the_one_before_it() {
        let mut a = Assembler::default();
        feed(&mut a, &frame(0, true, 50));
        let (one, two) = (frame(1, false, 250), frame(2, false, 250));
        assert!(feed(&mut a, &two).is_empty(), "2 cannot go before 1");
        assert_eq!(feed(&mut a, &one), vec![1, 2]);
    }

    #[test]
    fn a_lost_piece_stops_decoding_until_a_keyframe() {
        let mut a = Assembler::default();
        feed(&mut a, &frame(0, true, 50));
        let mut lossy = frame(1, false, 250);
        lossy.remove(1);
        assert!(feed(&mut a, &lossy).is_empty());
        for n in 2..=5 {
            assert!(feed(&mut a, &frame(n, false, 50)).is_empty(), "frame {n} would smear");
        }
        assert!(a.needs_key(), "four frames past a hole is a loss, not a delay");
        assert_eq!(feed(&mut a, &frame(6, true, 50)), vec![6]);
        assert_eq!(feed(&mut a, &frame(7, false, 50)), vec![7]);
    }

    #[test]
    fn duplicates_and_old_frames_are_ignored() {
        let mut a = Assembler::default();
        let key = frame(0, true, 250);
        assert_eq!(feed(&mut a, &key), vec![0]);
        assert!(feed(&mut a, &key).is_empty(), "a repeat of a decoded frame");
        let one = frame(1, false, 250);
        let doubled: Vec<Vec<u8>> = one.iter().flat_map(|p| [p.clone(), p.clone()]).collect();
        assert_eq!(feed(&mut a, &doubled), vec![1]);
    }

    #[test]
    fn frame_numbers_wrap() {
        let mut a = Assembler::default();
        assert_eq!(feed(&mut a, &frame(u32::MAX, true, 50)), vec![u32::MAX]);
        assert_eq!(feed(&mut a, &frame(0, false, 50)), vec![0]);
    }

    #[test]
    fn audio_is_not_mistaken_for_video() {
        assert_eq!(parse(&[KIND_AUDIO, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 9]), None);
        assert_eq!(parse(&[KIND_VIDEO, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 9]), None, "index past count");
        assert_eq!(parse(&[KIND_VIDEO, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 9]), None, "a delta that needs nothing");
    }

    /// A layered stream: 0 2 1 2 0 2 1 2 …, each frame needing the latest
    /// before it of its own layer or below.
    fn layered(n: u32) -> Vec<Vec<u8>> {
        const PATTERN: [u8; 4] = [0, 2, 1, 2];
        let layer = PATTERN[(n % 4) as usize];
        let back = match (n, layer) {
            (0, _) => 0,
            (_, 0) => 4,
            (_, 1) => 2,
            _ => 1,
        };
        let deps = Deps { key: n == 0, layer, back };
        fragment_layered(TRACK_MAIN, n, n * 42, deps, &[n as u8; 250], PAYLOAD).unwrap()
    }

    #[test]
    fn layers_survive_the_header() {
        let p = &layered(6)[0];
        let f = parse(p).unwrap();
        assert_eq!((f.layer, f.back, f.key), (1, 2, false));
        assert_eq!(layer_of(p), Some((TRACK_MAIN, 1)));
        let mut sealed = p.clone();
        sealed[0] |= SEALED;
        assert_eq!(layer_of(&sealed), Some((TRACK_MAIN, 1)), "a relay reads it through the seal");
        assert_eq!(layer_of(&frame(0, true, 50)[0]), Some((TRACK_MAIN, 0)));
        assert_eq!(pieces_of(&sealed), Some((TRACK_MAIN, 6, 3)));
    }

    #[test]
    fn every_layer_decodes_in_order() {
        let mut a = Assembler::default();
        let got: Vec<u32> = (0..12).flat_map(|n| feed(&mut a, &layered(n))).collect();
        assert_eq!(got, (0..12).collect::<Vec<_>>());
    }

    #[test]
    fn dropping_the_top_layers_still_decodes_the_rest() {
        // What a relay throttling someone forwards: layer 0 only, then layers
        // 0 and 1. Nothing waits for the frames it dropped.
        let mut a = Assembler::default();
        let base: Vec<u32> = (0..16).filter(|n| n % 4 == 0).flat_map(|n| feed(&mut a, &layered(n))).collect();
        assert_eq!(base, vec![0, 4, 8, 12]);
        assert!(!a.needs_key());
        let half: Vec<u32> = (16..24).filter(|n| n % 2 == 0).flat_map(|n| feed(&mut a, &layered(n))).collect();
        assert_eq!(half, vec![16, 18, 20, 22]);
        // And back to everything, mid-stream, with no keyframe.
        let all: Vec<u32> = (24..28).flat_map(|n| feed(&mut a, &layered(n))).collect();
        assert_eq!(all, vec![24, 25, 26, 27]);
    }

    #[test]
    fn a_lost_top_layer_frame_costs_only_itself() {
        let mut a = Assembler::default();
        let mut got = Vec::new();
        for n in 0..9 {
            if n == 3 {
                continue; // layer 2: nothing needs it
            }
            got.extend(feed(&mut a, &layered(n)));
        }
        assert_eq!(got, vec![0, 1, 2, 4, 5, 6, 7, 8]);
        assert!(!a.needs_key());
    }

    #[test]
    fn a_lost_middle_layer_frame_costs_what_needs_it() {
        let mut a = Assembler::default();
        let mut got = Vec::new();
        for n in 0..9 {
            if n == 2 {
                continue; // layer 1: frame 3 needs it; frame 4 does not
            }
            got.extend(feed(&mut a, &layered(n)));
        }
        assert_eq!(got, vec![0, 1, 4, 5, 6, 7, 8]);
        assert!(!a.needs_key());
    }

    #[test]
    fn a_lost_base_layer_frame_waits_for_a_keyframe() {
        let mut a = Assembler::default();
        let mut got = Vec::new();
        for n in 0..10 {
            if n == 4 {
                continue;
            }
            got.extend(feed(&mut a, &layered(n)));
        }
        assert_eq!(&got[..4], &[0, 1, 2, 3]);
        assert!(!got.contains(&8), "8 needs 4, which never came");
        assert!(a.needs_key());
    }
}
