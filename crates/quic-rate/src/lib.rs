//! How fast to send: each receiver measures what it loses of everyone's
//! audio ([`LossMeter`]) and says so once a second
//! (`call_proto::relay::LossReport`); each sender turns what it hears about
//! itself, its own send queue and its round trip into a budget
//! ([`Controller`]), and splits the budget between voice and video
//! ([`Plan`]).
//!
//! # Whose loss counts
//!
//! The relay forwards one stream to everyone, so a sender cannot serve each
//! receiver at its own rate. It takes the **least** loss any receiver reports:
//! loss everyone sees happened on the way in — the sender's uplink, or the
//! relay — and is the sender's to fix; loss only one receiver sees happened on
//! that receiver's downlink, and cutting everyone's picture would not help
//! them. (Serving them would take simulcast, which this is not.)
//!
//! # The rules
//!
//! Once a second, the first that applies:
//!
//! | signal | response |
//! | --- | --- |
//! | our own send queue overflowed | cut 15% |
//! | loss above 10% | cut by half the loss (10% loss: 5%; 40%: 20%) |
//! | round trip 150 ms and half again over its floor | cut 15% — a queue filling somewhere, before it overflows |
//! | loss under 2%, nothing cut for 3 s | grow 8% + 4 kb/s, to the ceiling |
//! | otherwise | hold |
//!
//! Cut fast, grow slowly: an overshoot costs everyone a frozen picture, and
//! an undershoot costs a slightly softer one. Starting a call, or turning a
//! camera on, starts at the ceiling — a home link usually has the headroom,
//! and finding out costs seconds, not the minute ramping up from the floor
//! would.
//!
//! # Download, at the relay
//!
//! All of the above is about what a sender sends. What one receiver can take
//! is the relay's business, and only when it is asked to make it its
//! business: [`Throttle`] is a relay's per-receiver decision about what to
//! hold back — video layers first, then cameras, then all video — from the
//! receiver's download loss, which [`downlink_loss`] estimates from what the
//! receiver reports and what the relay itself saw arrive. Unlike the sender's
//! rule, that takes the *worst* stream: with each sender's own losses taken
//! out, whatever is left went missing on the receiver's link.
//!
//! # Voice first
//!
//! Audio steps down a ladder of [`AUDIO_RUNGS`] — 40 and 32 kb/s fullband,
//! then 24 and 16 wideband — but only once video has reached its floor: a
//! blurred face is a better trade than a garbled voice.

use std::collections::HashMap;

/// One step of the voice ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioRate {
    pub bps: u32,
    /// To 20 kHz (CELT) rather than 8 (SILK); see `audio_codec`.
    pub fullband: bool,
}

/// Voice, best first. The step to wideband changes codec, so it comes at the
/// bitrate where SILK's efficiency starts to beat CELT's range.
pub const AUDIO_RUNGS: [AudioRate; 4] = [
    AudioRate { bps: 40_000, fullband: true },
    AudioRate { bps: 32_000, fullband: true },
    AudioRate { bps: 24_000, fullband: false },
    AudioRate { bps: 16_000, fullband: false },
];
const AUDIO_MAX: u32 = AUDIO_RUNGS[0].bps;
const AUDIO_MIN: u32 = AUDIO_RUNGS[AUDIO_RUNGS.len() - 1].bps;

/// Below this the full band costs more than it gives; for a manual setting.
const FULLBAND_FROM: u32 = 28_000;
const LOSS_CUT: f64 = 0.10;
const LOSS_CLEAR: f64 = 0.02;
const GROW: f64 = 1.08;
const GROW_STEP: f64 = 4_000.0;
const CUT: f64 = 0.85;
/// How long after a cut before growing again.
const SETTLE_MS: f64 = 3_000.0;
/// A report older than this no longer says anything about now.
const REPORT_MS: f64 = 3_000.0;
const DELAY_OVER_MS: f64 = 150.0;
/// How fast the round-trip floor forgets an old minimum, ms per tick — so a
/// route that got permanently longer stops looking like a queue.
const FLOOR_DRIFT_MS: f64 = 1.0;

/// How the bitrate is chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Auto,
    /// Exactly these, whatever the link does: for testing, or for a link
    /// known better than the controller can measure it.
    Manual { audio_bps: u32, video_bps: u32 },
}

/// Why the plan is what it is, for the page.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Why {
    /// Nothing heard to cut for, and at the ceiling.
    Ceiling,
    /// Nothing heard to cut for; growing.
    Growing,
    /// Some loss, not enough to cut for; holding.
    Holding,
    /// Cut: receivers lost this much of us.
    Loss(f64),
    /// Cut: our own send queue overflowed.
    Queue,
    /// Cut: the round trip rose — a queue filling somewhere.
    Delay,
    Manual,
}

/// What to send at now.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Plan {
    pub audio: AudioRate,
    /// For all our video tracks together; 0 with none on.
    pub video_bps: u32,
    pub why: Why,
}

/// What the sender knows about itself, each tick.
#[derive(Debug, Clone, Copy, Default)]
pub struct Signals {
    pub now_ms: f64,
    /// Smoothed round trip to the relay.
    pub rtt_ms: Option<f64>,
    /// Datagrams our own queues refused, cumulative.
    pub dropped: u64,
    /// Our video tracks' range, together: the least they can be sent at, and
    /// the most worth sending. Both 0 with none on.
    pub video_min: u32,
    pub video_max: u32,
}

/// A sender's bitrate, decided once a second.
#[derive(Debug, Default)]
pub struct Controller {
    mode: Mode,
    /// The budget, bps; 0 before the first tick.
    budget: f64,
    ceiling: f64,
    /// Loss each receiver last reported for us, and when.
    reports: HashMap<u32, (f64, f64)>,
    dropped: u64,
    rtt_floor: Option<f64>,
    last_cut: f64,
    last: Option<Plan>,
}

impl Controller {
    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn set_mode(&mut self, mode: Mode) {
        // Back to auto from a manual setting: start from where it was, rather
        // than from the ceiling.
        if let (Mode::Manual { audio_bps, video_bps }, Mode::Auto) = (self.mode, mode) {
            self.budget = (audio_bps + video_bps) as f64;
            self.last_cut = f64::NEG_INFINITY;
        }
        self.mode = mode;
    }

    /// Receiver `from` lost `loss` (0–1) of our audio in its last second.
    pub fn report(&mut self, from: u32, loss: f64, now_ms: f64) {
        self.reports.insert(from, (loss.clamp(0.0, 1.0), now_ms));
    }

    /// Someone left: their reports go with them.
    pub fn left(&mut self, from: u32) {
        self.reports.remove(&from);
    }

    /// The least loss any receiver reported lately — the loss that is ours.
    pub fn loss(&self, now_ms: f64) -> Option<f64> {
        self.reports
            .values()
            .filter(|(_, at)| now_ms - at <= REPORT_MS)
            .map(|&(loss, _)| loss)
            .fold(None, |least: Option<f64>, l| Some(least.map_or(l, |m| m.min(l))))
    }

    /// The last plan, if there has been one.
    pub fn plan(&self) -> Option<Plan> {
        self.last
    }

    /// Decide, once a second.
    pub fn tick(&mut self, s: Signals) -> Plan {
        let now = s.now_ms;
        self.reports.retain(|_, (_, at)| now - *at <= REPORT_MS);
        let overflowed = s.dropped > self.dropped;
        self.dropped = s.dropped;
        if let Some(rtt) = s.rtt_ms {
            self.rtt_floor = Some(self.rtt_floor.map_or(rtt, |f| (f + FLOOR_DRIFT_MS).min(rtt)));
        }

        let ceiling = (AUDIO_MAX + s.video_max) as f64;
        let floor = (AUDIO_MIN + s.video_min) as f64;
        if self.budget <= 0.0 {
            self.budget = ceiling;
        } else if ceiling > self.ceiling {
            // A track turned on: it starts at its own ceiling.
            self.budget += ceiling - self.ceiling;
        }
        self.ceiling = ceiling;

        let plan = match self.mode {
            Mode::Manual { audio_bps, video_bps } => Plan {
                audio: AudioRate { bps: audio_bps, fullband: audio_bps >= FULLBAND_FROM },
                video_bps: if s.video_max == 0 { 0 } else { video_bps },
                why: Why::Manual,
            },
            Mode::Auto => {
                let loss = self.loss(now);
                let delayed = match (s.rtt_ms, self.rtt_floor) {
                    (Some(rtt), Some(f)) => rtt > f + DELAY_OVER_MS && rtt > f * 1.5,
                    _ => false,
                };
                let why = if overflowed {
                    self.cut(CUT, now);
                    Why::Queue
                } else if let Some(l) = loss.filter(|&l| l > LOSS_CUT) {
                    self.cut(1.0 - l / 2.0, now);
                    Why::Loss(l)
                } else if delayed {
                    self.cut(CUT, now);
                    Why::Delay
                } else if loss.is_none_or(|l| l <= LOSS_CLEAR) && now - self.last_cut >= SETTLE_MS {
                    self.budget = (self.budget * GROW + GROW_STEP).min(ceiling);
                    if self.budget >= ceiling { Why::Ceiling } else { Why::Growing }
                } else if self.budget >= ceiling && loss.is_none_or(|l| l <= LOSS_CLEAR) {
                    Why::Ceiling
                } else {
                    Why::Holding
                };
                self.budget = self.budget.clamp(floor, ceiling);
                let (audio, video_bps) = split(self.budget as u32, s.video_min, s.video_max);
                Plan { audio, video_bps, why }
            }
        };
        self.last = Some(plan);
        plan
    }

    fn cut(&mut self, by: f64, now: f64) {
        self.budget *= by;
        self.last_cut = now;
    }
}

/// Voice first: the best rung that still leaves video its floor, and video
/// what is left.
pub fn split(budget: u32, video_min: u32, video_max: u32) -> (AudioRate, u32) {
    let fits = |r: &&AudioRate| {
        if video_max == 0 { r.bps <= budget } else { budget.saturating_sub(r.bps) >= video_min }
    };
    let audio = *AUDIO_RUNGS.iter().find(fits).unwrap_or(&AUDIO_RUNGS[AUDIO_RUNGS.len() - 1]);
    let video = if video_max == 0 { 0 } else { budget.saturating_sub(audio.bps).clamp(video_min, video_max) };
    (audio, video)
}

/// What a receiver loses of each sender, a window at a time: audio by
/// sequence number — it never stops, fifty packets a second, silence and all
/// — and video by the pieces of each frame that arrived. A sender's loss is
/// the worse of the two: a link that is full drops the big video pieces
/// first, and the small voice packets may slip through untouched.
///
/// A video frame of which nothing arrived is not counted, which is right for
/// layers a relay held back on purpose and only an underestimate otherwise.
#[derive(Debug, Default)]
pub struct LossMeter {
    senders: HashMap<u32, Window>,
    /// By (sender, track): each track numbers its own frames.
    video: HashMap<(u32, u8), Pieces>,
}

/// One video track's frames in flight, and the pieces settled this window.
#[derive(Debug, Default)]
struct Pieces {
    /// Frame → (pieces it has, pieces arrived).
    frames: std::collections::BTreeMap<u32, (u8, u8)>,
    newest: Option<u32>,
    expected: u32,
    got: u32,
}

/// A frame this many behind the newest has had all the time it will get.
const SETTLE_FRAMES: u32 = 3;

#[derive(Debug)]
struct Window {
    /// The first sequence number this window expects.
    base: u32,
    /// The newest seen in it.
    top: u32,
    got: u32,
    /// Whether anything has arrived in it.
    any: bool,
    /// Windows in a row with nothing in them.
    empty: u8,
}

/// A jump this far ahead is a sender that restarted its count, not loss.
const RESYNC: u32 = 3_000;

impl LossMeter {
    /// A packet `seq` arrived from `from`.
    pub fn observe(&mut self, from: u32, seq: u32) {
        let w = self.senders.entry(from).or_insert(Window { base: seq, top: seq, got: 0, any: false, empty: 0 });
        let ahead = seq.wrapping_sub(w.base);
        if ahead >= u32::MAX / 2 {
            // Behind the window: a late packet from the last one.
            return;
        }
        if ahead > RESYNC {
            *w = Window { base: seq, top: seq, got: 0, any: false, empty: 0 };
        }
        if !w.any || (seq.wrapping_sub(w.top) as i32) > 0 {
            w.top = seq;
        }
        w.any = true;
        w.got += 1;
    }

    /// A piece of video frame `frame`, which has `count` pieces, arrived from
    /// `from` on `track`.
    pub fn observe_video(&mut self, from: u32, track: u8, frame: u32, count: u8) {
        let v = self.video.entry((from, track)).or_default();
        if v.newest.is_some_and(|n| n.wrapping_sub(frame) < u32::MAX / 2 && n.wrapping_sub(frame) >= SETTLE_FRAMES) {
            return; // too late to count
        }
        if v.newest.is_none_or(|n| (frame.wrapping_sub(n) as i32) > 0) {
            v.newest = Some(frame);
        }
        let entry = v.frames.entry(frame).or_insert((count.max(1), 0));
        entry.1 = (entry.1 + 1).min(entry.0);
        // Settle what is old enough now, so a window's count is of whole frames.
        let newest = v.newest.expect("set above");
        let settled: Vec<u32> =
            v.frames.keys().copied().filter(|&f| newest.wrapping_sub(f) >= SETTLE_FRAMES).collect();
        for f in settled {
            let (have, got) = v.frames.remove(&f).expect("listed");
            v.expected += have as u32;
            v.got += got as u32;
        }
    }

    /// Someone left.
    pub fn left(&mut self, from: u32) {
        self.senders.remove(&from);
        self.video.retain(|&(id, _), _| id != from);
    }

    /// Loss per sender since the last call, in thousandths, and a new window.
    /// A sender that went silent for a whole window after sending is reported
    /// as having lost everything — once; after that they are forgotten, as
    /// someone who stopped.
    pub fn window(&mut self) -> Vec<(u32, u16)> {
        let mut out = Vec::new();
        self.senders.retain(|&id, w| {
            if !w.any {
                w.empty += 1;
                if w.empty == 1 {
                    out.push((id, 1000));
                }
                return w.empty < 3;
            }
            let expected = w.top.wrapping_sub(w.base) + 1;
            let lost = expected.saturating_sub(w.got);
            out.push((id, (lost as u64 * 1000 / expected as u64) as u16));
            *w = Window { base: w.top.wrapping_add(1), top: w.top, got: 0, any: false, empty: 0 };
            true
        });
        // Video: the worse of it and the audio, per sender.
        for (&(id, _), v) in self.video.iter_mut() {
            if v.expected == 0 {
                continue;
            }
            let permille = ((v.expected - v.got.min(v.expected)) as u64 * 1000 / v.expected as u64) as u16;
            (v.expected, v.got) = (0, 0);
            match out.iter_mut().find(|(s, _)| *s == id) {
                Some(entry) => entry.1 = entry.1.max(permille),
                None => out.push((id, permille)),
            }
        }
        out.sort_unstable();
        out
    }
}

/// How much a throttling relay holds back from one receiver. Each level
/// keeps what the one before kept, less one thing:
///
/// | level | forwarded |
/// | --- | --- |
/// | 0 | everything |
/// | 1 | video layers 0–1: half the frame rate |
/// | 2 | video layer 0: a quarter |
/// | 3 | screen shares at a quarter; no cameras |
/// | 4 | no video — voice alone |
///
/// Voice is never held back: it is small, and it is the call.
pub const THROTTLE_MAX: u8 = 4;
/// Download loss over this steps a level down.
const THROTTLE_LOSS: f64 = 0.08;
/// Under this for [`THROTTLE_CLEAR_MS`] steps a level back up.
const THROTTLE_CLEAR: f64 = 0.02;
/// Between steps down: long enough for the last one to show in the loss.
const THROTTLE_STEP_MS: f64 = 2_000.0;
/// How long loss must stay clear before stepping back up, at first.
const THROTTLE_CLEAR_MS: f64 = 6_000.0;
/// A step down this soon after a step up means the step up was too much:
/// the wait before the next doubles, to at most [`THROTTLE_CLEAR_MAX_MS`].
const THROTTLE_RELAPSE_MS: f64 = 10_000.0;
const THROTTLE_CLEAR_MAX_MS: f64 = 60_000.0;

/// A relay's decision about one receiver: see [`THROTTLE_MAX`] for the
/// levels. Stepped down fast on loss, back up slowly once it clears — and
/// more slowly each time stepping back up brings the loss straight back, so a
/// download that can take one level and not the next settles on it rather
/// than flapping a camera on and off.
#[derive(Debug)]
pub struct Throttle {
    level: u8,
    changed: f64,
    clear_since: Option<f64>,
    /// How long loss must stay clear to step up, now.
    clear_ms: f64,
    /// When it last stepped up.
    stepped_up: f64,
}

impl Default for Throttle {
    fn default() -> Self {
        Throttle {
            level: 0,
            changed: f64::NEG_INFINITY,
            clear_since: None,
            clear_ms: THROTTLE_CLEAR_MS,
            stepped_up: f64::NEG_INFINITY,
        }
    }
}

impl Throttle {
    pub fn level(&self) -> u8 {
        self.level
    }

    /// The receiver's download loss, from its latest report. The new level,
    /// when it changes.
    pub fn observe(&mut self, loss: f64, now_ms: f64) -> Option<u8> {
        let before = self.level;
        if loss > THROTTLE_LOSS {
            self.clear_since = None;
            if self.level < THROTTLE_MAX && now_ms - self.changed >= THROTTLE_STEP_MS {
                if now_ms - self.stepped_up < THROTTLE_RELAPSE_MS {
                    self.clear_ms = (self.clear_ms * 2.0).min(THROTTLE_CLEAR_MAX_MS);
                }
                self.level += 1;
                self.changed = now_ms;
            }
        } else if loss < THROTTLE_CLEAR {
            let since = *self.clear_since.get_or_insert(now_ms);
            if self.level > 0 && now_ms - since >= self.clear_ms && now_ms - self.changed >= self.clear_ms {
                self.level -= 1;
                self.changed = now_ms;
                self.stepped_up = now_ms;
                self.clear_since = Some(now_ms);
            } else if self.level == 0 && now_ms - since >= THROTTLE_CLEAR_MAX_MS {
                // A long clear stretch with nothing held back: start afresh.
                self.clear_ms = THROTTLE_CLEAR_MS;
            }
        } else {
            self.clear_since = None;
        }
        (self.level != before).then_some(self.level)
    }

    /// Whether a datagram goes to a receiver at `level`: `video` is its
    /// (track, layer) when it is video, `None` for voice.
    pub fn forwards(level: u8, video: Option<(u8, u8)>) -> bool {
        let Some((track, layer)) = video else { return true };
        match level {
            0 => true,
            1 => layer <= 1,
            2 => layer == 0,
            3 => layer == 0 && track != CAMERA,
            _ => false,
        }
    }
}

/// The camera's track number, `call_proto::TRACK_MAIN` — restated so this
/// crate stays dependency-free.
const CAMERA: u8 = 0;

/// A receiver's download loss: what it reports losing of each sender, less
/// what the relay saw that sender lose on the way in (`uplink`) — what is
/// left was lost between the relay and the receiver — and the most of those.
/// The most, not the least: a download that is full loses the heavy streams
/// and lets a voice-only one through untouched, so the stream that suffers
/// is the one that says how the link is doing. `None` with nothing reported.
pub fn downlink_loss(report: &[(u32, u16)], uplink: impl Fn(u32) -> f64) -> Option<f64> {
    report
        .iter()
        .map(|&(sender, permille)| (permille as f64 / 1000.0 - uplink(sender)).max(0.0))
        .fold(None, |most: Option<f64>, l| Some(most.map_or(l, |m| m.max(l))))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAMERA: (u32, u32) = (100_000, 600_000);

    fn signals(now_ms: f64) -> Signals {
        Signals { now_ms, rtt_ms: Some(40.0), dropped: 0, video_min: CAMERA.0, video_max: CAMERA.1 }
    }

    /// Run `secs` ticks with each receiver reporting `loss`.
    fn run(c: &mut Controller, from: f64, secs: usize, losses: &[f64]) -> (f64, Plan) {
        let mut plan = None;
        let mut t = from;
        for _ in 0..secs {
            for (i, &l) in losses.iter().enumerate() {
                c.report(i as u32, l, t);
            }
            plan = Some(c.tick(signals(t)));
            t += 1000.0;
        }
        (t, plan.unwrap())
    }

    fn total(p: Plan) -> u32 {
        p.audio.bps + p.video_bps
    }

    #[test]
    fn a_clean_link_sends_everything() {
        let mut c = Controller::default();
        let (_, p) = run(&mut c, 0.0, 5, &[0.0, 0.0]);
        assert_eq!(p.audio, AUDIO_RUNGS[0]);
        assert_eq!(p.video_bps, CAMERA.1);
        assert_eq!(p.why, Why::Ceiling);
    }

    #[test]
    fn loss_everyone_sees_cuts_and_clearing_grows_back() {
        let mut c = Controller::default();
        let (t, before) = run(&mut c, 0.0, 2, &[0.0, 0.0]);
        let (t, cut) = run(&mut c, t, 4, &[0.3, 0.25]);
        assert!(matches!(cut.why, Why::Loss(l) if (l - 0.25).abs() < 1e-9), "the least loss: {:?}", cut.why);
        // Four seconds of cutting by half the loss: 0.875⁴ ≈ 59%.
        assert!(total(cut) < total(before) * 60 / 100, "{} after 4 s at 25% loss, from {}", total(cut), total(before));
        assert_eq!(cut.audio, AUDIO_RUNGS[0], "voice is the last thing cut: video {}", cut.video_bps);
        // Clears: holds for the settling time, then grows back to the ceiling.
        let (t, held) = run(&mut c, t, 2, &[0.0, 0.0]);
        assert_eq!(total(held), total(cut), "nothing grows straight after a cut");
        let (_, grown) = run(&mut c, t, 40, &[0.0, 0.0]);
        assert_eq!(total(grown), total(before));
    }

    #[test]
    fn one_receivers_bad_downlink_does_not_cut_everyone() {
        let mut c = Controller::default();
        let (_, p) = run(&mut c, 0.0, 10, &[0.4, 0.0, 0.01]);
        assert_eq!(p.video_bps, CAMERA.1);
    }

    #[test]
    fn a_little_loss_holds() {
        let mut c = Controller::default();
        let (t, _) = run(&mut c, 0.0, 2, &[0.0]);
        let (t, cut) = run(&mut c, t, 1, &[0.2]);
        let (_, held) = run(&mut c, t, 10, &[0.05]);
        assert_eq!((total(held), held.why), (total(cut), Why::Holding));
    }

    #[test]
    fn voice_steps_down_only_once_video_is_at_its_floor() {
        let mut c = Controller::default();
        let (_, p) = run(&mut c, 0.0, 30, &[0.6]);
        assert_eq!(p.video_bps, CAMERA.0, "video at its floor");
        assert_eq!(p.audio, AUDIO_RUNGS[3], "and voice at its last rung");
        assert!(!p.audio.fullband);
        // Without video, voice alone takes the cuts.
        let mut alone = Controller::default();
        let mut s = Signals { video_min: 0, video_max: 0, ..signals(0.0) };
        alone.report(1, 0.0, 0.0);
        assert_eq!(alone.tick(s).audio, AUDIO_RUNGS[0]);
        for k in 1..5 {
            s.now_ms = k as f64 * 1000.0;
            alone.report(1, 0.5, s.now_ms);
            alone.tick(s);
        }
        assert_eq!(alone.plan().unwrap().audio, AUDIO_RUNGS[3]);
        assert_eq!(alone.plan().unwrap().video_bps, 0);
    }

    #[test]
    fn our_own_queue_overflowing_cuts_without_any_report() {
        let mut c = Controller::default();
        let first = c.tick(signals(0.0));
        let p = c.tick(Signals { dropped: 3, ..signals(1000.0) });
        assert_eq!(p.why, Why::Queue);
        assert!(total(p) < total(first));
        assert_ne!(c.tick(Signals { dropped: 3, ..signals(2000.0) }).why, Why::Queue, "only new drops count");
    }

    #[test]
    fn a_rising_round_trip_cuts_before_anything_is_lost() {
        let mut c = Controller::default();
        for k in 0..5 {
            c.tick(signals(k as f64 * 1000.0));
        }
        let p = c.tick(Signals { rtt_ms: Some(400.0), ..signals(5000.0) });
        assert_eq!(p.why, Why::Delay);
        // A route that is simply long is not a queue.
        let mut far = Controller::default();
        for k in 0..5 {
            assert_ne!(far.tick(Signals { rtt_ms: Some(300.0), ..signals(k as f64 * 1000.0) }).why, Why::Delay);
        }
    }

    #[test]
    fn turning_a_camera_on_starts_it_at_its_ceiling() {
        let mut c = Controller::default();
        let voice_only = Signals { video_min: 0, video_max: 0, ..signals(0.0) };
        c.tick(voice_only);
        let p = c.tick(signals(1000.0));
        assert_eq!(p.video_bps, CAMERA.1);
    }

    #[test]
    fn manual_is_manual_and_auto_resumes_from_it() {
        let mut c = Controller::default();
        c.set_mode(Mode::Manual { audio_bps: 24_000, video_bps: 200_000 });
        c.report(1, 0.5, 0.0);
        let p = c.tick(signals(0.0));
        assert_eq!(p, Plan { audio: AudioRate { bps: 24_000, fullband: false }, video_bps: 200_000, why: Why::Manual });
        c.set_mode(Mode::Auto);
        let p = c.tick(signals(1000.0));
        assert!(total(p) <= 224_000 * 109 / 100 + 4_000, "resumed from the manual setting, not the ceiling: {}", total(p));
    }

    #[test]
    fn reports_go_stale_and_leave_with_their_sender() {
        let mut c = Controller::default();
        c.report(1, 0.5, 0.0);
        assert_eq!(c.loss(1000.0), Some(0.5));
        assert_eq!(c.loss(10_000.0), None);
        c.report(2, 0.3, 10_000.0);
        c.left(2);
        assert_eq!(c.loss(10_000.0), None);
    }

    #[test]
    fn the_meter_counts_gaps() {
        let mut m = LossMeter::default();
        for seq in 0..50 {
            if seq % 10 != 3 {
                m.observe(7, seq);
            }
        }
        assert_eq!(m.window(), vec![(7, 100)]);
        for seq in 50..100 {
            m.observe(7, seq);
        }
        assert_eq!(m.window(), vec![(7, 0)], "a clean second after a lossy one");
    }

    #[test]
    fn the_meter_takes_reordering_and_late_packets_in_its_stride() {
        let mut m = LossMeter::default();
        for seq in [0, 2, 1, 4, 3, 5] {
            m.observe(1, seq);
        }
        assert_eq!(m.window(), vec![(1, 0)]);
        m.observe(1, 5); // a duplicate, from the last window
        for seq in 6..10 {
            m.observe(1, seq);
        }
        assert_eq!(m.window(), vec![(1, 0)]);
    }

    #[test]
    fn the_meter_wraps_resyncs_and_forgets() {
        let mut m = LossMeter::default();
        for seq in u32::MAX - 4..=u32::MAX {
            m.observe(1, seq);
        }
        for seq in 0..5 {
            m.observe(1, seq);
        }
        assert_eq!(m.window(), vec![(1, 0)], "across the wrap");
        m.observe(1, 1_000_000);
        m.observe(1, 1_000_001);
        assert_eq!(m.window(), vec![(1, 0)], "a restarted count is not loss");
        assert_eq!(m.window(), vec![(1, 1000)], "silent for a second after sending: all lost");
        assert_eq!(m.window(), vec![], "then just gone");
        m.observe(2, 0);
        m.left(2);
        assert_eq!(m.window(), vec![]);
    }

    #[test]
    fn a_throttle_steps_down_on_loss_and_back_up_once_clear() {
        let mut t = Throttle::default();
        assert_eq!(t.observe(0.0, 0.0), None);
        assert_eq!(t.observe(0.2, 2_000.0), Some(1));
        assert_eq!(t.observe(0.2, 3_000.0), None, "the last step has not had time to show");
        assert_eq!(t.observe(0.2, 4_000.0), Some(2));
        assert_eq!(t.observe(0.05, 6_000.0), None, "a little loss holds");
        let mut level = 2;
        let mut now = 7_000.0;
        while level > 0 && now < 60_000.0 {
            if let Some(l) = t.observe(0.0, now) {
                level = l;
            }
            now += 1_000.0;
        }
        assert_eq!(level, 0);
        assert!(now > 7_000.0 + 2.0 * THROTTLE_CLEAR_MS, "back up slowly: {now}");
    }

    #[test]
    fn a_download_that_takes_one_level_but_not_the_next_settles() {
        // A capped download: level 2 fits, level 1 does not. Each time the
        // throttle tries level 1 the loss comes straight back, and it waits
        // longer before trying again.
        let mut t = Throttle::default();
        let mut tries = Vec::new();
        let mut now = 0.0;
        while now < 300_000.0 {
            let loss = if t.level() < 2 { 0.3 } else { 0.0 };
            if t.observe(loss, now) == Some(1) {
                tries.push(now);
            }
            now += 1_000.0;
        }
        let gaps: Vec<f64> = tries.windows(2).map(|w| w[1] - w[0]).collect();
        assert!(gaps.windows(2).all(|g| g[1] >= g[0]), "tries at {tries:?}");
        assert!(tries.len() <= 8, "it kept trying: {tries:?}");
    }

    #[test]
    fn a_throttle_bottoms_out_at_voice_alone() {
        let mut t = Throttle::default();
        for k in 0..20 {
            t.observe(0.5, k as f64 * 2_000.0 + 2_000.0);
        }
        assert_eq!(t.level(), THROTTLE_MAX);
    }

    #[test]
    fn each_level_holds_back_one_more_thing() {
        let (camera, screen) = (0u8, 1u8);
        let voice = None;
        for level in 0..=THROTTLE_MAX {
            assert!(Throttle::forwards(level, voice), "voice always goes, at level {level}");
        }
        let goes = |level, track, layer| Throttle::forwards(level, Some((track, layer)));
        assert!(goes(0, camera, 2));
        assert!(!goes(1, camera, 2) && goes(1, camera, 1));
        assert!(!goes(2, camera, 1) && goes(2, camera, 0));
        assert!(!goes(3, camera, 0) && goes(3, screen, 0) && !goes(3, screen, 1));
        assert!(!goes(4, screen, 0));
    }

    #[test]
    fn download_loss_is_what_the_relay_did_not_already_see_lost() {
        // Sender 1's uplink loses 20%, which the receiver sees too; sender 2's
        // is clean, and the receiver loses 5% of it — its own link.
        let uplink = |s: u32| if s == 1 { 0.2 } else { 0.0 };
        assert!((downlink_loss(&[(1, 250), (2, 50)], uplink).unwrap() - 0.05).abs() < 1e-9);
        // Hearing only the lossy sender: none of it is the receiver's.
        assert!(downlink_loss(&[(1, 210)], uplink).unwrap() < 0.02);
        assert_eq!(downlink_loss(&[], uplink), None);
        // A full download: the camera's stream loses half, the voice-only
        // one nothing. The link is full.
        assert!((downlink_loss(&[(1, 700), (2, 0)], uplink).unwrap() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn the_meter_counts_lost_video_pieces() {
        let mut m = LossMeter::default();
        for f in 0..10 {
            m.observe(1, f);
        }
        // Ten frames of four pieces; frames 2 and 5 lose two pieces each.
        for f in 0..10u32 {
            for i in 0..4u8 {
                if (f == 2 || f == 5) && i < 2 {
                    continue;
                }
                m.observe_video(1, 0, f, 4);
            }
        }
        // Seven frames settled (0..=6): 28 pieces, 4 lost.
        assert_eq!(m.window(), vec![(1, 142)], "the worse of the audio (none lost) and the video");
    }

    #[test]
    fn video_tracks_are_counted_apart_and_dropped_frames_are_not_loss() {
        let mut m = LossMeter::default();
        // A camera and a screen share, numbering their frames independently;
        // the screen's odd frames held back by a relay, never seen at all.
        for f in 0..12u32 {
            m.observe_video(2, 0, f, 1);
            if f % 2 == 0 {
                m.observe_video(2, 1, f, 1);
            }
        }
        assert_eq!(m.window(), vec![(2, 0)]);
        m.left(2);
        assert_eq!(m.window(), vec![]);
    }
}
