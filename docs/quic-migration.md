# Moving voice off TCP

Status: **calls run on QUIC datagrams, browser to relay, in both directions,
through a jitter buffer.** The WebSocket is the fallback for networks where UDP
does not get through, and it is chosen by dialling rather than by guessing.

The migration is done. What is left is deployment work — certificate rotation,
what a gateway can and cannot proxy — and one measurement that came out worse
than expected, recorded below.

## Why

TCP guarantees delivery, ordering, and exactly-once. For speech all three are
the wrong guarantee. A lost audio packet is retransmitted and arrives ~100 ms
late, by which point playback has moved past it — so it is worthless *and* it
blocked every fresh packet behind it while in flight. One loss becomes a
multi-hundred-millisecond gap. That is head-of-line blocking, and it is TCP
working correctly.

Two things this does **not** fix, stated up front because the measurement came
first (see [noise-suppression.md](noise-suppression.md#chain-latency)):

- **It does not reduce the latency floor.** ~171 ms of that is buffering in the
  capture and playback blocks, and the transport contributes ~0 on loopback.
  QUIC moves the 99th percentile under loss, not the median.
- **It is not what makes calls sound better today.** The codec and the jitter
  buffer are; the transport is what makes them necessary.

## What exists

| crate | what it is | tests |
| --- | --- | --- |
| `jitter` | adaptive jitter buffer, PLC, and the playout clock, dependency-free | 21 |
| `audio-codec` | Opus encode/decode, pure Rust | 8 |
| `datagram` | QUIC link: datagrams for media, streams for control | 4 |

All three build for `wasm32-unknown-unknown` and for the host.

`datagram/tests/call.rs` runs the whole chain over a real QUIC connection on
loopback — Opus encode, datagrams across a socket, jitter buffer, Opus decode —
with one packet in nine deliberately never sent:

```
Stats { received: 80, late: 0, duplicate: 0, reordered: 26,
        concealed: 10, starved: 40, drift_events: 0 }
played 130 frames, rms 0.0876
```

80 of 90 is the deliberate loss. 26 reordered is the network genuinely
delivering out of order and the buffer fixing it. 10 concealed is exactly the
ten holes. 0 late means the buffer was deep enough. The starves are the playout
clock running past the end of the sender — the fixture, not the code.

## What is left

1. **Certificate rotation.** A node mints a certificate at startup, valid
   thirteen days, and browsers will not pin one for longer. A node up for a
   fortnight stops admitting new callers. The ticket response is the obvious
   carrier for a fresh hash.

2. **WebTransport cannot be reverse-proxied.** The gateway exists so nodes need
   not be publicly addressable; a QUIC session terminates at whoever holds the
   certificate, so it cannot. `/_voice/node/{id}/webtransport` passes the node's
   own address through unchanged, and a deployment unwilling to expose nodes
   keeps its calls on the WebSocket. This is a deployment decision, not a bug,
   but it is not the shape the gateway was designed around.

3. **Safari.** Still unverified.

## What is proven, and how

| claim | where |
| --- | --- |
| a call relays over QUIC, decoded back to what was said | `voice-server/tests/quic_relay.rs` — correlation 0.83 |
| a talker does not hear themselves over the new carrier | same test |
| raw PCM could never have fitted | same test: the measured datagram limit is 1413 bytes against 1952 |
| two **browsers** hold a call over QUIC datagrams, each hearing the other | `tools/voice-flows.js` — 712 packets each way, both meters live |
| against a pinned self-signed certificate, with a room ticket | same test, on a fleet that refuses unticketed joins |
| the send queue does not quietly overflow | same test — `unsent` is asserted zero, and it is the only thing that would distinguish a stalled publish path from a quiet room |
| Opus is actually on the wire, not silently fallen back | `tools/voice-flows.js` — 94 bytes a packet, 38 kbps |
| the jitter buffer is in the receive path, not bypassed | `tools/voice-flows.js` — it is carrying delay, and inventing nothing on a link with no loss |
| a mixed-encoding stream decodes correctly | `voice-proto/src/codec.rs` — the raw frame inside an Opus stream comes back lossless |
| loss goes to the codec, not to a repeater | same file — an Opus stream conceals with signal, not silence |
| how much delay a bursty sender costs | `jitter/src/lib.rs` — 20.0 ms evenly paced against 46.5 ms in bursts of four |

## How playout is clocked, with no clock to use

A jitter buffer is *pulled* on a playout clock. This platform has nothing to run
one on: `runtime_core` has no sleep, and `requestAnimationFrame` and
`setInterval` are both throttled to roughly once a second in a background tab —
which is exactly when a call has to keep working.

So **the arrival is the trigger and the clock is the pacer**. Each packet that
comes in pulls however many frames real time has moved on by
(`jitter::Clock`), and the sink's own ring buffer downstream absorbs the
burstiness. That ring was standing in for a jitter buffer before this; it is now
doing the job it is actually good at.

Two consequences worth stating:

- **When nothing arrives, nothing is produced.** A talker who stops mid-word
  gets concealment on the packets that follow the gap, and silence — not a
  concealed drone — for a stall with no end. For a talker who simply stopped,
  silence is the right answer.
- **The backlog is capped.** Real time keeps running while a tab is
  backgrounded, so the first packet after a resume would otherwise ask for every
  frame the clock says is owed. Ten frames is the ceiling, and hitting it
  resynchronises the clock rather than carrying the debt — a clock that stayed
  behind would return the cap on every call forever.

## Decisions worth not re-litigating

**Why WebTransport and not raw QUIC.** Browsers cannot open QUIC sockets.
WebTransport is the reachable form. `web-transport` 0.12 switches between quinn
and the browser's implementation by `#[path]`, so one source file serves both —
this was going to be the hard part and it is a dependency.

**Why WebTransport and not WebRTC.** WebRTC hands you the whole media stack —
jitter buffer, PLC, FEC, congestion control, Opus — already built and in every
browser including Safari. WebTransport hands you a pipe and the bill for all of
it. Taken deliberately: we are building that stack anyway, and the point of this
project is to find out where idealyst hurts. **Bandwidth estimation is the item
on that bill still unpaid** and the one people underestimate.

**Why the jitter buffer holds encoded packets.** Loss goes to whoever still has
the signal model. Opus resynthesises a plausible continuation; a PCM concealer
can only repeat what it heard. It also keeps `jitter` dependency-free — the
buffer never learns what a packet contains.

**Why a tag byte in front of the buffered payload.** Because a stream is not
necessarily all one encoding: a single failed Opus frame goes out raw, by
design, since a hole in the audio is worse than a large packet. The buffer
stores payloads it does not understand, so the encoding has to travel with them
— one byte, never on the wire, written and read in `codec::Playout` and nowhere
else. It also means a buffered payload is never empty, which matters because an
empty payload is how `jitter::Decode` spells "missing": a DTX frame saying
"still here, nothing to say" must not be mistaken for a gap.

**Why `rusty-opus` over the more active `opus-rs`.** Measured, not preferred:
`opus-rs` exposes no decoder-side concealment at all (`decode(&[])` errors), no
`decode_fec`, and no DTX. The in-band FEC bug reproduces *identically in both*,
so it is upstream's and switching does not fix it — and only `rusty-opus` has
the receiving half that a fix would make usable. The choice is one file.

## Known gaps

- **In-band FEC is off.** The encoder emits packets its own decoder mishandles
  once FEC is active — `fec` plus any non-zero `packet_loss_perc` drops
  correlation from 0.90 to 0.04 and clips. Reproduces in `rusty-opus` 0.9.1 and
  in `opus-rs` 0.1.32. Pinned by `fec_is_still_broken_upstream`, so a fix trips
  a test. Worth reporting upstream; reproduces in about twenty lines. This costs
  real quality on a lossy link — FEC *recovers* an isolated loss where PLC only
  conceals it.
- **The capture block is paid for twice, and the second charge is the bigger
  surprise.** Capture arrives 85 ms at a time and is cut into four 20 ms packets
  that go out together. A receiver cannot tell a burst it was sent from a burst
  the network made, so it sizes its buffer for it: measured in `jitter`'s own
  tests, an evenly paced sender settles at 20.0 ms of delay and bursts of four
  settle at 46.5 ms, and in the browser the buffer peaked near 100 ms. That is
  on top of the ~171 ms floor. There is no fix on this side — pacing the packets
  out needs a timer the runtime does not have — so it is recorded as framework
  finding 10c, where it makes a configurable block size the highest-leverage
  number in the audio stack rather than a nice-to-have.
- **No clock-drift correction.** `jitter` does not resample, so it cannot
  correct a few hundred ppm between two machines. Over a long call that drains
  the buffer or grows it. `Stats::drift_events` counts the symptom so the
  absence is visible rather than mysterious. The honest fix is a fractional
  resampler driven by buffer depth.
- **`web-transport` 0.12 does not forward `max_datagram_size` on wasm.** The
  backend exposes it and the browser has it, but the facade keeps the inner
  session private. Falls back to a 1200-byte floor, which never binds at ~60
  bytes a frame.
- **Safari.** Unverified, and historically the blocker for WebTransport. Check
  before promising it.
- **A refused ticket and a blocked UDP port look identical from a browser.**
  Both are `WebTransportError: Opening handshake failed`, with nothing to tell
  them apart — which is why the dial carries the room's ticket like the
  WebSocket does, from the same `carrier::Join::query`. An unauthenticated dial
  would report every ticket-checking node as unreachable.
- **Falling back costs about ten seconds on a network that blocks UDP.** A QUIC
  handshake nothing answers does not fail fast; the browser retries until its
  own timeout. Racing the dial against a sleep would fix it, and there is no
  timer in `runtime_core` to race it with — so this is a framework gap wearing a
  voice costume. The call does connect, just not promptly.
- **A client that cannot encode cannot use datagrams.** `Encoded::open` falls
  back to raw PCM at a sample rate Opus will not take (44.1 kHz is real
  hardware), and 20 ms of raw PCM does not fit a datagram at any tuning. The
  encoding is chosen from the first capture block, which arrives *after* the
  transport is chosen, so today that call is silent outward with `unsent`
  climbing and one console line saying why. The honest fix is to reopen on the
  WebSocket when the codec falls back.
- **A redirect re-runs the whole transport choice.** Each node publishes its own
  UDP port and its own certificate, so there is nothing about the old session to
  reuse — `connect` asks the new node from scratch, and a node that offers no
  WebTransport moves that call to the WebSocket mid-hop. Correct, but it means a
  handover can change the carrier, which the counters show and nothing else
  does.
- **A pinned certificate valid for too long fails the same way.** `rcgen`
  defaults to the year 4096; browsers refuse anything over about fourteen days,
  and say so as "Opening handshake failed" — naming neither certificates nor
  validity. `datagram::host::VALID_DAYS` is thirteen, with a test.

## A trap that cost an hour

`localhost` resolves to `::1` before `127.0.0.1` on this machine, so a client
dialling it against a v4-bound listener simply times out — indistinguishable
from a broken handshake or a certificate problem. Bind and dial the same
literal address.
