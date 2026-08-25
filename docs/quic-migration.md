# Moving voice off TCP

Status: **calls run on QUIC datagrams, browser to relay, in both directions.**
The WebSocket is the fallback for networks where UDP does not get through, and
it is chosen by dialling rather than by guessing. What is missing is the piece
an unreliable transport makes mandatory and a reliable one hid: a jitter buffer
on the receive path.

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
| `jitter` | adaptive jitter buffer + PLC, dependency-free | 14 |
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

1. **A jitter buffer on the receive path.** This is now the gap rather than a
   future one. The receive loop still decodes each packet as it arrives and
   writes it straight to the sink, which was correct on a transport that could
   not reorder or lose anything, and is not correct on this one. `jitter` is
   the piece — holding encoded packets, so loss goes to the decoder that has
   the signal model.

2. **Certificate rotation.** A node mints a certificate at startup, valid
   thirteen days, and browsers will not pin one for longer. A node up for a
   fortnight stops admitting new callers. The ticket response is the obvious
   carrier for a fresh hash.

3. **WebTransport cannot be reverse-proxied.** The gateway exists so nodes need
   not be publicly addressable; a QUIC session terminates at whoever holds the
   certificate, so it cannot. `/_voice/node/{id}/webtransport` passes the node's
   own address through unchanged, and a deployment unwilling to expose nodes
   keeps its calls on the WebSocket. This is a deployment decision, not a bug,
   but it is not the shape the gateway was designed around.

4. **Safari.** Still unverified.

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
