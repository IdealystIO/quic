# Moving voice off TCP

Status: **the pieces exist and are proven together; the web build can now
reach WebTransport; nothing is wired into the app yet.** The WebSocket path is
untouched and still carries every call.

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

1. **`voice-server`: a WebTransport listener beside the WebSocket one.**
   `datagram::Listener` is the piece; the relay's room fan-out is transport
   agnostic already.
2. **`voice-client`: choose a transport.** Two implementations behind one seam,
   with WebSocket as the fallback that is kept rather than removed — UDP is not
   universally reachable.
3. **20 ms packetisation.** `Off` mode still emits one packet per 85 ms capture
   block. That is 8160 bytes and *cannot* be a datagram at any tuning.
4. ~~**`--cfg=web_sys_unstable_apis` has to reach `idealyst build --web`.**~~
   **Done.** It does, from `.cargo/config.toml`, and the app carries it there.
   Getting it there cost two fixes in idealyst — see
   [findings 15 and 16](hearth-framework-findings.md#15-idealyst-build---web-silently-discards-cargoconfigtoml-rustflags):
   the web builder was dropping config rustflags without saying so, and the flag
   *switches* eleven unrelated web-sys signatures rather than adding bindings.
   Requires idealyst CLI **1.3.16** or later; on 1.3.15 the flag has to be an
   environment variable or it is silently discarded.
5. **Certificate rotation.** Browsers cap a pinned self-signed certificate at
   ~two weeks, so a self-hosted instance needs rotation and a way to hand
   clients the new hash. The ticket response is the obvious carrier.

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

## A trap that cost an hour

`localhost` resolves to `::1` before `127.0.0.1` on this machine, so a client
dialling it against a v4-bound listener simply times out — indistinguishable
from a broken handshake or a certificate problem. Bind and dial the same
literal address.
