# Moving voice off TCP

Status: **a relay serves calls over WebTransport, and a browser reaches it.
Audio still travels on the WebSocket.** The last step is the client carrying
its packets over the session it already opens.

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

1. **The client has to carry audio over the session it already opens.** It
   dials WebTransport at join, proves it works, closes it, and then makes the
   call on the WebSocket. Everything either side of that is done: the packets
   fit a datagram, the relay serves both transports through one `serve`, and
   the browser can open an authenticated session. What remains is the publish
   half — `SharedSender` is a `WsSender`, and the capture callback is
   synchronous while `Link::send` is not.

2. **A jitter buffer on the receive path.** Not needed today and that is the
   point: a reliable ordered transport has nothing to reorder. The moment audio
   moves to datagrams it does, and `jitter` is the piece — holding encoded
   packets, so loss goes to the decoder that has the signal model.

3. **Certificate rotation.** A node mints a certificate at startup, valid
   thirteen days, and browsers will not pin one for longer. A node up for a
   fortnight stops admitting new callers. The ticket response is the obvious
   carrier for a fresh hash.

4. **WebTransport cannot be reverse-proxied.** The gateway exists so nodes need
   not be publicly addressable; a QUIC session terminates at whoever holds the
   certificate, so it cannot. `/_voice/node/{id}/webtransport` passes the node's
   own address through unchanged, and a deployment unwilling to expose nodes
   keeps its calls on the WebSocket. This is a deployment decision, not a bug,
   but it is not the shape the gateway was designed around.

5. **Safari.** Still unverified.

## What is proven, and how

| claim | where |
| --- | --- |
| a call relays over QUIC, decoded back to what was said | `voice-server/tests/quic_relay.rs` — correlation 0.83 |
| a talker does not hear themselves over the new carrier | same test |
| raw PCM could never have fitted | same test: the measured datagram limit is 1413 bytes against 1952 |
| a **browser** opens an authenticated session against a pinned self-signed certificate | `tools/voice-flows.js` |
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
  them apart — which is why the client's reachability probe carries the room's
  ticket, and why the node answers a `probe=1` session on the control stream
  instead of just closing it. An unauthenticated probe reports every
  ticket-checking node as unreachable.
- **A pinned certificate valid for too long fails the same way.** `rcgen`
  defaults to the year 4096; browsers refuse anything over about fourteen days,
  and say so as "Opening handshake failed" — naming neither certificates nor
  validity. `datagram::host::VALID_DAYS` is thirteen, with a test.

## A trap that cost an hour

`localhost` resolves to `::1` before `127.0.0.1` on this machine, so a client
dialling it against a v4-bound listener simply times out — indistinguishable
from a broken handshake or a certificate problem. Bind and dial the same
literal address.
