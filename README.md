# quic

Real-time media over QUIC: a link that carries media as unreliable
datagrams and control as reliable streams, the wire format on it, and a relay
that forwards a room's datagrams to everyone else in it. No framework
dependency: the clients run natively (quinn) and in a browser (WebTransport),
and everything tests natively.

The media built on it (video, audio, a call's session) is
[IdealystIO/quic-media](https://github.com/IdealystIO/quic-media). Split out
of [idea-chat](https://github.com/IdealystIO/idea-chat), with its history.

| Crate | What it is |
|---|---|
| `quic-link` | The link: QUIC datagrams for media, one stream per control message, self-signed certificates a browser can pin |
| `quic-proto` | The wire format: audio and video datagrams, and what the relay adds and says |
| `quic-relay` | The relay: rooms, forwarding, grants checked at the door, throttling. A library and the `quic-relay` binary |
| `quic-auth` | Who may send what: grants an issuer signs, revocations, the gate a relay checks |
| `quic-e2ee` | SFrame (RFC 9605) end-to-end encryption, so the relay forwards what it cannot read |
| `quic-bitrate` | Bitrate control: loss measured by receivers, a sender's budget, its split between voice and video |

`docs/quic-migration.md` is why this replaced a WebSocket, and what moving
over took.

## Using it

Published to the idealyst registry:

```toml
quic-link = { version = "0.1", registry = "idealyst" }
```

**A browser build needs one flag of its own.** `web-sys` gates its
WebTransport bindings behind `--cfg=web_sys_unstable_apis`, and a dependency
cannot set it for you. In the app's `.cargo/config.toml`:

```toml
[target.wasm32-unknown-unknown]
rustflags = ["--cfg=web_sys_unstable_apis"]
```

`idealyst build --web` does not read that section (it sets
`CARGO_ENCODED_RUSTFLAGS`), so pass it there as
`RUSTFLAGS=--cfg=web_sys_unstable_apis idealyst build --web`.

## The relay

```bash
cargo run -p quic-relay -- 0.0.0.0:4433 --cert fullchain.pem --key privkey.pem --secret-file relay.secret
cargo run -p quic-relay -- mint --secret-file relay.secret --room ROOM --user USER --send avs
```

Without `--cert`/`--key` it makes a self-signed certificate and prints the
hash clients pin, a new one on every start. Without `--secret-file` anyone
may join any room. `crates/quic-relay/src/main.rs` lists every flag.

## Checks

```bash
cargo test --workspace
cargo check --target wasm32-unknown-unknown -p quic-link -p quic-proto -p quic-auth -p quic-e2ee -p quic-bitrate
```
