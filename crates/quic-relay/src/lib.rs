//! The quic-call relay. Clients connect into a room; every datagram and
//! control message one sends is forwarded to the rest of that room, tagged
//! with the sender's number, in `call_proto::relay`'s terms. It reads nothing
//! of a datagram past its first two bytes — no codec, no media — unless it is
//! throttling.
//!
//! With [`Config::throttle`], it also looks after each receiver's download:
//! it counts what arrives from each sender (audio sequence numbers, readable
//! through end-to-end encryption), reads the loss reports clients send each
//! other, and from the difference judges what each receiver's own link loses.
//! A receiver whose download is losing gets less — video layers held back,
//! then cameras, then all video — and is told so; see `call_rate::Throttle`.
//! That costs the relay a header read per datagram per receiver and a little
//! state per client, which is why it is an option.
//!
//! With [`Auth`], it is also where `call-auth` is enforced: a grant to get in,
//! checked once per connection; then, per datagram, whether the sender's
//! grant still allows that kind of media; renewals; revocations applied to
//! whoever is connected the moment they arrive. Without, anyone may connect to
//! any room — for a demo on a trusted network.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use call_auth::{Gate, Grant, Outcome};
use call_proto::relay::{tag, Connect, FromRelay, KeyRequest, LossReport, ToRelay};
use datagram::{Event, Link, Listener, Request};

/// Checking grants: the issuer's secret, and the longest grant to accept —
/// which is also how long a revocation is remembered.
pub struct Auth {
    pub secret: Vec<u8>,
    pub max_ttl: Duration,
}

pub struct Config {
    /// `None`: anyone may connect, to any room.
    pub auth: Option<Auth>,
    /// How long a connection whose grant has run out is kept, unable to send,
    /// for a late renewal before it is closed.
    pub grace: Duration,
    /// Drop this share (0–1) of forwarded datagrams at random — a lossy link
    /// on demand, for watching clients' bitrate control respond. 0 in
    /// anything real.
    pub loss: f64,
    /// Forward at most this many bits a second to each client, dropping what
    /// does not fit — a slow download on demand, which unlike random loss is
    /// what sending less fixes. For testing; `None` in anything real.
    pub cap_bps: Option<u32>,
    /// Apply [`Config::loss`] and [`Config::cap_bps`] only to what is
    /// forwarded to this client — one bad download, for watching throttling.
    pub loss_to: Option<u32>,
    /// Hold back video from receivers whose download cannot take it all; see
    /// the module docs.
    pub throttle: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config { auth: None, grace: Duration::from_secs(15), loss: 0.0, cap_bps: None, loss_to: None, throttle: false }
    }
}

/// The least time between keyframe requests forwarded from a throttled
/// receiver: each one makes the sender send its biggest frame to everyone.
const THROTTLED_KEY_GAP_MS: u64 = 2_000;

struct Peer {
    room: String,
    link: Link,
    /// `None` on a relay without auth.
    grant: Option<Grant>,
    /// Whether it has been told its grant ran out.
    told_expired: bool,
    /// What is held back from it, when throttling.
    throttle: call_rate::Throttle,
    /// When a keyframe request from it was last forwarded.
    last_key: u64,
    /// For [`Config::cap_bps`]: bytes it may still be sent, and when that
    /// was last topped up.
    allowance: f64,
    topped_up: std::time::Instant,
}

#[derive(Default)]
struct State {
    peers: HashMap<u32, Peer>,
    gate: Option<Gate>,
    next_id: u32,
    /// See [`Config::loss`].
    loss: f64,
    loss_to: Option<u32>,
    cap_bps: Option<u32>,
    throttle: bool,
    /// What arrives from each sender, counted when throttling; and the loss
    /// that came to over the last second, by sender.
    arrivals: call_rate::LossMeter,
    uplink: HashMap<u32, f64>,
}

type Shared = Arc<Mutex<State>>;

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Serve until the listener closes.
pub async fn serve(listener: Listener, config: Config) {
    let (handle, grace) = Handle::new(config);
    run(listener, handle.0, grace).await
}

/// Serve in the background, and keep a [`Handle`] to the running relay — for
/// an issuer living in the same process, which can then apply revocations
/// directly rather than dialling itself.
pub fn spawn(listener: Listener, config: Config) -> Handle {
    let (handle, grace) = Handle::new(config);
    tokio::spawn(run(listener, handle.0.clone(), grace));
    handle
}

async fn run(mut listener: Listener, state: Shared, grace: Duration) {
    tokio::spawn(expire(state.clone(), grace));
    if state.lock().unwrap().throttle {
        tokio::spawn(count_arrivals(state.clone()));
    }
    while let Some(request) = listener.accept().await {
        tokio::spawn(admit(state.clone(), request));
    }
}

/// A running relay, from the process that started it.
#[derive(Clone)]
pub struct Handle(Shared);

impl Handle {
    fn new(config: Config) -> (Handle, Duration) {
        let state = State {
            gate: config.auth.map(|a| Gate::new(a.secret, a.max_ttl.as_millis() as u64)),
            next_id: 1,
            loss: config.loss.clamp(0.0, 1.0),
            loss_to: config.loss_to,
            cap_bps: config.cap_bps,
            throttle: config.throttle,
            ..Default::default()
        };
        (Handle(Arc::new(Mutex::new(state))), config.grace)
    }

    /// Apply a signed revocation, exactly as one delivered with `?revoke=`
    /// would be: kicked clients are told and closed, limited ones told and
    /// filtered, and the voided grants refused from now on. Returns how many
    /// connected clients it touched.
    pub async fn revoke(&self, token: &str) -> Result<usize, call_auth::Refusal> {
        let (hit, gone) = apply(&self.0, token)?;
        let touched = hit.len();
        notify(hit, gone).await;
        Ok(touched)
    }

    /// How many clients are connected, across rooms.
    pub fn connected(&self) -> usize {
        self.0.lock().unwrap().peers.len()
    }
}

type Hit = (Vec<(u32, Link, Outcome)>, Vec<(u32, Vec<Link>)>);

/// Check a revocation and apply it to the relay's state. Who to tell comes
/// back, for sending outside the lock.
fn apply(state: &Shared, token: &str) -> Result<Hit, call_auth::Refusal> {
    let mut st = state.lock().unwrap();
    let st = &mut *st;
    let gate = st.gate.as_mut().ok_or(call_auth::Refusal::Malformed)?;
    let r = gate.revoke(token, now_ms())?;
    let mut hit = Vec::new();
    for (&id, peer) in st.peers.iter_mut() {
        let Some(grant) = peer.grant.as_mut() else { continue };
        match Gate::apply(&r, grant) {
            Outcome::Untouched => {}
            outcome => hit.push((id, peer.link.clone(), outcome)),
        }
    }
    println!("[relay] revocation {:?} for {} in {:?}: {} connected affected", r.action, r.user, r.room, hit.len());
    // Out of the room this instant, so nothing more is forwarded either way;
    // told and closed just after. The room hears they left now — by the time
    // their connection ends they are no longer in it to announce.
    let mut gone = Vec::new();
    for (id, _, outcome) in &hit {
        if *outcome == Outcome::Kicked {
            gone.push((*id, room_of(st, *id)));
            st.peers.remove(id);
        }
    }
    Ok((hit, gone))
}

async fn notify(hit: Vec<(u32, Link, Outcome)>, gone: Vec<(u32, Vec<Link>)>) {
    for (id, room) in gone {
        let left = FromRelay::Left(id).to_text();
        for other in room {
            let _ = other.control(&left).await;
        }
    }
    for (id, link, outcome) in hit {
        match outcome {
            Outcome::Kicked => {
                println!("[relay] #{id} revoked");
                let _ = link.control(&FromRelay::Revoked.to_text()).await;
                // A close in the same instant can beat the message out.
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    link.close(403, "revoked");
                });
            }
            Outcome::Limited(send) => {
                let _ = link.control(&FromRelay::MaySend(send.to_code()).to_text()).await;
            }
            Outcome::Untouched => {}
        }
    }
}

/// The room's other members, for sending to outside the lock.
impl Peer {
    /// For [`Config::cap_bps`]: whether `bytes` more fit its download now,
    /// taking them if so. A second's worth may queue, as in a router's buffer
    /// — enough for a keyframe to get through whole.
    fn afford(&mut self, bps: u32, bytes: usize) -> bool {
        let per_sec = bps as f64 / 8.0;
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.topped_up).as_secs_f64();
        self.topped_up = now;
        self.allowance = (self.allowance + elapsed * per_sec).min(per_sec);
        if self.allowance >= bytes as f64 {
            self.allowance -= bytes as f64;
            true
        } else {
            false
        }
    }
}

/// Once a second: what each sender lost on the way in, for judging receivers'
/// downloads against.
async fn count_arrivals(state: Shared) {
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let mut st = state.lock().unwrap();
        let window = st.arrivals.window();
        st.uplink = window.into_iter().map(|(id, permille)| (id, permille as f64 / 1000.0)).collect();
    }
}

fn room_of(state: &State, id: u32) -> Vec<Link> {
    let Some(room) = state.peers.get(&id).map(|p| p.room.as_str()) else { return Vec::new() };
    state.peers.iter().filter(|(other, p)| **other != id && p.room == room).map(|(_, p)| p.link.clone()).collect()
}

async fn admit(state: Shared, request: Request) {
    let from = request.remote_addr();
    let connect = Connect::parse(&request.url());
    if let Some(token) = connect.revoke {
        return revoke(state, request, &token).await;
    }
    let grant = {
        let st = state.lock().unwrap();
        match (&st.gate, &connect.grant) {
            (None, _) => Ok(None),
            (Some(_), None) => Err((401, "no grant".to_string())),
            (Some(gate), Some(token)) => gate
                .admit(&connect.room, token, now_ms())
                .map(Some)
                .map_err(|e| (403, e.to_string())),
        }
    };
    let grant = match grant {
        Ok(g) => g,
        Err((status, why)) => {
            println!("[relay] {from}: refused ({why})");
            return request.refuse(status).await;
        }
    };
    let link = match request.accept().await {
        Ok(link) => link,
        Err(e) => return eprintln!("[relay] {from}: {e}"),
    };

    // In, numbered, and introduced.
    let (id, others, names) = {
        let mut st = state.lock().unwrap();
        let id = st.next_id;
        st.next_id += 1;
        st.peers.insert(
            id,
            Peer {
                room: connect.room.clone(),
                link: link.clone(),
                grant: grant.clone(),
                told_expired: false,
                throttle: Default::default(),
                last_key: 0,
                allowance: 0.0,
                topped_up: std::time::Instant::now(),
            },
        );
        let names: Vec<(u32, String)> = st
            .peers
            .iter()
            .filter(|(_, p)| p.room == connect.room)
            .filter_map(|(&i, p)| p.grant.as_ref().map(|g| (i, g.user.clone())))
            .collect();
        (id, room_of(&st, id), names)
    };
    let who = grant.as_ref().map(|g| format!(" as {} (sends {})", g.user, g.send.to_code())).unwrap_or_default();
    println!("[relay] #{id} joined room {:?} from {from}{who}", connect.room);
    let _ = link.control(&FromRelay::You(id).to_text()).await;
    let joined = FromRelay::Joined(id).to_text();
    for other in &others {
        let _ = other.control(&joined).await;
    }
    for (other, user) in &names {
        let _ = link.control(&FromRelay::Named { id: *other, user: user.clone() }.to_text()).await;
    }
    if let Some(g) = &grant {
        let _ = link.control(&expires(g)).await;
        let named = FromRelay::Named { id, user: g.user.clone() }.to_text();
        for other in &others {
            let _ = other.control(&named).await;
        }
    }
    serve_peer(state, id, link).await;
}

fn expires(g: &Grant) -> String {
    FromRelay::Expires { secs: g.expires_ms.saturating_sub(now_ms()) / 1000 }.to_text()
}

async fn serve_peer(state: Shared, id: u32, link: Link) {
    // Counted and reported every few seconds rather than logged one by one: a
    // voice call is fifty datagrams a second per person.
    let (mut count, mut dropped, mut since) = (0u64, 0u64, std::time::Instant::now());
    // For `Config::loss`: a cheap generator, seeded per connection.
    let mut dice = (id as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut roll = move || {
        dice ^= dice << 13;
        dice ^= dice >> 7;
        dice ^= dice << 17;
        (dice >> 11) as f64 / (1u64 << 53) as f64
    };
    loop {
        let event = link.recv().await;
        if since.elapsed() >= Duration::from_secs(5) && count + dropped > 0 {
            println!("[relay] #{id}: {count} datagrams forwarded, {dropped} dropped in the last {:.0?}", since.elapsed());
            (count, dropped, since) = (0, 0, std::time::Instant::now());
        }
        match event {
            Event::Data(bytes) => {
                // The one check per datagram: may this connection send this?
                // Then, per receiver, whether it goes to them.
                let out = tag(id, &bytes);
                let targets = {
                    let mut st = state.lock().unwrap();
                    let st = &mut *st;
                    let Some(peer) = st.peers.get(&id) else { break };
                    let allowed = match &peer.grant {
                        None => true,
                        Some(g) => call_proto::media(&bytes).is_some_and(|m| g.may_send(m, now_ms())),
                    };
                    if !allowed {
                        None
                    } else {
                        if st.throttle {
                            if let Some((call_proto::TRACK_MAIN, seq)) = call_proto::audio::seq_of(&bytes) {
                                st.arrivals.observe(id, seq);
                            } else if let Some((track, frame, count)) = call_proto::video::pieces_of(&bytes) {
                                st.arrivals.observe_video(id, track, frame, count);
                            }
                        }
                        let video = call_proto::video::layer_of(&bytes);
                        let room = st.peers[&id].room.clone();
                        let (throttle, loss, loss_to, cap) = (st.throttle, st.loss, st.loss_to, st.cap_bps);
                        let mut targets = Vec::new();
                        for (&other, p) in st.peers.iter_mut() {
                            if other == id || p.room != room {
                                continue;
                            }
                            if throttle && !call_rate::Throttle::forwards(p.throttle.level(), video) {
                                continue;
                            }
                            let simulated = loss_to.is_none_or(|t| t == other);
                            if simulated && loss > 0.0 && roll() < loss {
                                continue;
                            }
                            if simulated && cap.is_some_and(|bps| !p.afford(bps, out.len())) {
                                continue;
                            }
                            targets.push(p.link.clone());
                        }
                        Some(targets)
                    }
                };
                let Some(targets) = targets else {
                    dropped += 1;
                    continue;
                };
                count += 1;
                for link in targets {
                    let _ = link.send(&out).await;
                }
            }
            Event::Control(text) => match ToRelay::parse(&text) {
                ToRelay::Renew(token) => {
                    let reply = {
                        let mut st = state.lock().unwrap();
                        let st = &mut *st;
                        match (st.gate.as_ref(), st.peers.get_mut(&id)) {
                            (Some(gate), Some(peer)) => match peer.grant.as_ref().map(|g| gate.renew(g, &token, now_ms())) {
                                Some(Ok(next)) => {
                                    let reply = expires(&next);
                                    peer.grant = Some(next);
                                    peer.told_expired = false;
                                    reply
                                }
                                Some(Err(e)) => FromRelay::Refused(e.to_string()).to_text(),
                                None => FromRelay::Refused("no grant to renew".into()).to_text(),
                            },
                            _ => FromRelay::Refused("this relay takes no grants".into()).to_text(),
                        }
                    };
                    let _ = link.control(&reply).await;
                }
                ToRelay::Ping(n) => {
                    let _ = link.control(&FromRelay::Pong(n).to_text()).await;
                }
                ToRelay::Say(text) => {
                    if !judge(&state, id, &link, &text).await {
                        continue;
                    }
                    let others = room_of(&state.lock().unwrap(), id);
                    let said = FromRelay::Said { from: id, text }.to_text();
                    for other in others {
                        let _ = other.control(&said).await;
                    }
                }
            },
            Event::Closed => break,
        }
    }
    let others = {
        let mut st = state.lock().unwrap();
        let others = room_of(&st, id);
        st.peers.remove(&id);
        st.arrivals.left(id);
        st.uplink.remove(&id);
        others
    };
    let left = FromRelay::Left(id).to_text();
    for other in others {
        let _ = other.control(&left).await;
    }
    println!("[relay] #{id} left");
}

/// What a throttling relay makes of a client's message to the room, before
/// passing it on: a loss report says how its download is doing, and may move
/// its level; a keyframe request from a throttled client is passed on at most
/// every [`THROTTLED_KEY_GAP_MS`]. False to not pass it on.
async fn judge(state: &Shared, id: u32, link: &Link, text: &str) -> bool {
    let (told, pass) = {
        let mut st = state.lock().unwrap();
        if !st.throttle {
            return true;
        }
        let st = &mut *st;
        let Some(peer) = st.peers.get_mut(&id) else { return false };
        let now = now_ms();
        if let Some(report) = LossReport::parse(text) {
            let uplink = &st.uplink;
            let told = call_rate::downlink_loss(&report.0, |s| uplink.get(&s).copied().unwrap_or(0.0))
                .and_then(|loss| peer.throttle.observe(loss, now as f64).map(|level| (level, loss)));
            (told, true)
        } else if KeyRequest::parse(text).is_some() && peer.throttle.level() > 0 {
            let pass = now.saturating_sub(peer.last_key) >= THROTTLED_KEY_GAP_MS;
            if pass {
                peer.last_key = now;
            }
            (None, pass)
        } else {
            (None, true)
        }
    };
    if let Some((level, loss)) = told {
        println!("[relay] #{id}: download losing {:.0}%, now holding back to level {level}", loss * 100.0);
        let _ = link.control(&FromRelay::Throttled(level).to_text()).await;
    }
    pass
}

/// An issuer connecting with a revocation: check it, apply it to everyone
/// connected, say so, hang up.
async fn revoke(state: Shared, request: Request, token: &str) {
    let from = request.remote_addr();
    if state.lock().unwrap().gate.is_none() {
        return request.refuse(404).await;
    }
    let (hit, gone) = match apply(&state, token) {
        Ok(applied) => applied,
        Err(e) => {
            println!("[relay] {from}: revocation refused ({e})");
            return request.refuse(403).await;
        }
    };
    notify(hit, gone).await;
    if let Ok(admin) = request.accept().await {
        let _ = admin.control(&FromRelay::Applied.to_text()).await;
        // Let the message go before the session does.
        tokio::time::sleep(Duration::from_millis(200)).await;
        admin.close(0, "applied");
    }
}

/// Grants running out: told at once (their datagrams already stop, since
/// `may_send` checks the clock), closed after the grace.
async fn expire(state: Shared, grace: Duration) {
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    loop {
        tick.tick().await;
        let now = now_ms();
        let (tell, close): (Vec<Link>, Vec<(u32, Link)>) = {
            let mut st = state.lock().unwrap();
            let (mut tell, mut close) = (Vec::new(), Vec::new());
            for (&id, peer) in st.peers.iter_mut() {
                let Some(g) = &peer.grant else { continue };
                if now < g.expires_ms {
                    continue;
                }
                if now >= g.expires_ms + grace.as_millis() as u64 {
                    close.push((id, peer.link.clone()));
                } else if !peer.told_expired {
                    peer.told_expired = true;
                    tell.push(peer.link.clone());
                }
            }
            (tell, close)
        };
        for link in tell {
            let _ = link.control(&FromRelay::Expires { secs: 0 }.to_text()).await;
        }
        for (id, link) in close {
            println!("[relay] #{id}: grant expired, closing");
            link.close(401, "grant expired");
        }
    }
}
