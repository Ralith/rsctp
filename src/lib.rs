extern crate rand;
extern crate byteorder;
extern crate slab;
#[macro_use]
extern crate bitflags;
extern crate crc32c_hw;
extern crate blake2;
extern crate crypto_mac;
extern crate generic_array;

use std::{fmt, ops, io, cmp};
use std::cmp::Ordering;
use std::net::{SocketAddr, IpAddr};
use std::time::{Duration, Instant};
use std::collections::{HashMap, VecDeque};

use slab::Slab;
use rand::{OsRng, Rng};
use blake2::Blake2b;
use crypto_mac::Mac;
use generic_array::GenericArray;

mod chunk;
mod chunk_queue;

use chunk::{Type, Wire, Param, Chunk, CommonHeader, ParamHeader};
use chunk_queue::ChunkQueue;

macro_rules! tryopt {
    ($val:expr) => (if let Some(x) = $val { x } else { return Nil::NIL; })
}

trait Nil {
    const NIL: Self;
}

impl Nil for () { const NIL: () = (); }
impl<T> Nil for Option<T> { const NIL: Option<T> = None; }

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct TransmitSeq(u32);

impl ops::Add<u32> for TransmitSeq {
    type Output = TransmitSeq;
    fn add(self, rhs: u32) -> TransmitSeq {
        TransmitSeq(self.0.wrapping_add(rhs))
    }
}

impl ops::Sub<u32> for TransmitSeq {
    type Output = TransmitSeq;
    fn sub(self, rhs: u32) -> TransmitSeq {
        TransmitSeq(self.0.wrapping_sub(rhs))
    }
}

impl fmt::Debug for TransmitSeq {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for TransmitSeq {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct StreamSeq(u16);

impl ops::Add<u16> for StreamSeq {
    type Output = StreamSeq;
    fn add(self, rhs: u16) -> StreamSeq {
        debug_assert!(rhs < 2u16.pow(15));
        StreamSeq(self.0.wrapping_add(rhs))
    }
}

impl fmt::Debug for StreamSeq {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for StreamSeq {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl PartialOrd for StreamSeq {
    fn partial_cmp(&self, other: &StreamSeq) -> Option<Ordering> {
        let a = self.0;
        let b = other.0;
        if a == b { Some(Ordering::Equal) }
        else if (a < b && b - a < 2u16.pow(15)) || (a > b && a - b > 2u16.pow(15)) { Some(Ordering::Less) }
        else {
            debug_assert!((a < b && b - a > 2u16.pow(15)) || (a > b && a - b < 2u16.pow(15)));
            Some(Ordering::Greater)
        }
    }
}

impl Ord for StreamSeq {
    fn cmp(&self, other: &StreamSeq) -> Ordering { self.partial_cmp(other).unwrap() }
}

#[derive(Debug, Copy, Clone)]
pub struct Parameters {
    /// bytes
    recv_window_initial: u32,
    /// ms
    valid_cookie_life: u32,
    /// ms
    rto_initial: u32,
    /// ms
    rto_min: u32,
    /// ms
    rto_max: u32,
    max_burst: u32,
    /// 1/2^n
    rto_alpha: u32,
    /// 1/2^n
    rto_beta: u32,
    association_max_retrans: u32,
    path_max_retrans: u32,
    max_init_retrans: u32,
    hb_interval: u32,
    hb_max_burst: u32,
    /// ms
    clock_granularity: u32,
}

impl Default for Parameters {
    fn default() -> Self {
        Parameters {
            recv_window_initial: 128 * 1024,
            valid_cookie_life: 60 * 1000,
            rto_initial: 3 * 1000,
            rto_min: 1 * 1000,
            rto_max: 60 * 1000,
            max_burst: 4,
            rto_alpha: 8,
            rto_beta: 4,
            association_max_retrans: 10,
            path_max_retrans: 5,
            max_init_retrans: 8,
            hb_interval: 30 * 1000,
            hb_max_burst: 1,
            clock_granularity: 5,
        }
    }
}

type MacAlgo = Blake2b;
type MacCode = GenericArray<u8, <MacAlgo as Mac>::OutputSize>;

pub struct Endpoint {
    params: Parameters,
    port: u16,
    /// Streams to request from incoming connections
    outbound_streams: u16,
    associations: Slab<Association>,
    peers: HashMap<SocketAddr, Peer>,
    rng: OsRng,
    events: VecDeque<(usize, Event)>,
    epoch: Instant,
    /// List of chunks to be transmitted outside of an association; addresses and tags stored 1:1 in `out_meta`
    out: ChunkQueue,
    out_meta: Vec<(SocketAddr, u32)>,
    // TODO: Refresh this occasionally (every n uses?)
    mac_key: GenericArray<u8, <MacAlgo as Mac>::OutputSize>,
}

impl Endpoint {
    pub fn new(params: Parameters, epoch: Instant, port: u16, outbound_streams: u16) -> io::Result<Self> {
        let mut rng = OsRng::new()?;
        let mut mac_key = *GenericArray::from_slice(&[0; 64]);
        rng.fill_bytes(&mut mac_key);
        Ok(Endpoint {
            params, port, outbound_streams, epoch, rng, mac_key,
            associations: Slab::new(),
            peers: HashMap::new(),
            events: VecDeque::new(),
            out: ChunkQueue::new(),
            out_meta: Vec::new(),
        })
    }

    pub fn associate(&mut self, now: Instant, addr: SocketAddr, streams: u16) -> usize {
        let local_verification_tag = self.rng.gen();
        let tsn = TransmitSeq(self.rng.gen());
        let id = self.associations.insert(Association {
            state: State::CookieWait,
            peer_verification_tag: 0,
            local_verification_tag,
            primary_path: addr,
            in_streams: Vec::new(),
            out_streams: Vec::new(),
            next_tsn: tsn + 1,
            last_recv_tsn: TransmitSeq(0),
            ack_state: 0,
            cumul_tsn_ack: tsn - 1,
            remote_cookie: None,
            init_retransmits: 0,
            tie_tags: self.rng.gen(),
        });
        self.associations[id].out_streams.resize(streams as usize, StreamSeq(0));
        let mut peer = Peer::new(now, id, RoundTripTimer::new(self.params.rto_initial));
        peer.send(now, chunk::Init {
            tag: local_verification_tag,
            a_rwnd: self.params.recv_window_initial,
            outbound_streams: streams,
            max_inbound_streams: u16::max_value(),
            tsn,
        });
        self.peers.insert(addr, peer);
        self.events.push_back((id, Event::TimerStart(TimerKind::Global(1), Duration::from_millis(self.params.rto_initial as u64))));
        id
    }

    pub fn shutdown(&mut self, _assoc: usize) { unimplemented!() }

    pub fn abort(&mut self, assoc: usize) {
        self.out_meta.push((self.associations[assoc].primary_path, self.associations[assoc].peer_verification_tag));
        self.out.push(chunk::Abort {});
        self.remove_assoc(assoc, None);
    }

    pub fn send(&mut self, _assoc: usize, _params: Send) { unimplemented!() }

    pub fn receive(&mut self, _assoc: usize) -> &[Receive] { unimplemented!() }

    pub fn status(&mut self, _assoc: usize) -> Status { unimplemented!() }

    pub fn poll(&mut self) -> Option<(usize, Event)> { self.events.pop_front() }

    pub fn handle_packet(&mut self, now: Instant, source: IpAddr, packet: &[u8]) {
        if packet.len() <= CommonHeader::size() as usize { return; }
        let header = CommonHeader::decode(&packet);
        if header.destination_port != self.port { return; }

        let crc = crc32c_hw::update(0, &packet[0..8]);
        let crc = crc32c_hw::update(crc, &[0, 0, 0, 0]);
        let packet = &packet[CommonHeader::size() as usize..];
        let crc = crc32c_hw::update(crc, packet);
        if crc != header.checksum { return; }

        let source = SocketAddr::new(source, header.source_port);

        let chunk_count = chunk_queue::Iter::new(packet).count();

        // §8.5.1 A: drop packets with 0 verification tag unless they only contain init
        if header.verification_tag == 0 {
            let mut iter = chunk_queue::Iter::new(packet);
            let chunk = tryopt!(iter.next());
            if chunk[0] != chunk::Init::TYPE { return; }
            if chunk_count != 1 { return; }
        }

        let mut assoc_id = self.peers.get(&source).map(|x| x.association);
        if let Some(id) = assoc_id {
            if header.verification_tag != self.associations[id].local_verification_tag {
                // Misc. §8.5.1 checks
                if chunk_count != 1 { return; }
                let chunk = chunk_queue::Iter::new(packet).next().unwrap();
                match chunk[0] {
                    chunk::Init::TYPE => {
                        if header.verification_tag != 0 { return; }
                    }
                    chunk::Abort::TYPE => {
                        if !chunk::AbortFlags::from(chunk[1]).contains(chunk::AbortFlags::T) ||
                            header.verification_tag != self.associations[id].peer_verification_tag
                        {
                            return;
                        }
                    }
                    chunk::ShutdownComplete::TYPE => {
                        if !chunk::ShutdownCompleteFlags::from(chunk[1]).contains(chunk::ShutdownCompleteFlags::T) ||
                            header.verification_tag != self.associations[id].peer_verification_tag
                        {
                            return;
                        }
                    }
                    _ => {}
                }
            }
        }

        for chunk in chunk_queue::Iter::new(packet) {
            if let Some(id) = assoc_id {
                self.handle_assoc_chunk(now, source, header.verification_tag, id, chunk);
            } else {
                assoc_id = self.handle_chunk(now, source, header.verification_tag, chunk);
            }
        }
        // TODO: Early ack if we just associated *and* got data
    }

    /// Process a chunk from a peer in an existing association
    fn handle_assoc_chunk(&mut self, now: Instant, source: SocketAddr, tag: u32, assoc_id: usize, chunk: &[u8]) {
        match (self.associations[assoc_id].state, chunk[0]) {
            (State::CookieWait, chunk::InitAck::TYPE) => {
                let (ack, params) = tryopt!(Chunk::<chunk::InitAck>::decode(chunk));
                {
                    let mut reply = self.peers.get_mut(&source).unwrap().send(now, chunk::CookieEcho {});
                    for (ty, value) in params {
                        match ty {
                            chunk::Cookie::TYPE => {
                                reply.raw_param(ty, value);
                                self.associations[assoc_id].remote_cookie = Some(value.to_vec().into_boxed_slice());
                            }
                            _ => {} // TODO: SHOULD generate unrecognized param errors
                        }
                    }
                }

                if self.associations[assoc_id].remote_cookie.is_none() {
                    // Cookie is required
                    self.out_meta.push((source, ack.value.tag));
                    self.out.push(chunk::Abort {});
                    self.remove_assoc(assoc_id, Some(ErrorKind::Protocol));
                    return;
                }

                let tcb = &mut self.associations[assoc_id];
                tcb.peer_verification_tag = ack.value.tag;
                tcb.state = State::CookieEchoed;
                tcb.init_retransmits = 0;
                tcb.last_recv_tsn = ack.value.tsn; // - 1?
                tcb.in_streams.resize(ack.value.outbound_streams as usize, StreamSeq(0));
                tcb.out_streams.truncate(ack.value.max_inbound_streams as usize);
                tcb.out_streams.shrink_to_fit();
                let peer = self.peers.get_mut(&source).unwrap();
                peer.rto.init(now - peer.last_time);
                self.events.push_back((assoc_id, Event::TimerStart(TimerKind::Global(1), peer.rto.get())));
            }
            // §8.5.1 E
            (State::CookieWait, chunk::ShutdownAck::TYPE) => { self.handle_chunk(now, source, tag, chunk); }
            (State::CookieWait, chunk::Init::TYPE) => {
                // §5.2.1 initialization collision
                let (init, params) = tryopt!(Chunk::<chunk::Init>::decode(chunk));
                self.send_duplicate_init_reply(now, source, assoc_id, &init, params, false);
            }


            (State::CookieEchoed, chunk::CookieAck::TYPE) => {
                tryopt!(Chunk::<chunk::CookieAck>::decode(chunk));
                let tcb = &mut self.associations[assoc_id];
                tcb.state = State::Established;
                tcb.remote_cookie = None; // We don't need the data stored here once established
                self.events.push_back((assoc_id, Event::TimerStop(TimerKind::Global(1))));
                self.events.push_back((assoc_id, Event::CommunicationUp {
                    outbound_streams: tcb.out_streams.len() as u16,
                    inbound_streams: tcb.in_streams.len() as u16,
                }));
                let peer = self.peers.get_mut(&source).unwrap();
                peer.rto.update(&self.params, now - peer.last_time);
            }
            // §8.5.1 E
            (State::CookieEchoed, chunk::ShutdownAck::TYPE) => { self.handle_chunk(now, source, tag, chunk); }
            (State::CookieEchoed, chunk::Init::TYPE) => {
                // §5.2.1 initialization collision
                let (init, params) = tryopt!(Chunk::<chunk::Init>::decode(chunk));
                // TODO: Multihoming: Ensure no new addresses, otherwise respond with abort
                self.send_duplicate_init_reply(now, source, assoc_id, &init, params, true);
            }
            (State::CookieEchoed, chunk::Error::TYPE) => {
                // §5.2.6
                let (_, mut params) = tryopt!(Chunk::<chunk::Error>::decode(chunk));
                tryopt!(params.find(|&(ty, _)| ty == chunk::StaleCookieError::TYPE));
                self.remove_assoc(assoc_id, Some(ErrorKind::StaleCookie));
            }


            (State::ShutdownAckSent, chunk::Init::TYPE) => {
                // §9.2: lost SHUTDOWN COMPLETE
                let peer = self.peers.get_mut(&source).unwrap();
                peer.send(now, chunk::ShutdownAck {});
            }
            (State::ShutdownAckSent, chunk::ShutdownComplete::TYPE) => {
                let (complete, _) = tryopt!(Chunk::<chunk::ShutdownComplete>::decode(chunk));
                unimplemented!()
            }


            (_, chunk::Init::TYPE) => {
                // §5.2.2
                let (init, params) = tryopt!(Chunk::<chunk::Init>::decode(chunk));
                // TODO: Multihoming: Ensure no new addresses, otherwise respond with abort
                self.send_duplicate_init_reply(now, source, assoc_id, &init, params, true);
            }
            (_, chunk::ShutdownComplete::TYPE) => {} // §8.5.1 C
            (_, chunk::InitAck::TYPE) => {}          // §5.2.3
            (_, chunk::CookieEcho::TYPE) => {
                // §5.2.4
                let (_, mut params) = tryopt!(Chunk::<chunk::CookieEcho>::decode(chunk));
                let (_, cookie_data) = tryopt!(params.find(|&(ty, _)| ty == chunk::Cookie::TYPE));
                if !chunk::Cookie::check_mac(&self.mac_key, cookie_data) { return; } // §5.1.5 step 2
                let cookie = chunk::Cookie::decode(cookie_data);

                let tcb = &mut self.associations[assoc_id];

                // §5.2.4 action D
                if cookie.local_verification_tag == tcb.local_verification_tag
                    && cookie.peer_verification_tag == tcb.peer_verification_tag
                {
                    if tcb.state == State::CookieEchoed {
                        tcb.state = State::Established;
                        self.events.push_back((assoc_id, Event::TimerStop(TimerKind::Global(1))));
                        self.events.push_back((assoc_id, Event::CommunicationUp {
                            outbound_streams: tcb.out_streams.len() as u16,
                            inbound_streams: tcb.in_streams.len() as u16,
                        }));
                    }
                    let peer = self.peers.get_mut(&tcb.primary_path).unwrap();
                    peer.send(now, chunk::CookieAck {});
                    return;
                }

                let rtt = now - (self.epoch + Duration::from_millis(cookie.timestamp));
                if rtt > Duration::from_millis(self.params.valid_cookie_life as u64) {
                    // Stale cookie
                    let measure = 1000 * (duration_ms(rtt) as u32 - self.params.valid_cookie_life);
                    self.out_meta.push((source, cookie.peer_verification_tag));
                    self.out.push(chunk::Error {})
                        .param(chunk::StaleCookieError { measure });
                    return;
                }

                if cookie.tie_tags == tcb.tie_tags
                    && cookie.local_verification_tag != tcb.local_verification_tag
                    && cookie.peer_verification_tag != tcb.peer_verification_tag
                {
                    // §5.2.4 action A: Peer restarted
                    // TODO: Reset cwnd, ssthresh
                    let old_state = tcb.state;
                    tcb.state = State::Established;
                    tcb.peer_verification_tag = cookie.peer_verification_tag;
                    tcb.local_verification_tag = cookie.local_verification_tag;
                    tcb.primary_path = source;
                    tcb.out_streams = vec![StreamSeq(0); cookie.outbound_streams as usize];
                    tcb.in_streams = vec![StreamSeq(0); cookie.inbound_streams as usize];
                    tcb.next_tsn = cookie.tsn + 1;
                    tcb.last_recv_tsn = cookie.recv_tsn; // - 1?
                    tcb.tie_tags = self.rng.gen();
                    let mut rttimer = RoundTripTimer::new(self.params.rto_initial);
                    rttimer.init(rtt);
                    let mut peer = Peer::new(now, assoc_id, rttimer);
                    peer.send(now, chunk::CookieAck {});
                    self.peers.insert(source, peer);
                    let event = if old_state == State::Established {
                        Event::Restart {
                            outbound_streams: cookie.outbound_streams,
                            inbound_streams: cookie.inbound_streams,
                        }
                    } else {
                        Event::CommunicationUp {
                            outbound_streams: cookie.outbound_streams,
                            inbound_streams: cookie.inbound_streams,
                        }
                    };
                    self.events.push_back((assoc_id, event));
                } else if cookie.local_verification_tag == tcb.local_verification_tag
                    && cookie.peer_verification_tag != tcb.peer_verification_tag
                {
                    // §5.2.4 action B: initialization collision
                    if tcb.state != State::Established {
                        tcb.state = State::Established;
                        self.events.push_back((assoc_id, Event::TimerStop(TimerKind::Global(1))));
                        self.events.push_back((assoc_id, Event::CommunicationUp {
                            outbound_streams: tcb.out_streams.len() as u16,
                            inbound_streams: tcb.in_streams.len() as u16,
                        }));
                    }
                    tcb.peer_verification_tag = cookie.peer_verification_tag;
                    let peer = self.peers.get_mut(&tcb.primary_path).unwrap();
                    peer.send(now, chunk::CookieAck {});
                }
                // Otherwise, §5.2.4 action C: ignore cookie
            }
            (_, chunk::CookieAck::TYPE) => {} // §5.2.5
            _ => unimplemented!()
        }
    }

    fn send_duplicate_init_reply(&mut self, now: Instant, source: SocketAddr, assoc_id: usize,
                                 init: &Chunk<chunk::Init>, params: chunk::ParamIter, tie_tags: bool) {
        let tcb = &self.associations[assoc_id];
        self.out_meta.push((source, init.value.tag));
        let mut ack = self.out.push(chunk::InitAck {
            tag: tcb.local_verification_tag,
            a_rwnd: self.params.recv_window_initial,
            outbound_streams: tcb.out_streams.len() as u16,
            max_inbound_streams: u16::max_value(),
            tsn: tcb.next_tsn - 1,
        });
        ack.param(chunk::Cookie {
            mac: *MacCode::from_slice(&[0; 64]),
            local_verification_tag: tcb.local_verification_tag,
            peer_verification_tag: init.value.tag,
            timestamp: duration_ms(now - self.epoch),
            inbound_streams: init.value.outbound_streams,
            outbound_streams: tcb.out_streams.len() as u16,
            tsn: tcb.next_tsn - 1,
            recv_tsn: init.value.tsn,
            tie_tags: if tie_tags { tcb.tie_tags } else { 0 },
        });
        chunk::Cookie::write_mac(&self.mac_key, &mut ack[Chunk::<chunk::Init>::size() as usize + 4..]);
        for (ty, value) in params {
            match ty {
                // TODO: Multihoming
                _ => {
                    if ParamHeader::report(ty) {
                        ack.param(chunk::UnrecognizedParameter { ty, value });
                    }
                    if ParamHeader::stop(ty) {
                        break;
                    }
                }
            }
        }
    }

    /// Process a chunk from an unknown peer
    fn handle_chunk(&mut self, now: Instant, source: SocketAddr, verification_tag: u32, chunk: &[u8]) -> Option<usize> {
        match chunk[0] {
            chunk::Init::TYPE => {
                if verification_tag != 0 { return None; }
                let (init, params) = tryopt!(Chunk::<chunk::Init>::decode(chunk));
                let outbound_streams = cmp::min(init.value.max_inbound_streams, self.outbound_streams);
                let local_verification_tag = self.rng.gen();
                let tsn = TransmitSeq(self.rng.gen());
                self.out_meta.push((source, init.value.tag));
                let mut reply = self.out.push(chunk::InitAck {
                    tag: local_verification_tag,
                    a_rwnd: self.params.recv_window_initial,
                    outbound_streams,
                    max_inbound_streams: u16::max_value(),
                    tsn,
                });

                reply.param(chunk::Cookie {
                    mac: *MacCode::from_slice(&[0; 64]),
                    local_verification_tag,
                    peer_verification_tag: init.value.tag,
                    timestamp: duration_ms(now - self.epoch),
                    inbound_streams: init.value.outbound_streams,
                    outbound_streams, tsn,
                    recv_tsn: init.value.tsn,
                    tie_tags: 0,
                });

                chunk::Cookie::write_mac(&self.mac_key, &mut reply[Chunk::<chunk::Init>::size() as usize + 4..]);

                for (ty, value) in params {
                    match ty {
                        // TODO: Multihoming
                        _ => {
                            if ParamHeader::report(ty) {
                                reply.param(chunk::UnrecognizedParameter { ty, value });
                            }
                            if ParamHeader::stop(ty) {
                                break;
                            }
                        }
                    }
                }
            }
            chunk::CookieEcho::TYPE => {
                let (_, mut params) = tryopt!(Chunk::<chunk::CookieEcho>::decode(chunk));
                let (_, cookie_data) = tryopt!(params.find(|&(ty, _)| ty == chunk::Cookie::TYPE));
                if !chunk::Cookie::check_mac(&self.mac_key, cookie_data) { return None; } // §5.1.5 step 2
                let cookie = chunk::Cookie::decode(cookie_data);

                if cookie.local_verification_tag != verification_tag { return None; } // §5.1.5 step 3

                let rtt = now - (self.epoch + Duration::from_millis(cookie.timestamp));
                if rtt > Duration::from_millis(self.params.valid_cookie_life as u64) {
                    // Stale cookie
                    let measure = 1000 * (duration_ms(rtt) as u32 - self.params.valid_cookie_life);
                    self.out_meta.push((source, cookie.peer_verification_tag));
                    self.out.push(chunk::Error {})
                        .param(chunk::StaleCookieError { measure });
                    return None;
                }
                let id = self.associations.insert(Association {
                    state: State::Established,
                    peer_verification_tag: cookie.peer_verification_tag,
                    local_verification_tag: cookie.local_verification_tag,
                    primary_path: source,
                    in_streams: vec![StreamSeq(0); cookie.inbound_streams as usize],
                    out_streams: vec![StreamSeq(0); cookie.outbound_streams as usize],
                    next_tsn: cookie.tsn + 1,
                    last_recv_tsn: cookie.recv_tsn, // - 1?
                    ack_state: 0,
                    cumul_tsn_ack: cookie.tsn - 1,
                    remote_cookie: None,
                    init_retransmits: 0,
                    tie_tags: self.rng.gen(),
                });
                let mut rttimer = RoundTripTimer::new(self.params.rto_initial);
                rttimer.init(rtt);
                let mut peer = Peer::new(now, id, rttimer);
                peer.send(now, chunk::CookieAck {});
                self.peers.insert(source, peer);
                self.events.push_back((id, Event::CommunicationUp {
                    outbound_streams: cookie.outbound_streams,
                    inbound_streams: cookie.inbound_streams,
                }));
                return Some(id);
            }
            chunk::Abort::TYPE => {} // §3.3.7 says ignore aborts from unknown peers
            chunk::ShutdownComplete::TYPE => {} // §8.5.1 C
            _ => unimplemented!()
        }
        None
    }

    /// Must only be called after processing timer start/stop events
    pub fn handle_timeout(&mut self, now: Instant, assoc: usize, kind: TimerKind) {
        match (self.associations[assoc].state, kind) {
            (State::CookieWait, TimerKind::Global(1)) => {
                if self.associations[assoc].init_retransmits >= self.params.max_init_retrans {
                    self.remove_assoc(assoc, Some(ErrorKind::Timeout));
                    return;
                }

                let tcb = &mut self.associations[assoc];
                let peer = self.peers.get_mut(&tcb.primary_path).unwrap();
                peer.rto.expire(self.params.rto_max);
                self.events.push_back((assoc, Event::TimerStart(TimerKind::Global(1), peer.rto.get())));
                // Retransmit
                tcb.init_retransmits += 1;
                peer.send(now, chunk::Init {
                    tag: tcb.local_verification_tag,
                    a_rwnd: self.params.recv_window_initial,
                    outbound_streams: tcb.out_streams.len() as u16,
                    max_inbound_streams: u16::max_value(),
                    tsn: tcb.next_tsn - 1,
                });
            }
            (State::CookieEchoed, TimerKind::Global(1)) => {
                if self.associations[assoc].init_retransmits >= self.params.max_init_retrans {
                    self.remove_assoc(assoc, Some(ErrorKind::Timeout));
                    return;
                }

                let tcb = &mut self.associations[assoc];
                let peer = self.peers.get_mut(&tcb.primary_path).unwrap();
                peer.rto.expire(self.params.rto_max);
                self.events.push_back((assoc, Event::TimerStart(TimerKind::Global(1), peer.rto.get())));
                // Retransmit
                tcb.init_retransmits += 1;
                peer.send(now, chunk::CookieEcho {})
                    .raw_param(chunk::Cookie::TYPE, tcb.remote_cookie.as_ref().unwrap());
            }
            _ => unreachable!()
        }
    }

    fn remove_assoc(&mut self, assoc: usize, reason: Option<ErrorKind>) {
        // TODO: Multihoming
        self.peers.remove(&self.associations[assoc].primary_path);
        self.associations.remove(assoc);
        self.events.push_back((assoc, Event::CommunicationLost { reason }));
    }
}

fn duration_ms(d: Duration) -> u64 {
    d.as_secs() * 1000 + (d.subsec_nanos() / 1000_000) as u64
}

/// See RFC4960 §13.2
#[derive(Debug)]
struct Association {
    peer_verification_tag: u32,
    local_verification_tag: u32,
    state: State,
    primary_path: SocketAddr,
    in_streams: Vec<StreamSeq>,
    out_streams: Vec<StreamSeq>,
    // peer_rwnd: u32,
    next_tsn: TransmitSeq,
    last_recv_tsn: TransmitSeq,
    ack_state: u8,
    cumul_tsn_ack: TransmitSeq,
    tie_tags: u64,

    /// Used only in state CookieEchoed to support retransmits
    remote_cookie: Option<Box<[u8]>>,
    /// Used only in state CookieWait and CookieEchoed to enable timing out
    init_retransmits: u32,
}

#[derive(Debug, Copy, Clone)]
struct RoundTripTimer {
    srtt: u32,
    rttvar: u32,
    rto: u32,
}

impl RoundTripTimer {
    pub fn new(initial: u32) -> Self {
        RoundTripTimer {
            srtt: 0,
            rttvar: 0,
            rto: initial,
        }
    }

    pub fn init(&mut self, r: Duration) {
        let r = duration_ms(r) as u32;
        self.srtt = r;
        self.rttvar = r/2;
        self.rto = self.srtt + 4 * self.rttvar;
    }

    pub fn update(&mut self, params: &Parameters, r: Duration) {
        let r = duration_ms(r) as u32;
        self.rttvar =
            self.rttvar - (self.rttvar >> params.rto_beta)
            + cmp::max(self.srtt, r) - cmp::min(self.srtt, r) >> params.rto_beta;
        if self.rttvar == 0 { self.rttvar = params.clock_granularity; }
        self.srtt =
            self.srtt - (self.srtt >> params.rto_alpha)
            + r >> params.rto_alpha;
        self.rto = cmp::min(params.rto_max, cmp::max(params.rto_min, self.srtt + 4 * self.rttvar));
    }

    pub fn expire(&mut self, rto_max: u32) {
        self.rto = cmp::min(rto_max, self.rto * 2);
    }

    pub fn get(&self) -> Duration {
        Duration::from_millis(self.rto as u64)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Send<'a> {
    pub data: &'a [u8],
    pub context: u32,
    pub stream: u16,
    pub lifetime: Option<Duration>,
    pub destination: Option<SocketAddr>,
    pub ordered: bool,
    pub bundle: bool,
    pub protocol: u32,
}

impl<'a> Default for Send<'a> {
    fn default() -> Self {
        Send {
            data: &[],
            context: 0,
            stream: 0,
            lifetime: None,
            destination: None,
            ordered: true,
            bundle: true,
            protocol: 0,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Receive<'a> {
    pub data: &'a [u8],
    pub source: SocketAddr,
    pub stream: u16,
    pub sequence: StreamSeq,
    pub partial: Option<TransmitSeq>,
    pub protocol: u16,
}

#[derive(Debug, Clone)]
pub struct Status {
    pub connected: bool,
    pub unacked: u32,
    pub pending: u32,
    pub primary: usize,
}

/// See RFC4960 §13.3
pub struct Peer {
    association: usize,
    reachable: bool,
    rto: RoundTripTimer,
    rto_pending: bool,
    last_time: Instant,
    out: ChunkQueue,
}

impl Peer {
    fn new(now: Instant, association: usize, rto: RoundTripTimer) -> Self {
        Peer {
            association, rto,
            reachable: true,
            rto_pending: false,
            last_time: now,
            out: ChunkQueue::new(),
        }
    }

    fn send<T: chunk::Type>(&mut self, now: Instant, x: T) -> chunk_queue::ParamsBuilder<T> {
        self.last_time = now;
        self.out.push(x)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ErrorKind {
    /// Peer violated the protocol
    Protocol,
    /// Peer is not responding
    Timeout,
    /// Couldn't complete the handshake within the time limit set by the peer
    StaleCookie,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Event {
    DataArrive { stream: u16 },
    SendFailure { reason: ErrorKind, context: u32 },
    CommunicationUp { outbound_streams: u16, inbound_streams: u16 },
    CommunicationLost { reason: Option<ErrorKind> },
    CommunicationError { reason: ErrorKind },
    Restart { outbound_streams: u16, inbound_streams: u16 },
    ShutdownComplete,

    TimerStart(TimerKind, Duration),
    TimerStop(TimerKind),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum TimerKind { Global(usize), Destination(SocketAddr) }

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum State {
    CookieWait,
    CookieEchoed,
    Established,
    ShutdownPending,
    ShutdownSent,
    ShutdownReceived,
    ShutdownAckSent,
}

fn compute_header<'a, I>(source_port: u16, destination_port: u16, verification_tag: u32, chunks: I) -> CommonHeader
    where I: IntoIterator<Item=&'a [u8]>
{
    let mut dummy = [0; 12];
    CommonHeader {
        source_port, destination_port, verification_tag,
        checksum: 0,
    }.encode(&mut dummy);
    let mut crc = crc32c_hw::update(0, &dummy);
    for x in chunks {
        crc = crc32c_hw::update(crc, x);
    }
    CommonHeader {
        source_port, destination_port, verification_tag,
        checksum: crc,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::iter;

    #[test]
    fn init_message() {
        let proto_params = Parameters::default();
        let mut e = Endpoint::new(proto_params, Instant::now(), 24, 1).unwrap();
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 42);
        e.associate(Instant::now(), remote, 17);
        let peer = e.peers.get(&remote).unwrap();
        assert!(!peer.out.is_empty());
        let (init, init_params) = Chunk::<chunk::Init>::decode(peer.out.iter().next().expect("no message")).expect("decode failed");
        assert_eq!(init.length, Chunk::<chunk::Init>::size());
        assert_eq!(init.flags, chunk::InitFlags::from(0));
        assert_eq!(init.value.a_rwnd, proto_params.recv_window_initial);
        assert_eq!(init.value.outbound_streams, 17);
        assert_eq!(init_params.count(), 0);
    }

    #[test]
    fn handshake() {
        let proto_params = Parameters::default();
        let now = Instant::now();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 42);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 24);

        let mut client = Endpoint::new(proto_params, now, client_addr.port(), 1).unwrap();
        let mut server = Endpoint::new(proto_params, now, server_addr.port(), 1).unwrap();

        let client_assoc = client.associate(now, server_addr, 1);
        assert_eq!(client.associations[client_assoc].state, State::CookieWait);
        transmit(now, &mut client, client_addr, &mut server, server_addr);
        transmit(now, &mut server, server_addr, &mut client, client_addr);
        assert_eq!(client.associations[client_assoc].state, State::CookieEchoed);
        transmit(now, &mut client, client_addr, &mut server, server_addr);
        transmit(now, &mut server, server_addr, &mut client, client_addr);
        assert_eq!(client.associations[client_assoc].state, State::Established);
        let server_assoc = server.peers.get(&client_addr).expect("server missing client peer").association;
        assert_eq!(server.associations[server_assoc].state, State::Established);
    }

    #[test]
    fn init_timeout() {
        let proto_params = Parameters::default();
        let mut now = Instant::now();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 42);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 24);

        let mut client = Endpoint::new(proto_params, now, client_addr.port(), 1).unwrap();

        client.associate(now, server_addr, 1);
        let mut timed_out = false;
        while let Some((assoc, event)) = client.poll() {
            use Event::*;
            match event {
                TimerStart(kind, duration) => {
                    now += duration;
                    client.handle_timeout(now, assoc, kind);
                }
                CommunicationLost { reason: Some(ErrorKind::Timeout) } => { timed_out = true; }
                e => panic!("unexpected event: {:?}", e),
            }
        }
        assert!(timed_out);
    }

    #[test]
    fn cookie_echo_timeout() {
        let proto_params = Parameters::default();
        let mut now = Instant::now();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 42);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 24);

        let mut client = Endpoint::new(proto_params, now, client_addr.port(), 1).unwrap();
        let mut server = Endpoint::new(proto_params, now, server_addr.port(), 1).unwrap();

        let client_assoc = client.associate(now, server_addr, 1);
        // Drain events so we don't feed the CookeEchoed state timeouts for CookieWait's timer
        while let Some((_, event)) = client.poll() {
            use Event::*;
            match event {
                TimerStart(_, _) => {}
                _ => panic!("unexpected event: {:?}", event),
            }
        }
        transmit(now, &mut client, client_addr, &mut server, server_addr);
        transmit(now, &mut server, server_addr, &mut client, client_addr);
        assert_eq!(client.associations[client_assoc].state, State::CookieEchoed);
        let mut timed_out = false;
        while let Some((assoc, event)) = client.poll() {
            use Event::*;
            match event {
                TimerStart(kind, duration) => {
                    now += duration;
                    client.handle_timeout(now, assoc, kind);
                }
                CommunicationLost { reason: Some(ErrorKind::Timeout) } => { timed_out = true; }
                _ => panic!("unexpected event: {:?}", event),
            }
        }
        assert!(timed_out);
    }

    fn transmit(now: Instant, send: &mut Endpoint, send_addr: SocketAddr, recv: &mut Endpoint, recv_addr: SocketAddr) {
        let mut packet = vec![0; 12];

        if let Some(peer) = send.peers.get_mut(&recv_addr) {
            let assoc = &mut send.associations[peer.association];

            // Send association messages
            compute_header(send_addr.port(), recv_addr.port(), assoc.peer_verification_tag, &peer.out)
                .encode(&mut packet);
            for chunk in &peer.out {
                packet.extend(chunk);
            }
            peer.out.clear();
            recv.handle_packet(now, send_addr.ip(), &packet);

            packet.truncate(12);
        }

        // Send non-association messages
        for (&(dest, tag), chunk) in send.out_meta.iter().zip(&send.out) {
            if dest != recv_addr { continue; }
            compute_header(send_addr.port(), recv_addr.port(), tag, iter::once(chunk))
                .encode(&mut packet);
            packet.extend(chunk);

            recv.handle_packet(now, send_addr.ip(), &packet);

            packet.truncate(12);
        }
        send.out_meta.clear();
        send.out.clear();
    }
}
