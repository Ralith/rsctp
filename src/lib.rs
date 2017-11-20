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

#[cfg(test)]
mod tests;

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
impl<T, E: Nil> Nil for Result<T, E> { const NIL: Self = Err(E::NIL); }

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

    pub fn abort(&mut self, assoc: usize, reason: &[u8]) {
        // TODO: Assert MTU compliance
        let addr = self.associations[assoc].primary_path;
        let tag = self.associations[assoc].peer_verification_tag;
        self.send_ootb(addr, tag, chunk::Abort {})
            .param(chunk::UserInitiatedAbort(reason));
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
        } else {
            // §8.4 checks
            // 1
            match source.ip() {
                IpAddr::V4(x) => if x.is_broadcast() { return; }
                IpAddr::V6(x) => if x.is_multicast() { return; }
            }
            // 2
            if chunk_queue::Iter::new(packet).find(|x| {
                x[0] == chunk::Abort::TYPE
                    || x[0] == chunk::ShutdownComplete::TYPE
                    || x[0] == chunk::CookieAck::TYPE
            }).is_some() { return; }
        }

        for chunk in chunk_queue::Iter::new(packet) {
            if let Some(id) = assoc_id {
                self.handle_assoc_chunk(now, source, header.verification_tag, id, chunk);
            } else {
                match self.handle_ootb_chunk(now, source, header.verification_tag, chunk) {
                    Ok(id) => { assoc_id = Some(id); }
                    Err(()) => { break; }
                }
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
                    self.send_ootb(source, ack.value.tag, chunk::Abort {});
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
            (State::CookieWait, chunk::ShutdownAck::TYPE) => { self.handle_ootb_chunk(now, source, tag, chunk); }
            (State::CookieWait, chunk::Init::TYPE) => {
                // §5.2.1 initialization collision
                let (init, params) = tryopt!(Chunk::<chunk::Init>::decode(chunk));
                self.send_duplicate_init_reply(now, source, assoc_id, &init, params, false, false);
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
            (State::CookieEchoed, chunk::ShutdownAck::TYPE) => { self.handle_ootb_chunk(now, source, tag, chunk); }
            (State::CookieEchoed, chunk::Init::TYPE) => {
                // §5.2.1 initialization collision
                let (init, params) = tryopt!(Chunk::<chunk::Init>::decode(chunk));
                // TODO: Multihoming: Ensure no new addresses, otherwise respond with abort
                self.send_duplicate_init_reply(now, source, assoc_id, &init, params, true, false);
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
                self.send_duplicate_init_reply(now, source, assoc_id, &init, params, true, true);
            }
            (_, chunk::ShutdownComplete::TYPE) => {} // §8.5.1 C
            (_, chunk::InitAck::TYPE) => {}          // §5.2.3
            (_, chunk::CookieEcho::TYPE) => {
                // §5.2.4
                let (_, mut params) = tryopt!(Chunk::<chunk::CookieEcho>::decode(chunk));
                let (_, cookie_data) = tryopt!(params.find(|&(ty, _)| ty == chunk::Cookie::TYPE));
                if !chunk::Cookie::check_mac(&self.mac_key, cookie_data) { return; } // §5.1.5 step 2
                let cookie = chunk::Cookie::decode(cookie_data);

                {
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
                }

                let rtt = now - (self.epoch + Duration::from_millis(cookie.timestamp));
                if rtt > Duration::from_millis(self.params.valid_cookie_life as u64) {
                    // Stale cookie
                    let measure = 1000 * (duration_ms(rtt) as u32 - self.params.valid_cookie_life);
                    self.send_ootb(source, cookie.peer_verification_tag, chunk::Error {})
                        .param(chunk::StaleCookieError { measure });
                    return;
                }

                let tcb = &mut self.associations[assoc_id];
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
                                 init: &Chunk<chunk::Init>, params: chunk::ParamIter,
                                 tie_tags: bool, new_verification_tag: bool) {
        let tcb = &self.associations[assoc_id];
        self.out_meta.push((source, init.value.tag));
        let local_verification_tag = if new_verification_tag { self.rng.gen() } else { tcb.local_verification_tag };
        let mut ack = self.out.push(chunk::InitAck {
            tag: local_verification_tag,
            a_rwnd: self.params.recv_window_initial,
            outbound_streams: tcb.out_streams.len() as u16,
            max_inbound_streams: u16::max_value(),
            tsn: tcb.next_tsn - 1,
        });
        ack.param(chunk::Cookie {
            mac: *MacCode::from_slice(&[0; 64]),
            local_verification_tag,
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

    /// Process an "out of the blue" chunk, i.e. one from an unknown peer
    ///
    /// Returns `Ok(_)` on association established; `Err(())` if the packet should not be processed further.
    fn handle_ootb_chunk(&mut self, now: Instant, source: SocketAddr, verification_tag: u32, chunk: &[u8]) -> Result<usize, ()> {
        match chunk[0] {
            chunk::Init::TYPE => {
                if verification_tag != 0 { return Err(()); }
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
                Err(())
            }
            chunk::CookieEcho::TYPE => {
                let (_, mut params) = tryopt!(Chunk::<chunk::CookieEcho>::decode(chunk));
                let (_, cookie_data) = tryopt!(params.find(|&(ty, _)| ty == chunk::Cookie::TYPE));
                if !chunk::Cookie::check_mac(&self.mac_key, cookie_data) { return Err(()); } // §5.1.5 step 2
                let cookie = chunk::Cookie::decode(cookie_data);

                if cookie.local_verification_tag != verification_tag { return Err(()); } // §5.1.5 step 3

                let rtt = now - (self.epoch + Duration::from_millis(cookie.timestamp));
                if rtt > Duration::from_millis(self.params.valid_cookie_life as u64) {
                    // Stale cookie
                    let measure = 1000 * (duration_ms(rtt) as u32 - self.params.valid_cookie_life);
                    self.send_ootb(source, cookie.peer_verification_tag, chunk::Error {})
                        .param(chunk::StaleCookieError { measure });
                    return Err(());
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
                Ok(id)
            }
            chunk::ShutdownAck::TYPE => { // §8.4 step 5
                tryopt!(Chunk::<chunk::ShutdownAck>::decode(chunk));
                self.send_ootb(source, verification_tag, chunk::ShutdownComplete {}).flags(chunk::ShutdownCompleteFlags::T);
                Err(())
            }
            chunk::Error::TYPE => {
                // §5.2.6
                let (_, mut params) = tryopt!(Chunk::<chunk::Error>::decode(chunk));
                if params.find(|&(ty, _)| ty == chunk::StaleCookieError::TYPE).is_none() {
                    self.send_ootb(source, verification_tag, chunk::Abort {}).flags(chunk::AbortFlags::T);
                }
                Err(())
            }
            _ => {              // §8.4 step 8
                self.send_ootb(source, verification_tag, chunk::Abort {}).flags(chunk::AbortFlags::T);
                Err(())
            }
        }
    }

    fn send_ootb<T: chunk::Type>(&mut self, dest: SocketAddr, tag: u32, x: T) -> chunk_queue::ParamsBuilder<T> {
        self.out_meta.push((dest, tag));
        self.out.push(x)
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
