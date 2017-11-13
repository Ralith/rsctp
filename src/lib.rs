extern crate rand;
extern crate byteorder;
extern crate slab;
#[macro_use]
extern crate bitflags;
extern crate crc32c_hw;

use std::{fmt, ops, io, cmp};
use std::ops::Range;
use std::cmp::Ordering;
use std::net::{SocketAddr, IpAddr};
use std::time::{Duration, Instant};
use std::collections::{HashMap, VecDeque};

use slab::Slab;
use rand::{OsRng, Rng};
use byteorder::{ByteOrder, NetworkEndian};

mod chunk;
mod chunk_queue;

use chunk::{Type, Wire, Param, Chunk, CommonHeader};
use chunk_queue::ChunkQueue;

macro_rules! tryopt {
    ($val:expr) => (if let Some(x) = $val { x } else { return; })
}

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
    out: ChunkQueue,
    out_meta: Vec<(SocketAddr, u32)>,
}

impl Endpoint {
    pub fn new(params: Parameters, epoch: Instant, port: u16, outbound_streams: u16) -> io::Result<Self> {
        Ok(Endpoint {
            params, port, outbound_streams, epoch,
            associations: Slab::new(),
            peers: HashMap::new(),
            rng: OsRng::new()?,
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
        });
        self.associations[id].out_streams.resize(streams as usize, StreamSeq(0));
        let mut peer = Peer::new(now, id, RoundTripTimer::new(self.params.rto_initial));
        peer.out.push(chunk::Init {
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

    pub fn shutdown(&self, assoc: usize) { unimplemented!() }

    pub fn abort(&self, assoc: usize) { unimplemented!() }

    pub fn send(&self, assoc: usize, params: Send) { unimplemented!() }

    pub fn receive(&self, assoc: usize) -> &[Receive] { unimplemented!() }

    pub fn status(&self, assoc: usize) -> Status { unimplemented!() }

    pub fn poll(&mut self) -> Option<(usize, Event)> { self.events.pop_front() }

    pub fn handle_packet(&mut self, now: Instant, source: IpAddr, packet: &[u8]) {
        if packet.len() <= CommonHeader::size() as usize { return; }
        let header = CommonHeader::decode(&packet);

        let crc = crc32c_hw::update(0, &packet[0..8]);
        let crc = crc32c_hw::update(crc, &[0, 0, 0, 0]);
        let packet = &packet[CommonHeader::size() as usize..];
        let crc = crc32c_hw::update(crc, packet);
        if crc != header.checksum { return; }

        let source = SocketAddr::new(source, header.source_port);

        let mut assoc_id = None;
        if let Some(id) = self.peers.get(&source).map(|x| x.association) {
            let tcb = &mut self.associations[id];
            // Discard packets with bad tags, per RFC 4960 §8.5
            if header.verification_tag != tcb.local_verification_tag { return; } 
            assoc_id = Some(id);
        }

        let mut packet = packet;
        while !packet.is_empty() {
            let length = NetworkEndian::read_u16(&packet[2..4]);
            if let Some(id) = assoc_id {
                self.handle_assoc_chunk(now, source, id, &packet[0..length as usize]);
            } else {
                self.handle_chunk(now, source, &packet[0..length as usize]);
            }
            packet = &packet[length as usize..]
        }
    }

    /// Process a chunk from a peer in an existing association
    fn handle_assoc_chunk(&mut self, now: Instant, source: SocketAddr, assoc_id: usize, chunk: &[u8]) {
        let tcb = &mut self.associations[assoc_id];
        match (tcb.state, chunk[0]) {
            (State::CookieWait, chunk::InitAck::TYPE) => {
                let (ack, params) = tryopt!(Chunk::<chunk::InitAck>::decode(chunk));
                let mut reply = self.peers.get_mut(&source).unwrap().out.push(chunk::CookieEcho {});
                let mut got_cookie = false;
                for (ty, value) in params {
                    match ty {
                        chunk::Cookie::TYPE => {
                            reply.raw_param(ty, value);
                            got_cookie = true;
                        }
                        _ => {} // TODO: SHOULD denerate unrecognized param errors
                    }
                }

                if !got_cookie {
                    // Cookie is required
                    self.out_meta.push((source, ack.value.tag));
                    self.out.push(chunk::Abort {});
                    return;
                }

                tcb.peer_verification_tag = ack.value.tag;
                tcb.state = State::CookieEchoed;
                tcb.last_recv_tsn = ack.value.tsn; // - 1?
                tcb.in_streams.resize(ack.value.outbound_streams as usize, StreamSeq(0));
                tcb.out_streams.truncate(ack.value.max_inbound_streams as usize);
                tcb.out_streams.shrink_to_fit();
                // TODO: Set and use initial RTT
                self.events.push_back((assoc_id,  Event::TimerStart(TimerKind::Global(1), Duration::from_millis(self.params.rto_initial as u64))));
            }
            (State::CookieEchoed, chunk::CookieAck::TYPE) => {
                tryopt!(Chunk::<chunk::CookieAck>::decode(chunk));
                tcb.state = State::Established;
                self.events.push_back((assoc_id, Event::TimerStop(TimerKind::Global(1))));
                self.events.push_back((assoc_id, Event::CommunicationUp {
                    outbound_streams: tcb.out_streams.len() as u16,
                    inbound_streams: tcb.in_streams.len() as u16,
                }));
            }
            _ => unimplemented!()
        }
    }

    /// Process a chunk from an unknown peer
    fn handle_chunk(&mut self, now: Instant, source: SocketAddr, chunk: &[u8]) {
        match chunk[0] {
            chunk::Init::TYPE => {
                let (init, params) = tryopt!(Chunk::<chunk::Init>::decode(chunk));
                for (ty, value) in params {
                    match ty {
                        _ => {} // TODO: Multihoming; MUST generate unrecognized param errors
                    }
                }
                let outbound_streams = cmp::min(init.value.max_inbound_streams, self.outbound_streams);
                self.out_meta.push((source, init.value.tag));
                let local_verification_tag = self.rng.gen();
                let tsn = TransmitSeq(self.rng.gen());
                self.out.push(chunk::InitAck {
                    tag: local_verification_tag,
                    a_rwnd: self.params.recv_window_initial,
                    outbound_streams,
                    max_inbound_streams: u16::max_value(),
                    tsn,
                }).param(chunk::Cookie {
                    local_verification_tag,
                    peer_verification_tag: init.value.tag,
                    timestamp: duration_ms(now - self.epoch),
                    inbound_streams: init.value.outbound_streams,
                    outbound_streams, tsn,
                    recv_tsn: init.value.tsn,
                });
            }
            chunk::CookieEcho::TYPE => {
                let (_, mut params) = tryopt!(Chunk::<chunk::CookieEcho>::decode(chunk));
                let (_, cookie) = tryopt!(params.find(|&(ty, _)| ty == chunk::Cookie::TYPE));
                let cookie = chunk::Cookie::decode(cookie);
                let rtt = now - (self.epoch + Duration::from_millis(cookie.timestamp));
                if rtt > Duration::from_millis(self.params.valid_cookie_life as u64) {
                    // Stale cookie
                    let measure = 1000 * (duration_ms(rtt) as u32 - self.params.valid_cookie_life);
                    self.send_abort(source, cookie.peer_verification_tag, chunk::StaleCookieError { measure });
                    return;
                } 
                let id = self.associations.insert(Association {
                    state: State::Established,
                    peer_verification_tag: cookie.peer_verification_tag,
                    local_verification_tag: cookie.local_verification_tag,
                    primary_path: source,
                    in_streams: Vec::new(),
                    out_streams: Vec::new(),
                    next_tsn: cookie.tsn + 1,
                    last_recv_tsn: cookie.recv_tsn, // - 1?
                    ack_state: 0,
                    cumul_tsn_ack: cookie.tsn - 1,
                });
                self.associations[id].out_streams.resize(cookie.outbound_streams as usize, StreamSeq(0));
                self.associations[id].in_streams.resize(cookie.inbound_streams as usize, StreamSeq(0));
                let mut rttimer = RoundTripTimer::new(self.params.rto_initial);
                rttimer.init(duration_ms(rtt) as u32);
                let mut peer = Peer::new(now, id, rttimer);
                peer.out.push(chunk::CookieAck {});
                self.peers.insert(source, peer);
                self.events.push_back((id, Event::CommunicationUp {
                    outbound_streams: cookie.outbound_streams,
                    inbound_streams: cookie.inbound_streams,
                }));
            }
            // §3.3.7 says ignore aborts from unknown peers
            chunk::Abort::TYPE => {}
            _ => unimplemented!()
        }
    }

    fn send_abort<T: chunk::Param>(&mut self, dest: SocketAddr, tag: u32, reason: T) {
        self.out_meta.push((dest, tag));
        self.out.push(chunk::Abort {})
            .param(reason);
    }

    pub fn handle_timeout(&mut self, assoc: usize, kind: TimerKind) {
        let tcb = &mut self.associations[assoc];
        match (tcb.state, kind) {
            (State::CookieWait, TimerKind::Global(1)) => {
                let timer = &mut self.peers.get_mut(&tcb.primary_path).unwrap().rtt;
                timer.expire(self.params.rto_max);
                self.events.push_back((assoc,  Event::TimerStart(TimerKind::Global(1), timer.rto())));
                // Retransmit Init
                unimplemented!()
            }
            (State::CookieEchoed, TimerKind::Global(1)) => {
                let timer = &mut self.peers.get_mut(&tcb.primary_path).unwrap().rtt;
                timer.expire(self.params.rto_max);
                self.events.push_back((assoc, Event::TimerStart(TimerKind::Global(1), timer.rto())));
                // Retransmit CookieEcho
                unimplemented!()
            }
            _ => unimplemented!()
        }
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

    pub fn init(&mut self, r: u32) {
        self.srtt = r;
        self.rttvar = r/2;
        self.rto = self.srtt + 4 * self.rttvar;
    }

    pub fn update(&mut self, params: &Parameters, r: u32) {
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

    pub fn rto(&self) -> Duration {
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
    rtt: RoundTripTimer,
    rto_pending: bool,
    last_time: Instant,
    out: ChunkQueue,
}

impl Peer {
    fn new(now: Instant, association: usize, rtt: RoundTripTimer) -> Self {
        Peer {
            association, rtt,
            reachable: true,
            rto_pending: false,
            last_time: now,
            out: ChunkQueue::new(),
        }
    }
}

#[derive(Debug)]
pub enum Event {
    DataArrive { stream: u16 },
    SendFailure { reason: io::Error, context: u32 },
    CommunicationUp { outbound_streams: u16, inbound_streams: u16 },
    CommunicationLost { reason: Option<io::Error>, last_acked: TransmitSeq, last_sent: TransmitSeq },
    CommunicationError { reason: io::Error },
    Restart,
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
        assert_eq!(init.flags, chunk::InitFlags::empty());
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
