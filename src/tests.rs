use super::*;
use std::net::Ipv4Addr;
use std::iter;

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

fn run_handshake(now: Instant,
             mut client: &mut Endpoint, client_addr: SocketAddr,
             mut server: &mut Endpoint, server_addr: SocketAddr) -> (usize, usize)
{
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
    (client_assoc, server_assoc)
}

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

    run_handshake(now, &mut client, client_addr, &mut server, server_addr);
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

#[test]
fn init_collision_1() {
    let proto_params = Parameters::default();
    let now = Instant::now();

    let a_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 42);
    let b_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 24);

    let mut a = Endpoint::new(proto_params, now, a_addr.port(), 1).unwrap();
    let mut b = Endpoint::new(proto_params, now, b_addr.port(), 1).unwrap();

    let a_assoc = a.associate(now, b_addr, 1);
    let b_assoc = b.associate(now, a_addr, 1);
    assert_eq!(a.associations[a_assoc].state, State::CookieWait);
    assert_eq!(b.associations[b_assoc].state, State::CookieWait);
    transmit(now, &mut a, a_addr, &mut b, b_addr);
    transmit(now, &mut b, b_addr, &mut a, a_addr);
    assert_eq!(a.associations[a_assoc].state, State::CookieEchoed);
    transmit(now, &mut a, a_addr, &mut b, b_addr);
    assert_eq!(b.associations[b_assoc].state, State::Established);
    transmit(now, &mut b, b_addr, &mut a, a_addr);
    assert_eq!(a.associations[a_assoc].state, State::Established);
    assert_eq!(a.associations.len(), 1);
    assert_eq!(b.associations.len(), 1);
}

#[test]
fn init_collision_2() {
    let proto_params = Parameters::default();
    let now = Instant::now();

    let a_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 42);
    let b_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 24);

    let mut a = Endpoint::new(proto_params, now, a_addr.port(), 1).unwrap();
    let mut b = Endpoint::new(proto_params, now, b_addr.port(), 1).unwrap();

    let a_assoc = a.associate(now, b_addr, 1);
    assert_eq!(a.associations[a_assoc].state, State::CookieWait);
    transmit(now, &mut a, a_addr, &mut b, b_addr);
    transmit(now, &mut b, b_addr, &mut a, a_addr);
    assert_eq!(a.associations[a_assoc].state, State::CookieEchoed);
    let b_assoc = b.associate(now, a_addr, 1);
    assert_eq!(b.associations[b_assoc].state, State::CookieWait);
    transmit(now, &mut b, b_addr, &mut a, a_addr);
    transmit(now, &mut a, a_addr, &mut b, b_addr);
    assert_eq!(b.associations[b_assoc].state, State::CookieEchoed);
    assert_eq!(a.associations[a_assoc].state, State::CookieEchoed);
    transmit(now, &mut b, b_addr, &mut a, a_addr);
    assert_eq!(a.associations[a_assoc].state, State::Established);
    assert_eq!(a.associations.len(), 1);
    assert_eq!(b.associations.len(), 1);
}

#[test]
fn restart() {
    let proto_params = Parameters::default();
    let now = Instant::now();

    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 42);
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 24);

    let mut client = Endpoint::new(proto_params, now, client_addr.port(), 1).unwrap();
    let mut server = Endpoint::new(proto_params, now, server_addr.port(), 1).unwrap();

    let (_, server_assoc) = run_handshake(now, &mut client, client_addr, &mut server, server_addr);
    client = Endpoint::new(proto_params, now, client_addr.port(), 1).unwrap();
    let client_assoc = client.associate(now, server_addr, 1);
    assert_eq!(client.associations[client_assoc].state, State::CookieWait);
    transmit(now, &mut client, client_addr, &mut server, server_addr);
    transmit(now, &mut server, server_addr, &mut client, client_addr);
    assert_eq!(client.associations[client_assoc].state, State::CookieEchoed);
    transmit(now, &mut client, client_addr, &mut server, server_addr);
    transmit(now, &mut server, server_addr, &mut client, client_addr);
    assert_eq!(client.associations[client_assoc].state, State::Established);
    assert_eq!(server.associations[server_assoc].state, State::Established);
    let mut restarted = false;
    while let Some((assoc, event)) = server.poll() {
        use Event::*;
        match event {
            Restart { .. } => {
                assert_eq!(assoc, server_assoc);
                restarted = true;
            }
            _ => {}
        }
    }
    assert!(restarted);
}

#[test]
fn abort() {
    let proto_params = Parameters::default();
    let now = Instant::now();

    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 42);
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 24);

    let mut client = Endpoint::new(proto_params, now, client_addr.port(), 1).unwrap();
    let mut server = Endpoint::new(proto_params, now, server_addr.port(), 1).unwrap();

    let (client_assoc, server_assoc) = run_handshake(now, &mut client, client_addr, &mut server, server_addr);
    let reason = [1, 2, 3, 4];
    client.abort(client_assoc, &reason);
    transmit(now, &mut client, client_addr, &mut server, server_addr);
    let mut aborted = false;
    while let Some((assoc, event)) = server.poll() {
        use Event::*;
        match event {
            CommunicationLost { reason: Some(ErrorKind::UserInitiatedAbort { reason: received }) } => {
                assert_eq!(assoc, server_assoc);
                assert_eq!(&received, &reason);
                aborted = true;
            }
            _ => {}
        }
    }
    assert!(aborted);
}
