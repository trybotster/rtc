//! A stream id freed by a remote close must not be handed to a new channel while a reset of
//! that id is still in flight.
//!
//! RFC 8831 §6.7:
//!
//! > if one side decides to close the data channel, it resets the corresponding outgoing
//! > stream. When the peer sees that an incoming stream was reset, it also resets its
//! > corresponding outgoing stream. Once this is completed, the data channel is closed. [...]
//! > Streams are available for reuse after a reset has been performed.
//!
//! The interleaving (A creates channels, B closes one of them):
//!
//! 1. B closes channel X on stream S and sends an outgoing reset of S (H1).
//! 2. A receives H1, resets its incoming S and answers with its own outgoing reset of S (O1).
//! 3. B receives O1. B had already reset its outgoing S (H1); the published `rtc-sctp`
//!    nevertheless answers O1 with a second outgoing reset of S (H2).
//! 4. Before H2 arrives, A creates channel C. The published stack freed S at step 2, so C gets
//!    S, the lowest free id of A's parity, and sends its DCEP OPEN on S.
//! 5. H2 arrives and resets the new stream S: C closes before it ever opens.
//!
//! The peers run over an in-memory link with a logical clock, so each step's datagrams are
//! delivered, or held, by hand, and the interleaving is exact. Nothing here sleeps.

use anyhow::{Result, bail};
use bytes::BytesMut;
use rtc::data_channel::{RTCDataChannelId, StreamId};
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Logical time the pump may advance while waiting for a condition. Reached only on failure.
const PUMP_BUDGET: Duration = Duration::from_secs(30);

type Datagram = (SocketAddr, BytesMut);

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    opened: Vec<RTCDataChannelId>,
    closed: Vec<RTCDataChannelId>,
    connected: bool,
}

impl Peer {
    fn new(addr: SocketAddr, now: Instant) -> Result<Self> {
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .build(now)?;
        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: addr.ip().to_string(),
                port: addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?;
        pc.add_local_candidate(RTCIceCandidate::from(&candidate).to_json()?)?;
        Ok(Self {
            pc,
            addr,
            opened: Vec::new(),
            closed: Vec::new(),
            connected: false,
        })
    }

    /// Every datagram this peer wants to send now.
    fn outbound(&mut self) -> Vec<Datagram> {
        let mut out = Vec::new();
        while let Some(msg) = self.pc.poll_write() {
            out.push((self.addr, msg.message));
        }
        out
    }

    fn deliver(&mut self, now: Instant, datagrams: Vec<Datagram>) {
        for (from, message) in datagrams {
            self.pc
                .handle_read(TaggedBytesMut {
                    now,
                    transport: TransportContext {
                        local_addr: self.addr,
                        peer_addr: from,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message,
                })
                .ok();
        }
    }

    fn drain_events(&mut self) {
        while let Some(event) = self.pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    RTCPeerConnectionState::Connected,
                ) => self.connected = true,
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                    self.opened.push(id)
                }
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnClose(id)) => {
                    self.closed.push(id)
                }
                _ => {}
            }
        }
        while self.pc.poll_read().is_some() {}
    }
}

/// Two peers on an in-memory link. `now` is a logical clock: it advances only to the next
/// deadline either peer reports, and only when no datagram is waiting.
struct Link {
    a: Peer,
    b: Peer,
    now: Instant,
    to_a: VecDeque<Datagram>,
    to_b: VecDeque<Datagram>,
}

impl Link {
    /// Moves every datagram and event once, in both directions.
    fn step(&mut self) {
        let a_out = self.a.outbound();
        self.to_b.extend(a_out);
        let b_out = self.b.outbound();
        self.to_a.extend(b_out);
        let to_a: Vec<Datagram> = self.to_a.drain(..).collect();
        let to_b: Vec<Datagram> = self.to_b.drain(..).collect();
        let now = self.now;
        self.a.deliver(now, to_a);
        self.b.deliver(now, to_b);
        self.a.drain_events();
        self.b.drain_events();
    }

    fn idle(&mut self) -> bool {
        self.to_a.is_empty() && self.to_b.is_empty()
    }

    /// Runs the link until `done` holds, advancing logical time to the next deadline whenever
    /// nothing is in flight.
    fn pump_until(&mut self, what: &str, mut done: impl FnMut(&mut Link) -> bool) -> Result<()> {
        let limit = self.now + PUMP_BUDGET;
        loop {
            self.step();
            if done(self) {
                return Ok(());
            }
            let a_out = self.a.outbound();
            self.to_b.extend(a_out);
            let b_out = self.b.outbound();
            self.to_a.extend(b_out);
            if !self.idle() {
                continue;
            }
            let next = [self.a.pc.poll_timeout(), self.b.pc.poll_timeout()]
                .into_iter()
                .flatten()
                .min();
            let Some(next) = next else {
                bail!("{what}: nothing in flight and no deadline");
            };
            if next > limit {
                bail!("{what}: not reached within {PUMP_BUDGET:?} of logical time");
            }
            self.now = self.now.max(next);
            let now = self.now;
            self.a.pc.handle_timeout(now).ok();
            self.b.pc.handle_timeout(now).ok();
        }
    }
}

fn connect() -> Result<Link> {
    let now = Instant::now();
    let mut a = Peer::new("127.0.0.1:41001".parse()?, now)?;
    let mut b = Peer::new("127.0.0.1:41002".parse()?, now)?;
    // A carries a first channel so the association exists before the channels under test.
    a.pc.create_data_channel("control", None)?;
    let offer = a.pc.create_offer(None)?;
    a.pc.set_local_description(now, offer.clone())?;
    b.pc.set_remote_description(now, offer)?;
    let answer = b.pc.create_answer(None)?;
    b.pc.set_local_description(now, answer.clone())?;
    a.pc.set_remote_description(now, answer)?;
    let mut link = Link {
        a,
        b,
        now,
        to_a: VecDeque::new(),
        to_b: VecDeque::new(),
    };
    link.pump_until("connect", |l| {
        l.a.connected && l.b.connected && !l.a.opened.is_empty() && !l.b.opened.is_empty()
    })?;
    Ok(link)
}

fn stream_id(peer: &mut Peer, id: RTCDataChannelId) -> Option<StreamId> {
    peer.pc.data_channel(id).and_then(|dc| dc.stream_id())
}

#[test]
fn channel_created_while_a_remote_close_is_in_flight_opens() -> Result<()> {
    let mut link = connect()?;

    // A opens X and Y; B learns both.
    let x = link.a.pc.create_data_channel("x", None)?.id();
    let y = link.a.pc.create_data_channel("y", None)?.id();
    link.pump_until("x and y open", |l| {
        l.a.opened.contains(&x) && l.a.opened.contains(&y) && l.b.opened.len() >= 3
    })?;
    let x_stream = stream_id(&mut link.a, x).expect("x has a stream id");
    let b_x = *link
        .b
        .opened
        .iter()
        .find(|id| {
            link.b
                .pc
                .data_channel(**id)
                .is_some_and(|dc| dc.label() == "x")
        })
        .expect("B opened x");

    // 1. B closes X: its outgoing reset of S (H1) goes to A.
    link.b.pc.data_channel(b_x).expect("B's x").close()?;
    let h1 = link.b.outbound();
    assert!(!h1.is_empty(), "B's close must send its reset");
    let now = link.now;
    link.a.deliver(now, h1);
    link.a.drain_events();

    // 2. A's answer (its outgoing reset of S, and the response to H1) goes to B.
    let o1 = link.a.outbound();
    link.b.deliver(now, o1);
    link.b.drain_events();

    // 3. Whatever B sends in answer is held in flight.
    let held = link.b.outbound();

    // 4. A creates C while B's answer is in flight.
    let c = link.a.pc.create_data_channel("c", None)?.id();
    let c_stream = stream_id(&mut link.a, c);
    let c_open = link.a.outbound();

    // 5. B's held answer reaches A first, then C's OPEN reaches B; then the link runs normally.
    link.a.deliver(now, held);
    link.a.drain_events();
    link.b.deliver(now, c_open);
    link.b.drain_events();
    let settled = link.pump_until("c opens or closes", |l| {
        l.a.opened.contains(&c) || l.a.closed.contains(&c)
    });

    assert!(
        !link.a.closed.contains(&c) || link.a.opened.contains(&c),
        "C (stream {c_stream:?}; X had stream {x_stream}) closed before it opened",
    );
    settled?;
    assert!(link.a.opened.contains(&c), "C must open");
    Ok(())
}
