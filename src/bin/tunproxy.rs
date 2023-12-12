use futures::{SinkExt, StreamExt};
use priority_queue::PriorityQueue;
use smoltcp::{
    iface::{Interface, SocketSet},
    phy::{
        Checksum, ChecksumCapabilities, Device as SmolDevice, DeviceCapabilities, Medium, RxToken,
        TxToken,
    },
    socket::{
        tcp::{self, State as TcpState},
        udp, Socket,
    },
    time::Instant as SmolInstant,
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, IpProtocol, IpVersion,
        Ipv4Address, Ipv4Packet, Ipv6Address, TcpPacket, UdpPacket,
    },
};
use std::{
    cmp::Reverse,
    collections::{hash_map::Entry, HashMap, VecDeque},
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_util::codec::Framed;
use tun::{self, AsyncDevice, Device as TunDevice, TunPacket, TunPacketCodec};

const TUN: &str = "utun1989";
const MTU: usize = 1500;
const TCP_BUFSIZE: usize = 64 * 1024;
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const TCP_HALFOPEN_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const TCP_MAX_SEGMENT_LIFE: Duration = Duration::from_secs(2 * 60);
const TCP_ESTABLISH_WAIT: Duration = Duration::from_secs(15);

fn capabilities() -> DeviceCapabilities {
    let mut capabilities = DeviceCapabilities::default();
    capabilities.medium = Medium::Ip;
    capabilities.max_transmission_unit = MTU;
    capabilities.checksum = ChecksumCapabilities::ignored();
    capabilities.checksum.ipv4 = Checksum::Tx;
    capabilities.checksum.tcp = Checksum::Tx;
    capabilities.checksum.udp = Checksum::Tx;
    capabilities
}

struct DummyDevice {}

impl SmolDevice for DummyDevice {
    type RxToken<'a> = DummyRxToken;
    type TxToken<'a> = DummyTxToken;
    fn receive(&mut self, _: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        None
    }
    fn transmit(&mut self, _: SmolInstant) -> Option<Self::TxToken<'_>> {
        None
    }
    fn capabilities(&self) -> DeviceCapabilities {
        capabilities()
    }
}

pub struct DummyRxToken {}
pub struct DummyTxToken {}

impl RxToken for DummyRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut [])
    }
}

impl TxToken for DummyTxToken {
    fn consume<R, F>(self, _: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut [])
    }
}

struct PacketQ {
    rx_pkt: Option<Vec<u8>>,
    tx_sender: mpsc::UnboundedSender<Vec<u8>>,
}

impl PacketQ {
    fn new(rx_pkt: Option<Vec<u8>>, tx_sender: mpsc::UnboundedSender<Vec<u8>>) -> Self {
        Self { rx_pkt, tx_sender }
    }
}

impl SmolDevice for PacketQ {
    type RxToken<'a> = PqRxToken where Self: 'a;
    type TxToken<'a> = PqTxToken<'a> where Self: 'a;

    fn receive(&mut self, _: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(rx_pkt) = self.rx_pkt.take() {
            let rx = PqRxToken { rx_pkt };
            let tx = PqTxToken(self);
            Some((rx, tx))
        } else {
            None
        }
    }

    fn transmit(&mut self, _: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(PqTxToken(self))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        capabilities()
    }
}

struct PqRxToken {
    rx_pkt: Vec<u8>,
}

impl RxToken for PqRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(self.rx_pkt.as_mut_slice())
    }
}

struct PqTxToken<'a>(&'a mut PacketQ);

impl<'a> TxToken for PqTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        let _ = self.0.tx_sender.send(buffer); // l3_tx()
        result
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Flow {
    pub source_ip: IpAddress,
    pub source_port: u16,
    pub dest_ip: IpAddress,
    pub dest_port: u16,
    pub protocol: IpProtocol,
}

impl std::fmt::Display for Flow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {}:{} => {}:{}",
            self.protocol, self.source_ip, self.source_port, self.dest_ip, self.dest_port
        )
    }
}

struct Handle {
    socket: Option<Socket<'static>>,
    endpoint: Option<IpEndpoint>,
    last_rxtx: Instant,
    poll_at: Instant,
}

impl Handle {
    fn new(flow: Flow) -> Self {
        let socket = if flow.protocol == IpProtocol::Tcp {
            let rx = tcp::SocketBuffer::new(vec![0u8; TCP_BUFSIZE]);
            let tx = tcp::SocketBuffer::new(vec![0u8; TCP_BUFSIZE]);
            let mut socket = tcp::Socket::new(rx, tx);
            socket.listen(flow.dest_port).expect("tcp listen");
            Some(Socket::Tcp(socket))
        } else {
            assert_eq!(flow.protocol, IpProtocol::Udp);
            let rxm = vec![udp::PacketMetadata::EMPTY; 1];
            let txm = vec![udp::PacketMetadata::EMPTY; 1];
            let rx = udp::PacketBuffer::new(rxm, vec![0u8; 2 * MTU]);
            let tx = udp::PacketBuffer::new(txm, vec![0u8; 2 * MTU]);
            let mut socket = udp::Socket::new(rx, tx);
            socket
                .bind(IpListenEndpoint {
                    addr: Some(flow.dest_ip),
                    port: flow.dest_port,
                })
                .expect("udp bind");
            Some(Socket::Udp(socket))
        };
        Self {
            socket,
            endpoint: None,
            last_rxtx: Instant::now(),
            poll_at: Instant::now(),
        }
    }

    fn idle_timeout(&self) -> Duration {
        match &self.socket {
            Some(Socket::Tcp(sock)) => match sock.state() {
                TcpState::Established => TCP_IDLE_TIMEOUT,
                TcpState::TimeWait => TCP_MAX_SEGMENT_LIFE,
                TcpState::Listen | TcpState::SynReceived | TcpState::SynSent | TcpState::Closed => {
                    TCP_ESTABLISH_WAIT
                }
                TcpState::CloseWait
                | TcpState::FinWait1
                | TcpState::FinWait2
                | TcpState::LastAck
                | TcpState::Closing => TCP_HALFOPEN_IDLE_TIMEOUT,
            },
            Some(Socket::Udp(_)) => UDP_IDLE_TIMEOUT,
            _ => UDP_IDLE_TIMEOUT,
        }
    }

    #[allow(dead_code)]
    fn close(&mut self) {
        if let Some(Socket::Tcp(sock)) = &mut self.socket {
            sock.close()
        }
    }

    fn state(&self) -> TcpState {
        match &self.socket {
            Some(Socket::Tcp(sock)) => sock.state(),
            _ => TcpState::Established,
        }
    }

    fn read(&mut self, l4_rx_data: &mut VecDeque<Vec<u8>>) {
        match self.socket.as_mut().unwrap() {
            Socket::Udp(sock) => match sock.recv() {
                Ok((data, udp::UdpMetadata { endpoint, .. })) => {
                    self.endpoint = Some(endpoint);
                    l4_rx_data.push_back(data.into());
                    self.last_rxtx = Instant::now();
                }
                Err(udp::RecvError::Exhausted) => {}
            },
            Socket::Tcp(sock) => {
                if sock.can_recv() {
                    match sock.recv(|data| {
                        l4_rx_data.push_back(data.into());
                        (data.len(), data.len())
                    }) {
                        Ok(_) => {
                            self.last_rxtx = Instant::now();
                        }
                        Err(_) => {}
                    }
                }
            }
            _ => {}
        }
    }

    fn write(&mut self, data: &[u8]) -> Option<usize> {
        match self.socket.as_mut().unwrap() {
            Socket::Udp(sock) => {
                let Some(endpoint) = self.endpoint.as_ref() else {
                    return None;
                };
                match sock.send_slice(data, *endpoint) {
                    Ok(()) => {
                        self.last_rxtx = Instant::now();
                        Some(data.len())
                    }
                    Err(udp::SendError::BufferFull) => Some(0),
                    Err(udp::SendError::Unaddressable) => None,
                }
            }
            Socket::Tcp(sock) => {
                if sock.can_send() {
                    match sock.send_slice(data) {
                        Ok(size) => {
                            if size > 0 {
                                self.last_rxtx = Instant::now();
                            }
                            Some(size)
                        }
                        Err(tcp::SendError::InvalidState) => None,
                    }
                } else {
                    Some(0)
                }
            }
            _ => None,
        }
    }

    fn poll(
        &mut self,
        iface: &mut Interface,
        time: Instant,
        l3_rx_pkt: Option<Vec<u8>>,
        l4_rx_data: &mut VecDeque<Vec<u8>>,
        l3_tx_sender: mpsc::UnboundedSender<Vec<u8>>,
    ) -> Instant {
        let has_l3_rx = l3_rx_pkt.is_some();
        let mut pktq = PacketQ::new(l3_rx_pkt, l3_tx_sender);
        let mut socket_set = SocketSet::new(vec![]);
        let handle = match self.socket.take().unwrap() {
            Socket::Udp(sock) => socket_set.add(sock),
            Socket::Tcp(sock) => socket_set.add(sock),
            _ => {
                unreachable!()
            }
        };
        let smol_time: SmolInstant = time.into();
        let mut poll_at = Some(smol_time);
        let changed = iface.poll(smol_time, &mut pktq, &mut socket_set);
        if !changed {
            poll_at = iface.poll_at(smol_time, &socket_set);
        }
        self.socket = Some(socket_set.remove(handle));

        // l3_rx => l4_rx
        if has_l3_rx {
            self.read(l4_rx_data);
        }

        let poll_at = match poll_at {
            Some(poll_at) => {
                if poll_at == SmolInstant::ZERO {
                    time // now
                } else {
                    time + (poll_at - smol_time).into()
                }
            }
            None => time + self.idle_timeout(),
        };
        self.poll_at = poll_at;
        poll_at
    }
}

struct TunProxy {
    device: Framed<AsyncDevice, TunPacketCodec>,
    iface: Interface,
    flows: HashMap<Flow, Handle>,
    polling: PriorityQueue<Flow, Reverse<Instant>>,
    l4_rx: HashMap<Flow, VecDeque<Vec<u8>>>,
    l3_tx_sender: mpsc::UnboundedSender<Vec<u8>>,
    l3_tx_receiver: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl TunProxy {
    fn new(device: Framed<AsyncDevice, TunPacketCodec>) -> Self {
        let dummy_v4 = Ipv4Address::new(0, 0, 0, 1);
        let dummy_v6 = Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1);
        let iface_config = smoltcp::iface::Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(iface_config, &mut DummyDevice {}, SmolInstant::now());
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs.push(IpCidr::new(dummy_v4.into(), 0)).unwrap();
            ip_addrs.push(IpCidr::new(dummy_v6.into(), 0)).unwrap()
        });
        iface.routes_mut().add_default_ipv4_route(dummy_v4).unwrap();
        iface.routes_mut().add_default_ipv6_route(dummy_v6).unwrap();
        iface.set_any_ip(true);

        let (l3_tx_sender, l3_tx_receiver) = mpsc::unbounded_channel();

        Self {
            device,
            iface,
            flows: Default::default(),
            polling: Default::default(),
            l4_rx: Default::default(),
            l3_tx_sender,
            l3_tx_receiver,
        }
    }

    fn l3_parse(frame: &[u8]) -> Option<Flow> {
        match IpVersion::of_packet(frame).ok()? {
            IpVersion::Ipv4 => {
                let packet = Ipv4Packet::new_unchecked(frame);
                let source_ip = IpAddress::from(packet.src_addr());
                let dest_ip = IpAddress::from(packet.dst_addr());
                match packet.next_header() {
                    IpProtocol::Tcp => {
                        let tcp_packet = TcpPacket::new_checked(packet.payload()).ok()?;
                        Some(Flow {
                            source_ip,
                            source_port: tcp_packet.src_port(),
                            dest_ip,
                            dest_port: tcp_packet.dst_port(),
                            protocol: IpProtocol::Tcp,
                        })
                    }
                    IpProtocol::Udp => {
                        let udp_packet = UdpPacket::new_checked(packet.payload()).ok()?;
                        Some(Flow {
                            source_ip,
                            source_port: udp_packet.src_port(),
                            dest_ip,
                            dest_port: udp_packet.dst_port(),
                            protocol: IpProtocol::Udp,
                        })
                    }
                    _ => None,
                }
            }
            IpVersion::Ipv6 => None,
        }
    }

    fn l3_rx(&mut self, pkt: TunPacket) -> Option<Flow> {
        let pkt: Vec<u8> = pkt.into_bytes().into_iter().collect();
        let now = Instant::now();
        let flow = Self::l3_parse(&pkt)?;
        let handle: &mut Handle = match self.flows.entry(flow) {
            Entry::Occupied(o) => o.into_mut(),
            Entry::Vacant(e) => {
                self.polling.push(flow, Reverse(now));
                e.insert(Handle::new(flow))
            }
        };
        let poll_at = handle.poll(
            &mut self.iface,
            now,
            Some(pkt),
            self.l4_rx.entry(flow).or_default(),
            self.l3_tx_sender.clone(),
        );
        self.polling.change_priority(&flow, Reverse(poll_at));
        Some(flow)
    }

    fn remove(&mut self, flow: &Flow) {
        log::info!("remove flow {flow}");
        self.flows.remove(flow);
        self.polling.remove(flow);
        self.l4_rx.remove(flow);
    }

    fn poll_all(&mut self) -> Option<Instant> {
        let now = Instant::now();
        loop {
            let Some((&flow, _)) = self.polling.peek() else {
                return None;
            };
            let handle = self.flows.get_mut(&flow).expect("handle not found");
            if handle.poll_at > now {
                // next time to poll
                return Some(handle.poll_at);
            }
            let poll_at = handle.poll(
                &mut self.iface,
                now,
                None,
                self.l4_rx.entry(flow).or_default(),
                self.l3_tx_sender.clone(),
            );
            self.polling.change_priority(&flow, Reverse(poll_at));
            log::info!("poll_all {} {}", flow, handle.state());
            if handle.last_rxtx.elapsed() > handle.idle_timeout() {
                self.remove(&flow);
            }
        }
    }

    async fn l4_tx(&mut self, flow: &Flow, l4_data: &[u8]) -> Option<usize> {
        if let Some(handle) = self.flows.get_mut(flow) {
            // l4_tx => l3_tx
            let ret = handle.write(l4_data);
            let poll_at = handle.poll(
                &mut self.iface,
                Instant::now(),
                None,
                self.l4_rx.entry(*flow).or_default(),
                self.l3_tx_sender.clone(),
            );
            self.polling.change_priority(flow, Reverse(poll_at));
            ret
        } else {
            None
        }
    }

    async fn transmit_data(&mut self, flow: &Flow) {
        while let Some(l4_data) = self.l4_rx.get_mut(flow).and_then(|q| q.pop_front()) {
            if let Some(size) = self.l4_tx(flow, &l4_data).await {
                if size != l4_data.len() {
                    // retry later
                    if let Some(q) = self.l4_rx.get_mut(flow) {
                        q.push_front(l4_data.into_iter().skip(size).collect());
                    }
                }
            }
        }
    }

    async fn run(&mut self) {
        loop {
            let wakeup = match self.poll_all() {
                Some(wakeup) => wakeup,
                None => Instant::now() + Duration::from_secs(86400),
            };
            tokio::select! {
                _ = sleep(wakeup - Instant::now()) => {
                    log::info!("wake");
                }
                Some(Ok(pkt)) = self.device.next() => {
                    log::info!("pkt");
                    if let Some(flow) = self.l3_rx(pkt) {
                        self.transmit_data(&flow).await;
                    }
                }
                Some(pkt) = self.l3_tx_receiver.recv() => {
                    let _ = self.device.send(TunPacket::new(pkt)).await;
                }
            }
        }
    }
}

fn new_tun() -> Framed<AsyncDevice, TunPacketCodec> {
    let mut config = tun::Configuration::default();
    config
        .name(TUN)
        .mtu(MTU as i32)
        .address((10, 255, 0, 1))
        .destination((10, 255, 0, 1))
        .netmask((255, 255, 255, 0))
        .layer(tun::Layer::L3)
        .up();
    let tun = tun::create_as_async(&config).unwrap();
    log::info!("{}", tun.get_ref().name().unwrap());
    tun.into_framed()
}

#[tokio::main]
async fn main() {
    let env = env_logger::Env::default().default_filter_or("info");
    env_logger::Builder::from_env(env).init();
    let device = new_tun();
    let mut tun_proxy = TunProxy::new(device);
    tun_proxy.run().await;
}
