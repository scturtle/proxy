use futures::{SinkExt, StreamExt};
use smoltcp::{
    iface::{Interface, SocketHandle, SocketSet},
    phy::{
        Checksum, ChecksumCapabilities, Device as SmolDevice, DeviceCapabilities, Medium, RxToken,
        TxToken,
    },
    socket::{
        tcp::{self, State as TcpState},
        Socket,
    },
    storage::RingBuffer,
    time::{Duration as SmolDuration, Instant as SmolInstant},
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpProtocol, IpVersion, Ipv4Address, Ipv4Packet,
        Ipv6Address, TcpPacket,
    },
};
use spin::mutex::SpinMutex;
use std::{
    collections::{HashMap, HashSet},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    thread::{self, Thread},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpSocket,
    sync::mpsc,
};
use tokio_util::codec::Framed;
use tun::{self, AsyncDevice, Device as TunDevice, TunPacket, TunPacketCodec};

const TUN: &str = "utun1989";
const MTU: usize = 1500;
const TCP_BUFSIZE: usize = 64 * 1024;

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

struct VirtDevice {
    l3_rx_receiver: mpsc::UnboundedReceiver<Vec<u8>>,
    l3_tx_sender: mpsc::UnboundedSender<Vec<u8>>,
}

impl VirtDevice {
    fn new(
        rx_receiver: mpsc::UnboundedReceiver<Vec<u8>>,
        tx_sender: mpsc::UnboundedSender<Vec<u8>>,
    ) -> Self {
        Self {
            l3_rx_receiver: rx_receiver,
            l3_tx_sender: tx_sender,
        }
    }
}

impl SmolDevice for VirtDevice {
    type RxToken<'a> = PqRxToken where Self: 'a;
    type TxToken<'a> = PqTxToken<'a> where Self: 'a;

    fn receive(&mut self, _: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Ok(pkt) = self.l3_rx_receiver.try_recv() {
            let rx = PqRxToken { pkt };
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
    pkt: Vec<u8>,
}

impl RxToken for PqRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(self.pkt.as_mut_slice())
    }
}

struct PqTxToken<'a>(&'a mut VirtDevice);

impl<'a> TxToken for PqTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        let _ = self.0.l3_tx_sender.send(buffer);
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

struct Control {
    send_buffer: RingBuffer<'static, u8>,
    send_waker: Option<Waker>,
    recv_buffer: RingBuffer<'static, u8>,
    recv_waker: Option<Waker>,
    last_rxtx: Instant,
    polling_thread: Thread,
}

impl Control {
    fn new(polling_thread: Thread) -> Self {
        Self {
            send_buffer: RingBuffer::new(vec![0u8; 4 * TCP_BUFSIZE]),
            send_waker: None,
            recv_buffer: RingBuffer::new(vec![0u8; 4 * TCP_BUFSIZE]),
            recv_waker: None,
            last_rxtx: Instant::now(),
            polling_thread,
        }
    }
}

#[derive(Clone)]
struct Connection {
    flow: Flow,
    control: Arc<SpinMutex<Control>>,
}

impl Connection {
    fn new(flow: Flow, polling_thread: Thread) -> Self {
        let control = Arc::new(SpinMutex::new(Control::new(polling_thread)));
        Self { flow, control }
    }
}

impl AsyncRead for Connection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut control = self.control.lock();
        if control.recv_buffer.is_empty() {
            if let Some(old_waker) = control.recv_waker.replace(cx.waker().clone()) {
                if !old_waker.will_wake(cx.waker()) {
                    old_waker.wake();
                }
            }
            return Poll::Pending;
        }
        let n = control.recv_buffer.dequeue_slice(buf.initialize_unfilled());
        buf.advance(n);
        // log::info!("socket => external");
        control.last_rxtx = Instant::now();
        // log::info!("unpark in async read");
        control.polling_thread.unpark();
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut control = self.control.lock();
        if control.send_buffer.is_full() {
            if let Some(old_waker) = control.send_waker.replace(cx.waker().clone()) {
                if !old_waker.will_wake(cx.waker()) {
                    old_waker.wake();
                }
            }
            return Poll::Pending;
        }
        let n = control.send_buffer.enqueue_slice(buf);
        // log::info!("external => socket");
        control.last_rxtx = Instant::now();
        // log::info!("unpark in async write");
        control.polling_thread.unpark();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn idle_timeout(state: TcpState) -> Duration {
    const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
    const TCP_HALFOPEN_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
    const TCP_MAX_SEGMENT_LIFE: Duration = Duration::from_secs(2 * 60);
    const TCP_ESTABLISH_WAIT: Duration = Duration::from_secs(15);
    match state {
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
    }
}

async fn tcp_copy_bidir<A: AsyncRead + AsyncWrite, B: AsyncRead + AsyncWrite>(a: A, b: B) {
    let (mut a_r, mut a_w) = tokio::io::split(a);
    let (mut b_r, mut b_w) = tokio::io::split(b);
    tokio::select!(
        _ = tokio::io::copy(&mut a_r, &mut b_w) => (),
        _ = tokio::io::copy(&mut b_r, &mut a_w) => (),
    );
}

struct TunProxy {
    device: Framed<AsyncDevice, TunPacketCodec>,
    l3_rx_sender: mpsc::UnboundedSender<Vec<u8>>,
    l3_tx_receiver: mpsc::UnboundedReceiver<Vec<u8>>,
    socket_set: Arc<SpinMutex<SocketSet<'static>>>,
    flows: Arc<SpinMutex<HashSet<Flow>>>,
    connections: Arc<SpinMutex<HashMap<SocketHandle, Connection>>>,
    polling_thread: Thread,
}

impl TunProxy {
    fn new(device: Framed<AsyncDevice, TunPacketCodec>) -> Self {
        let (l3_rx_sender, l3_rx_receiver) = mpsc::unbounded_channel();
        let (l3_tx_sender, l3_tx_receiver) = mpsc::unbounded_channel();
        let virt_device = VirtDevice::new(l3_rx_receiver, l3_tx_sender);

        let socket_set = Arc::new(SpinMutex::new(SocketSet::new(vec![])));
        let flows = Arc::new(SpinMutex::new(HashSet::new()));
        let connections = Arc::new(SpinMutex::new(HashMap::new()));

        let polling_thread = {
            let socket_set = socket_set.clone();
            let flows = flows.clone();
            let connections = connections.clone();
            thread::spawn(move || Self::polling(virt_device, socket_set, flows, connections))
                .thread()
                .clone()
        };

        Self {
            device,
            l3_rx_sender,
            l3_tx_receiver,
            polling_thread,
            socket_set,
            flows,
            connections,
        }
    }

    fn create_interface(virt_device: &mut VirtDevice) -> Interface {
        let iface_config = smoltcp::iface::Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(iface_config, virt_device, SmolInstant::now());
        let dummy_v4 = Ipv4Address::new(0, 0, 0, 1);
        let dummy_v6 = Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1);
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs.push(IpCidr::new(dummy_v4.into(), 0)).unwrap();
            ip_addrs.push(IpCidr::new(dummy_v6.into(), 0)).unwrap()
        });
        iface.routes_mut().add_default_ipv4_route(dummy_v4).unwrap();
        iface.routes_mut().add_default_ipv6_route(dummy_v6).unwrap();
        iface.set_any_ip(true);
        iface
    }

    fn polling(
        mut virt_device: VirtDevice,
        socket_set: Arc<SpinMutex<SocketSet<'static>>>,
        flows: Arc<SpinMutex<HashSet<Flow>>>,
        connections: Arc<SpinMutex<HashMap<SocketHandle, Connection>>>,
    ) {
        let mut iface = Self::create_interface(&mut virt_device);
        loop {
            let before_poll = SmolInstant::now();
            let updated = iface.poll(before_poll, &mut virt_device, &mut socket_set.lock());
            // log::info!("poll {updated}");
            {
                let mut socket_set = socket_set.lock();
                let mut flows = flows.lock();
                let mut connections = connections.lock();
                let mut to_removed = vec![];
                for (handle, socket) in socket_set.iter_mut() {
                    let mut control = connections.get_mut(&handle).unwrap().control.lock();
                    match socket {
                        Socket::Tcp(socket) => {
                            let mut wake_receiver = false;
                            while socket.can_recv() && !control.recv_buffer.is_full() {
                                wake_receiver = true;
                                let Ok(_) = socket.recv(|buffer| {
                                    let n = control.recv_buffer.enqueue_slice(buffer);
                                    (n, ())
                                }) else {
                                    break;
                                };
                                // log::info!("iface => socket");
                            }
                            if wake_receiver {
                                if let Some(waker) = control.recv_waker.take() {
                                    waker.wake();
                                }
                            }

                            let mut wake_sender = false;
                            while socket.can_send() && !control.send_buffer.is_empty() {
                                wake_sender = true;
                                let Ok(_) = socket.send(|buffer| {
                                    let n = control.send_buffer.dequeue_slice(buffer);
                                    (n, ())
                                }) else {
                                    break;
                                };
                                // log::info!("socket => iface");
                            }
                            if wake_sender {
                                if let Some(waker) = control.send_waker.take() {
                                    waker.wake();
                                }
                            }

                            if control.last_rxtx.elapsed() > idle_timeout(socket.state()) {
                                to_removed.push(handle);
                            }
                        }
                        _ => unreachable!(),
                    }
                }

                for handle in to_removed {
                    socket_set.remove(handle);
                    flows.remove(&connections[&handle].flow);
                    connections.remove(&handle);
                }
            }

            if !updated {
                let duration = iface
                    .poll_delay(before_poll, &socket_set.lock())
                    .unwrap_or(SmolDuration::from_millis(1000));
                // log::info!("sleep {duration}");
                if duration != SmolDuration::ZERO {
                    thread::park_timeout(duration.into());
                }
            }
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
                        None // TODO
                    }
                    _ => None,
                }
            }
            IpVersion::Ipv6 => None,
        }
    }

    async fn process_frame(&mut self, pkt: TunPacket) {
        let pkt: Vec<u8> = pkt.into_bytes().into_iter().collect();
        let Some(flow) = Self::l3_parse(&pkt) else {
            return;
        };
        if !self.flows.lock().contains(&flow) {
            log::info!("{flow}");
            let socket = {
                let rx = tcp::SocketBuffer::new(vec![0u8; TCP_BUFSIZE]);
                let tx = tcp::SocketBuffer::new(vec![0u8; TCP_BUFSIZE]);
                let mut socket = tcp::Socket::new(rx, tx);
                socket.listen(flow.dest_port).expect("tcp listen");
                socket
            };
            let socket_handle = self.socket_set.lock().add(socket);
            let connection = Connection::new(flow, self.polling_thread.clone());
            let conn = connection.clone();
            self.flows.lock().insert(flow);
            self.connections.lock().insert(socket_handle, connection);

            // FIXME: redirect to httpbin.org
            let socket = TcpSocket::new_v4().unwrap();
            let mut host = tokio::net::lookup_host("httpbin.org:80").await.unwrap();
            let host = host.next().unwrap();
            let stream = socket.connect(host).await.unwrap();
            tokio::spawn(tcp_copy_bidir(conn, stream));
        }
        self.l3_rx_sender.send(pkt).unwrap();
        // log::info!("unpark new pkt");
        self.polling_thread.unpark();
    }

    async fn run(&mut self) {
        loop {
            tokio::select! {
                Some(pkt) = self.l3_tx_receiver.recv() => {
                    self.device.send(TunPacket::new(pkt)).await.unwrap();
                }
                Some(Ok(pkt)) = self.device.next() => {
                    self.process_frame(pkt).await;
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
    env_logger::Builder::from_env(env)
        .format_timestamp_millis()
        .init();
    let device = new_tun();
    let mut tun_proxy = TunProxy::new(device);
    tun_proxy.run().await;
}
