use log::{error, info};
use proxy::Addr;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::Item as KeyItem;
use sha2::{Digest, Sha224};
use std::io::{BufReader, Error as IoError, ErrorKind, Result as IoResult};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::TlsAcceptor;

fn load_cert_key(cert: &str, key: &str) -> (Vec<Certificate>, PrivateKey) {
    let mut reader = BufReader::new(std::fs::File::open(cert).expect("cert not found"));
    let certs = rustls_pemfile::certs(&mut reader).expect("parse cert failed");
    let certs = certs.into_iter().map(Certificate).collect();
    let mut reader = BufReader::new(std::fs::File::open(key).expect("key not found"));
    let key = rustls_pemfile::read_one(&mut reader)
        .expect("parse key failed")
        .expect("no key found");
    let key = match key {
        KeyItem::RSAKey(key) => key,
        KeyItem::PKCS8Key(key) => key,
        KeyItem::ECKey(key) => key,
        _ => {
            panic!("unknown private key type");
        }
    };
    let key = PrivateKey(key);
    (certs, key)
}

fn make_server_config(cert: &str, key: &str) -> ServerConfig {
    let (certs, key) = load_cert_key(cert, key);
    ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("generate server config failed")
}

async fn tcp_copy_bidir<A: AsyncRead + AsyncWrite, B: AsyncRead + AsyncWrite>(a: A, b: B) {
    let (mut a_r, mut a_w) = tokio::io::split(a);
    let (mut b_r, mut b_w) = tokio::io::split(b);
    tokio::select!(
        _ = tokio::io::copy(&mut a_r, &mut b_w) => (),
        _ = tokio::io::copy(&mut b_r, &mut a_w) => (),
    );
}

async fn client_to_udp<R: AsyncRead + Unpin>(mut client: R, outbound: &UdpSocket) -> IoResult<()> {
    loop {
        let addr = Addr::read_addr_from(&mut client).await?;
        let target: SocketAddr = addr.try_into()?;
        let size = client.read_u16().await?;
        let _ = client.read_u16().await?;
        let mut buf = vec![0u8; size as usize];
        if 0 == client.read_exact(&mut buf).await? {
            return Ok(());
        }
        outbound.send_to(&buf, target).await?;
    }
}

async fn udp_to_client<W: AsyncWrite + Unpin>(outbound: &UdpSocket, mut client: W) -> IoResult<()> {
    let mut buffer = [0u8; 0x4000];
    loop {
        let (size, addr) = outbound.recv_from(&mut buffer).await?;
        if size == 0 {
            return Ok(());
        }
        Addr::Socket(addr).write_to(&mut client).await?;
        client.write_u16(size as u16).await?;
        client.write_u16(0x0D0A).await?;
        client.write_all(&buffer[..size]).await?;
    }
}

async fn udp_copy_bidir<A: AsyncRead + AsyncWrite>(a: A, outbound: UdpSocket) {
    let (mut reader, mut writer) = tokio::io::split(a);
    tokio::select!(
        _ = client_to_udp(&mut reader, &outbound) => (),
        _ = udp_to_client(&outbound, &mut writer) => (),
    );
}

struct Connection {
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    client: SocketAddr,
    secret: Arc<Vec<u8>>,
    remote: SocketAddr,
}

impl Connection {
    async fn handle(self) -> IoResult<()> {
        let Self {
            mut stream, client, ..
        } = self;
        let mut buf = [0u8; 56];
        stream.read_exact(&mut buf).await?;
        if buf != self.secret.as_slice() {
            error!("[{client}] not authorized");
            let mut target = TcpStream::connect(self.remote).await?;
            target.write_all(&buf).await?;
            tcp_copy_bidir(target, stream).await;
            return Ok(());
        }
        let _ = stream.read_u16().await?;
        let command = stream.read_u8().await?;
        let addr = Addr::read_addr_from(&mut stream).await?;
        let _ = stream.read_u16().await?;
        if command == 1 {
            info!("[{client}] tcp to {addr}");
            let addr: SocketAddr = addr.try_into()?;
            let target = TcpStream::connect(addr).await?;
            tcp_copy_bidir(target, stream).await;
            info!("[{client}] done");
            Ok(())
        } else if command == 3 {
            info!("[{client}] udp to {addr}");
            let outbound = UdpSocket::bind("0.0.0.0:0").await?;
            udp_copy_bidir(stream, outbound).await;
            info!("[{client}] done");
            Ok(())
        } else {
            let msg = format!("[{client}] unknown command {command}");
            Err(IoError::new(ErrorKind::Other, msg))
        }
    }
}

use clap::Parser;
#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:443")]
    local: String,
    #[arg(long, default_value = "127.0.0.1:80")]
    remote: String,
    #[arg(long, default_value = "/etc/cert/fullchain.pem")]
    cert: String,
    #[arg(long, default_value = "/etc/cert/key.pem")]
    key: String,
    #[arg(long, default_value = "")]
    secret: String,
}

#[tokio::main(worker_threads = 4)]
async fn main() -> IoResult<()> {
    env_logger::init();
    let Args {
        local,
        remote,
        cert,
        key,
        secret,
    } = Args::parse();
    let remote = remote.to_socket_addrs()?.next().expect("bad remote addr");
    let secret: Vec<u8> = Sha224::digest(secret.as_bytes())
        .iter()
        .flat_map(|x| format!("{:02x}", x).into_bytes())
        .collect();
    let secret = Arc::new(secret);

    let server_config = Arc::new(make_server_config(&cert, &key));
    let tls_acceptor = TlsAcceptor::from(server_config);
    let tcp_listener = TcpListener::bind(&local).await?;

    loop {
        let (tcp_stream, client) = tcp_listener.accept().await?;
        info!("[{client}] new");
        let secret = secret.clone();
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            let stream = match tls_acceptor.accept(tcp_stream).await {
                Err(err) => {
                    return error!("[{client}] tls err: {err}");
                }
                Ok(stream) => stream,
            };
            info!("[{client}] tls ok");
            let conn = Connection {
                stream,
                client,
                secret,
                remote,
            };
            if let Err(err) = conn.handle().await {
                error!("[{client}] err: {err}");
            }
        });
    }
}
