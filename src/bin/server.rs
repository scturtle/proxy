use log::{error, info};
use proxy::Addr;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::Item as KeyItem;
use sha2::{Digest, Sha224};
use std::io::{BufReader, Error as IoError, ErrorKind, Result as IoResult};
use std::net::{SocketAddr, ToSocketAddrs};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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

pub fn make_server_config(cert: &str, key: &str) -> ServerConfig {
    let (certs, key) = load_cert_key(cert, key);
    ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("generate server config failed")
}

struct Connection {
    stream: tokio_rustls::TlsStream<TcpStream>,
    client: SocketAddr,
    secret: Vec<u8>,
    remote: SocketAddr,
}

impl Connection {
    async fn handle(self) -> IoResult<()> {
        let Self {
            mut stream, client, ..
        } = self;
        let mut buf = [0u8; 56];
        stream.read_exact(&mut buf).await?;
        if buf != self.secret.as_ref() {
            error!("[{client}] not authorized");
            let mut target = TcpStream::connect(self.remote).await?;
            target.write_all(&buf).await?;
            let _ = tokio::io::copy_bidirectional(&mut target, &mut stream).await;
            return Ok(());
        }
        let _ = stream.read_u16().await?;
        let command = stream.read_u8().await?;
        if command != 1 {
            let msg = format!("[{client}] command({command}) != 1");
            return Err(IoError::new(ErrorKind::Other, msg));
        }
        let address = Addr::read_addr_from(&mut stream).await?;
        info!("[{client}] connect to {address}");
        let address: SocketAddr = address.try_into()?;
        let _ = stream.read_u16().await?;
        let target = TcpStream::connect(address).await?;
        info!("[{client}] copy bidir");
        let (mut src_reader, mut src_writer) = tokio::io::split(stream);
        let (mut dst_reader, mut dst_writer) = tokio::io::split(target);
        tokio::select!(
            _ = tokio::io::copy(&mut src_reader, &mut dst_writer) => (),
            _ = tokio::io::copy(&mut dst_reader, &mut src_writer) => (),
        );
        info!("[{client}] copy bidir done");
        Ok(())
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

    let server_config = make_server_config(&cert, &key);
    let tls_acceptor = TlsAcceptor::from(std::sync::Arc::new(server_config));
    let listener = TcpListener::bind(&local).await?;

    loop {
        let (stream, client) = listener.accept().await?;
        info!("[{client}] new");
        let stream = match tls_acceptor.accept(stream).await {
            Ok(stream) => stream,
            Err(err) => {
                error!("[{client}] tls: {err}");
                continue;
            }
        };
        let conn = Connection {
            stream: tokio_rustls::TlsStream::Server(stream),
            client,
            secret: secret.clone(),
            remote,
        };
        tokio::spawn(async move {
            if let Err(err) = conn.handle().await {
                error!("[{client}] err: {err}");
            }
        });
    }
}
