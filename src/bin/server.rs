use log::error;
use proxy::read_addr_from;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::Item as KeyItem;
use sha2::{Digest, Sha224};
use std::io::{BufReader, Error as IoError, ErrorKind, Result as IoResult};
use std::net::{SocketAddr, ToSocketAddrs};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

fn load_cert_key(certfile: &str, keyfile: &str) -> (Vec<Certificate>, PrivateKey) {
    let mut reader = BufReader::new(std::fs::File::open(certfile).expect("certfile not found"));
    let certs = rustls_pemfile::certs(&mut reader).expect("parse certfile failed");
    let certs = certs.into_iter().map(Certificate).collect();
    let mut reader = BufReader::new(std::fs::File::open(keyfile).expect("keyfile not found"));
    let key = rustls_pemfile::read_one(&mut reader)
        .expect("parse keyfile failed")
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

pub fn make_server_config(certfile: &str, keyfile: &str) -> ServerConfig {
    let (certs, key) = load_cert_key(certfile, keyfile);
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
    async fn handle(&mut self) -> IoResult<()> {
        let mut buf = [0u8; 56];
        self.stream.read_exact(&mut buf).await?;
        if buf != self.secret.as_ref() {
            error!("[{}] not authorized", self.client);
            let mut target = TcpStream::connect(self.remote).await?;
            target.write_all(&buf).await?;
            let _ = tokio::io::copy_bidirectional(&mut target, &mut self.stream).await;
            return Ok(());
        }
        let _ = self.stream.read_u16().await?;
        let command = self.stream.read_u8().await?;
        if command != 1 {
            return Err(IoError::new(ErrorKind::Other, "not connect command"));
        }
        let address = read_addr_from(&mut self.stream).await?;
        let _ = self.stream.read_u16().await?;
        let mut target = TcpStream::connect(address).await?;
        let _ = tokio::io::copy_bidirectional(&mut target, &mut self.stream).await;
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
    certfile: String,
    #[arg(long, default_value = "/etc/cert/key.pem")]
    keyfile: String,
    #[arg(long, default_value = "")]
    secret: String,
}

#[tokio::main(worker_threads = 4)]
async fn main() -> IoResult<()> {
    env_logger::init();

    let args = std::sync::Arc::new(Args::parse());
    let remote = args
        .remote
        .to_socket_addrs()?
        .next()
        .expect("bad remote addr");
    let secret: Vec<u8> = Sha224::digest(args.secret.as_bytes())
        .iter()
        .flat_map(|x| format!("{:02x}", x).into_bytes())
        .collect();

    let server_config = make_server_config(&args.certfile, &args.keyfile);
    let tls_acceptor = TlsAcceptor::from(std::sync::Arc::new(server_config));
    let listener = TcpListener::bind(&args.local).await?;

    loop {
        let (stream, client) = listener.accept().await?;
        let stream = match tls_acceptor.accept(stream).await {
            Ok(stream) => stream,
            Err(err) => {
                error!("[{client}] tls: {err}");
                continue;
            }
        };
        let mut conn = Connection {
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
