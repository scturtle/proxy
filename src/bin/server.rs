use proxy::read_addr_from;

use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::Item as KeyItem;
use std::io::{BufReader, Error as IoError, ErrorKind, Result as IoResult};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

type TlsStream = tokio_rustls::TlsStream<TcpStream>;

fn load_cert_key(cert: &str, key: &str) -> IoResult<(Vec<Certificate>, PrivateKey)> {
    let mut reader = BufReader::new(std::fs::File::open(cert)?);
    let certs = rustls_pemfile::certs(&mut reader)?;
    let certs = certs.into_iter().map(Certificate).collect();
    let mut reader = BufReader::new(std::fs::File::open(key)?);
    let Some(key) = rustls_pemfile::read_one(&mut reader)? else {
        return Err(IoError::new(ErrorKind::Other, "private key not found"));
    };
    let key = match key {
        KeyItem::RSAKey(key) => key,
        KeyItem::PKCS8Key(key) => key,
        KeyItem::ECKey(key) => key,
        _ => {
            return Err(IoError::new(ErrorKind::Other, "unknown private key type"));
        }
    };
    let key = PrivateKey(key);
    Ok((certs, key))
}

pub fn make_server_config() -> IoResult<ServerConfig> {
    let (certs, key) = load_cert_key("cert.pem", "key.pem")?;
    let cfg = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| IoError::new(ErrorKind::Other, err.to_string()))?;
    Ok(cfg)
}

struct Connection {
    stream: TlsStream,
}

impl Connection {
    async fn handle(&mut self) -> IoResult<()> {
        let mut buf = [0u8; 56];
        self.stream.read_exact(&mut buf).await?;
        // TODO: verify
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

#[tokio::main]
async fn main() -> IoResult<()> {
    let server_config = make_server_config()?;
    let tls_acceptor = TlsAcceptor::from(std::sync::Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:5000").await?;
    loop {
        let (stream, _) = listener.accept().await?;
        let stream = tls_acceptor.accept(stream).await?;
        let stream = tokio_rustls::TlsStream::Server(stream);
        let mut conn = Connection { stream };
        tokio::spawn(async move {
            match conn.handle().await {
                Ok(()) => {}
                Err(err) => eprintln!("{err}"),
            }
        });
    }
}
