use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[repr(u8)]
enum Reply {
    Succeeded = 0x0,
    HostUnreachable = 0x4,
    CommandNotSupported = 0x7,
}

struct Connection {
    stream: TcpStream,
}

impl Connection {
    async fn auth(&mut self) -> IoResult<()> {
        let mut buf = [0u8; 8];
        self.stream.read_exact(&mut buf[..2]).await?;
        let len = buf[1] as usize;
        self.stream.read_exact(&mut buf[..len]).await?;
        let buf = [5, 0]; // no auth
        self.stream.write_all(&buf).await
    }
    async fn reply(&mut self, reply: Reply) -> IoResult<()> {
        let buf = [5, reply as u8, 0, 1, 0, 0, 0, 0, 0, 0];
        self.stream.write_all(&buf).await
    }
    async fn shutdown(&mut self) -> IoResult<()> {
        self.stream.shutdown().await
    }
}

enum Address {
    Socket(SocketAddr),
    Domain(Vec<u8>, u16),
}

impl Address {
    async fn read_from<R: AsyncRead + Unpin>(r: &mut R) -> IoResult<Self> {
        match r.read_u8().await? {
            0x01 => {
                let mut buf = [0u8; 4];
                r.read_exact(&mut buf).await?;
                let addr = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = r.read_u16().await?;
                Ok(Self::Socket(SocketAddr::from((addr, port))))
            }
            0x03 => {
                let len = r.read_u8().await?;
                let mut buf = vec![0u8; len as usize];
                r.read_exact(&mut buf).await?;
                let port = r.read_u16().await?;
                Ok(Self::Domain(buf, port))
            }
            0x04 => {
                let mut buf = [0u16; 8];
                for x in &mut buf {
                    *x = r.read_u16().await?;
                }
                let addr = std::net::Ipv6Addr::new(
                    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
                );
                let port = r.read_u16().await?;
                Ok(Self::Socket(SocketAddr::from((addr, port))))
            }
            _ => Err(IoError::new(ErrorKind::Other, "unknown address")),
        }
    }
}

struct Request {
    command: u8,
    address: Address,
}

impl Request {
    async fn read_from<R: AsyncRead + Unpin>(r: &mut R) -> IoResult<Self> {
        let ver = r.read_u8().await?;
        if ver != 5 {
            return Err(IoError::new(ErrorKind::Other, "ver"));
        }
        let command = r.read_u8().await?;
        r.read_u8().await?;
        let address = Address::read_from(r).await?;
        Ok(Self { command, address })
    }
}

struct Server {
    listener: TcpListener,
}

impl Server {
    fn new(listener: TcpListener) -> Self {
        Self { listener }
    }
    async fn accept(&self) -> IoResult<Connection> {
        let (stream, _) = self.listener.accept().await?;
        Ok(Connection { stream })
    }
}

async fn handle(mut conn: Connection) -> IoResult<()> {
    conn.auth().await?;

    let request = Request::read_from(&mut conn.stream).await?;
    if request.command != 1 {
        conn.reply(Reply::CommandNotSupported).await?;
        return conn.shutdown().await;
    }

    let target = match request.address {
        Address::Domain(domain, port) => {
            let domain = String::from_utf8_lossy(&domain);
            TcpStream::connect((domain.as_ref(), port)).await
        }
        Address::Socket(socket) => TcpStream::connect(socket).await,
    };
    let Ok(mut target) = target else {
        conn.reply(Reply::HostUnreachable).await?;
        return conn.shutdown().await;
    };

    conn.reply(Reply::Succeeded).await?;
    let _ = tokio::io::copy_bidirectional(&mut target, &mut conn.stream).await;
    Ok(())
}

#[tokio::main]
async fn main() -> IoResult<()> {
    let listener = TcpListener::bind("127.0.0.1:5000").await?;
    let server = Server::new(listener);
    while let Ok(conn) = server.accept().await {
        tokio::spawn(async move {
            match handle(conn).await {
                Ok(()) => {}
                Err(err) => eprintln!("{err}"),
            }
        });
    }
    Ok(())
}
