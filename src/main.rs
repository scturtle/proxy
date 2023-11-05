use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::net::{SocketAddr, ToSocketAddrs};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[repr(u8)]
enum Reply {
    Succeeded = 0x0,
    CommandNotSupported = 0x7,
}

struct Connection {
    stream: TcpStream,
}

struct Request {
    command: u8,
    address: SocketAddr,
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

    async fn read_addr(&mut self) -> IoResult<SocketAddr> {
        match self.stream.read_u8().await? {
            0x01 => {
                let mut buf = [0u8; 4];
                self.stream.read_exact(&mut buf).await?;
                let addr = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = self.stream.read_u16().await?;
                Ok(SocketAddr::from((addr, port)))
            }
            0x03 => {
                let len = self.stream.read_u8().await?;
                let mut buf = vec![0u8; len as usize];
                self.stream.read_exact(&mut buf).await?;
                let port = self.stream.read_u16().await?;
                let domain = String::from_utf8_lossy(&buf);
                let addr = (domain.as_ref(), port)
                    .to_socket_addrs()?
                    .next()
                    .ok_or_else(|| IoError::new(ErrorKind::Other, "failed to resolve DNS"))?;
                Ok(addr)
            }
            0x04 => {
                let mut buf = [0u16; 8];
                for x in &mut buf {
                    *x = self.stream.read_u16().await?;
                }
                let addr = std::net::Ipv6Addr::new(
                    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
                );
                let port = self.stream.read_u16().await?;
                Ok(SocketAddr::from((addr, port)))
            }
            _ => Err(IoError::new(ErrorKind::Other, "unknown address")),
        }
    }

    async fn read_request(&mut self) -> IoResult<Request> {
        let ver = self.stream.read_u8().await?;
        if ver != 5 {
            return Err(IoError::new(ErrorKind::Other, "ver"));
        }
        let command = self.stream.read_u8().await?;
        self.stream.read_u8().await?;
        let address = self.read_addr().await?;
        Ok(Request { command, address })
    }

    async fn handle(&mut self) -> IoResult<()> {
        self.auth().await?;
        let request = self.read_request().await?;
        if request.command != 1 {
            return self.reply(Reply::CommandNotSupported).await;
        }
        let mut target = TcpStream::connect(request.address).await?;
        self.reply(Reply::Succeeded).await?;
        let _ = tokio::io::copy_bidirectional(&mut target, &mut self.stream).await;
        Ok(())
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

#[tokio::main]
async fn main() -> IoResult<()> {
    let listener = TcpListener::bind("127.0.0.1:5000").await?;
    let server = Server::new(listener);
    while let Ok(mut conn) = server.accept().await {
        tokio::spawn(async move {
            match conn.handle().await {
                Ok(()) => {}
                Err(err) => eprintln!("{err}"),
            }
        });
    }
    Ok(())
}
