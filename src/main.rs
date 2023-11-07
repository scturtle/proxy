use proxy::read_addr_from;

use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::net::SocketAddr;
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

    async fn read_request(&mut self) -> IoResult<Request> {
        if self.stream.read_u8().await? != 5 {
            return Err(IoError::new(ErrorKind::Other, "ver"));
        }
        let command = self.stream.read_u8().await?;
        self.stream.read_u8().await?;
        let address = read_addr_from(&mut self.stream).await?;
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
            if let Err(err) = conn.handle().await {
                eprintln!("{err}");
            }
        });
    }
    Ok(())
}
