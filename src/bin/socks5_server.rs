use log::{error, info};
use proxy::Addr;
use std::io::{Cursor, Error as IoError, ErrorKind, Result as IoResult};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[repr(u8)]
enum Reply {
    Succeeded = 0x0,
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

    async fn reply_udp(&mut self, port: u16) -> IoResult<()> {
        self.stream
            .write_all(&[5, Reply::Succeeded as u8, 0, 1, 0, 0, 0, 0])
            .await?;
        self.stream.write_u16(port).await
    }

    async fn handle(&mut self) -> IoResult<()> {
        self.auth().await?;
        if self.stream.read_u8().await? != 5 {
            return Err(IoError::new(ErrorKind::Other, "ver"));
        }
        let command = self.stream.read_u8().await?;
        let _ = self.stream.read_u8().await?;
        let address = Addr::read_addr_from(&mut self.stream).await?;
        if command == 1 {
            self.reply(Reply::Succeeded).await?;
            let address: SocketAddr = address.try_into()?;
            let mut target = TcpStream::connect(address).await?;
            tcp_copy_bidir(&mut target, &mut self.stream).await;
            Ok(())
        } else if command == 3 {
            let inbound = UdpSocket::bind("0.0.0.0:0").await?;
            self.reply_udp(inbound.local_addr()?.port()).await?;
            udp_copy_bidir(inbound).await;
            Ok(())
        } else {
            self.reply(Reply::CommandNotSupported).await
        }
    }
}

async fn handle_udp_request(inbound: &UdpSocket, outbound: &UdpSocket) -> IoResult<()> {
    let mut buffer = [0u8; 0x10000];
    loop {
        let (size, client_addr) = inbound.recv_from(&mut buffer).await?;
        inbound.connect(client_addr).await?;
        let mut cursor = Cursor::new(buffer.as_slice());
        cursor.set_position(3);
        let target = Addr::read_addr_from(&mut cursor).await?;
        let target_addr: SocketAddr = target.try_into()?;
        let data = &buffer[cursor.position() as usize..size];
        outbound.send_to(data, target_addr).await?;
    }
}

async fn handle_udp_response(inbound: &UdpSocket, outbound: &UdpSocket) -> IoResult<()> {
    let mut buffer = [0u8; 0x10000];
    let header = [0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    buffer[..header.len()].copy_from_slice(&header);
    loop {
        let (size, _) = outbound.recv_from(&mut buffer[header.len()..]).await?;
        inbound.send(&buffer[..header.len() + size]).await?;
    }
}

async fn udp_copy_bidir(inbound: UdpSocket) {
    let outbound = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    tokio::select!(
        _ = handle_udp_request(&inbound, &outbound) => (),
        _ = handle_udp_response(&inbound, &outbound) => (),
    );
}

async fn tcp_copy_bidir(a: &mut TcpStream, b: &mut TcpStream) {
    let (mut a_reader, mut a_writer) = tokio::io::split(a);
    let (mut b_reader, mut b_writer) = tokio::io::split(b);
    tokio::select!(
        _ = tokio::io::copy(&mut a_reader, &mut b_writer) => (),
        _ = tokio::io::copy(&mut b_reader, &mut a_writer) => (),
    );
}

use clap::Parser;
#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:5000")]
    bind: String,
}

#[tokio::main]
async fn main() -> IoResult<()> {
    env_logger::init();
    let Args { bind } = Args::parse();
    info!("bind to {bind}");
    let listener = TcpListener::bind(&bind).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        let mut conn = Connection { stream };
        tokio::spawn(async move {
            if let Err(err) = conn.handle().await {
                error!("err: {err}");
            }
        });
    }
}
