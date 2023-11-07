use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::net::{SocketAddr, ToSocketAddrs};
use tokio::io::AsyncReadExt;

pub async fn read_addr_from<R: AsyncReadExt + Unpin>(mut r: R) -> IoResult<SocketAddr> {
    match r.read_u8().await? {
        0x01 => {
            let mut buf = [0u8; 4];
            r.read_exact(&mut buf).await?;
            let addr = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = r.read_u16().await?;
            Ok(SocketAddr::from((addr, port)))
        }
        0x03 => {
            let len = r.read_u8().await?;
            let mut buf = vec![0u8; len as usize];
            r.read_exact(&mut buf).await?;
            let port = r.read_u16().await?;
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
                *x = r.read_u16().await?;
            }
            let addr = std::net::Ipv6Addr::new(
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            );
            let port = r.read_u16().await?;
            Ok(SocketAddr::from((addr, port)))
        }
        _ => Err(IoError::new(ErrorKind::Other, "unknown address")),
    }
}
