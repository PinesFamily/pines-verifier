//! Bounds the real Proxy transport; alpha.15's ProxyTlsConfig contains only a host.
use crate::gateway::Ticket;
use std::{
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..128).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..32).contains(&b))
                || (a == 192
                    && (b == 168 || (b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99)))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            // Global unicast only; exclude mapped/translation, Teredo, documentation,
            // benchmarking and 6to4 destinations rather than tunnelling to IPv4.
            segments[0] & 0xe000 == 0x2000
                && segments[0] != 0x2002
                && !(segments[0] == 0x2001 && (segments[1] <= 0x01ff || segments[1] == 0x0db8))
                && !(segments[0] == 0x3fff && segments[1] <= 0x0fff)
        }
    }
}

/// Build features reported by `/info`. A production build reports none; production extensions refuse any.
#[cfg(feature = "bench-fixture")]
pub const BUILD_FEATURES: &[&str] = &["bench-fixture"];
#[cfg(not(feature = "bench-fixture"))]
pub const BUILD_FEATURES: &[&str] = &[];

/// Benchmark builds only (`--features bench-fixture`): `TLSN_BENCH_ORIGIN_OVERRIDES=host=ip:port,…` sends an allowed
/// fixture host to an owned local origin. Production builds cannot compile this path.
#[cfg(feature = "bench-fixture")]
fn bench_override(host: &str) -> Option<SocketAddr> {
    std::env::var("TLSN_BENCH_ORIGIN_OVERRIDES")
        .ok()?
        .split(',')
        .find_map(|entry| {
            let (name, address) = entry.trim().split_once('=')?;
            (name == host).then(|| address.parse().ok()).flatten()
        })
}

/// Policy refusals are `PermissionDenied`; failures to reach an allowed origin are `ConnectionRefused`.
pub async fn connect(ticket: &Ticket, host: &str) -> io::Result<tokio::net::TcpStream> {
    if ticket.server_name != host {
        return Err(denied());
    }
    #[cfg(feature = "bench-fixture")]
    if let Some(address) = bench_override(host) {
        return tokio::net::TcpStream::connect(address).await;
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, 443)).await?.collect();
        if addresses.is_empty()
            || addresses.len() > 16
            || addresses
                .iter()
                .any(|address| !public_ip(address.ip()) || address.port() != 443)
        {
            return Err(denied());
        }
        for address in addresses {
            // Connect to this validated IP, with no second DNS lookup.
            if let Ok(Ok(stream)) = tokio::time::timeout(
                Duration::from_secs(3),
                tokio::net::TcpStream::connect(address),
            )
            .await
            {
                return Ok(stream);
            }
        }
        Err(unreachable())
    })
    .await
    .map_err(|_| unreachable())?
}
fn unreachable() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionRefused, "TLSN origin unreachable")
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "TLSN transport policy refused",
    )
}

#[derive(Default)]
struct Records {
    header: [u8; 5],
    header_len: usize,
    remaining: usize,
    count: usize,
    limit: usize,
}
impl Records {
    fn consume(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            if self.remaining > 0 {
                let length = bytes.len().min(self.remaining);
                self.remaining -= length;
                bytes = &bytes[length..];
            } else {
                let length = bytes.len().min(5 - self.header_len);
                self.header[self.header_len..self.header_len + length]
                    .copy_from_slice(&bytes[..length]);
                self.header_len += length;
                bytes = &bytes[length..];
                if self.header_len == 5 {
                    self.remaining = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
                    self.header_len = 0;
                    self.count += 1;
                    if self.count > self.limit || self.remaining > 18_432 {
                        return Err(denied());
                    }
                }
            }
        }
        Ok(())
    }
}
struct Budget {
    remaining: usize,
    records: Option<Records>,
}
impl Budget {
    fn consume(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.remaining = self.remaining.checked_sub(bytes.len()).ok_or_else(denied)?;
        if let Some(records) = &mut self.records {
            records.consume(bytes)?;
        }
        Ok(())
    }
}
pub struct BoundedIo<T> {
    inner: T,
    read: Budget,
    write: Budget,
}
impl<T> BoundedIo<T> {
    pub fn protocol(inner: T, limit: usize) -> Self {
        Self {
            inner,
            read: Budget {
                remaining: limit,
                records: None,
            },
            write: Budget {
                remaining: limit,
                records: None,
            },
        }
    }
    pub fn origin(inner: T, ticket: Option<&Ticket>) -> Self {
        let Some(ticket) = ticket else {
            return Self::protocol(inner, usize::MAX);
        };
        // Includes ciphertext tags/record headers and a bounded handshake allowance.
        let overhead = 65_536 + ticket.max_recv_records * 29;
        let records = || {
            Some(Records {
                limit: ticket.max_recv_records,
                ..Records::default()
            })
        };
        Self {
            inner,
            read: Budget {
                remaining: ticket.max_recv_bytes + overhead,
                records: records(),
            },
            write: Budget {
                remaining: ticket.max_sent_bytes + overhead,
                records: records(),
            },
        }
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for BoundedIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => Poll::Ready(this.read.consume(&buf.filled()[before..])),
            other => other,
        }
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for BoundedIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.len() > this.write.remaining {
            return Poll::Ready(Err(denied()));
        }
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(length)) => {
                Poll::Ready(this.write.consume(&buf[..length]).map(|_| length))
            }
            other => other,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[test]
    fn denies_special_addresses_and_mapped_ipv4() {
        for ip in [
            "0.0.0.0",
            "10.0.0.1",
            "127.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.1.1",
            "192.0.2.1",
            "198.18.0.1",
            "224.0.0.1",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "2002:7f00:1::",
            "64:ff9b::7f00:1",
            "3fff::1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "9.9.9.9", "2606:4700:4700::1111"] {
            assert!(public_ip(ip.parse().unwrap()), "{ip}");
        }
    }
    #[test]
    fn counts_records_across_partial_headers_and_rejects_oversize_records() {
        let mut records = Records {
            limit: 1,
            ..Records::default()
        };
        records.consume(&[23, 3]).unwrap();
        records.consume(&[3, 0, 2, 1]).unwrap();
        records.consume(&[2]).unwrap();
        assert!(records.consume(&[23, 3, 3, 0, 0]).is_err());
        assert!(Records {
            limit: 2,
            ..Records::default()
        }
        .consume(&[23, 3, 3, 255, 255])
        .is_err());
    }
    #[tokio::test]
    async fn bounds_reads_and_writes_on_the_actual_stream() {
        let (left, mut right) = tokio::io::duplex(128);
        let mut bounded = BoundedIo::protocol(left, 3);
        bounded.write_all(b"abc").await.unwrap();
        assert!(bounded.write_all(b"d").await.is_err());
        right.write_all(b"abcd").await.unwrap();
        assert!(bounded.read_exact(&mut [0; 4]).await.is_err());
    }
}
