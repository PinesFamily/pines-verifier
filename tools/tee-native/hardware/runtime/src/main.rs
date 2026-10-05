//! Measured NSM/clock adapter and bounded fixed-route vsock bridges.
//! No secret or error excerpts are written to the parent console.
use aws_nitro_enclaves_nsm_api::{
    api::{Request, Response},
    driver::{nsm_exit, nsm_init, nsm_process_request},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use std::{
    io::{self, Read},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err("RUNTIME_REFUSED".into())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    public_key: String,
    nonce: String,
    user_data: String,
}

fn attest() -> Result<()> {
    // Private stdin inherited only by the measured Node process. No network
    // endpoint accepts caller-selected attestation fields or host time.
    let mut input = Vec::new();
    io::stdin().take(2049).read_to_end(&mut input)?;
    require(input.len() <= 2048)?;
    let b: Binding = serde_json::from_slice(&input)?;
    let key = STANDARD.decode(b.public_key)?;
    let nonce = STANDARD.decode(b.nonce)?;
    let data = STANDARD.decode(b.user_data)?;
    require(key.len() == 91 && nonce.len() == 32 && data.len() == 32)?;
    let fd = nsm_init();
    require(fd >= 0)?;
    let reply = nsm_process_request(
        fd,
        Request::Attestation {
            public_key: Some(key.into()),
            nonce: Some(nonce.into()),
            user_data: Some(data.into()),
        },
    );
    nsm_exit(fd);
    let Response::Attestation { document } = reply else {
        return Err("NSM_REFUSED".into());
    };
    require(document.len() <= 16384)?;
    println!("{}", STANDARD.encode(document));
    Ok(())
}

fn nsm_time() -> Result<i128> {
    // The NSM device supplies the timestamp. Unsigned parent input is never read.
    let fd = nsm_init();
    require(fd >= 0)?;
    let reply = nsm_process_request(
        fd,
        Request::Attestation {
            public_key: None,
            nonce: None,
            user_data: None,
        },
    );
    nsm_exit(fd);
    let Response::Attestation { document } = reply else {
        return Err("NSM_REFUSED".into());
    };
    use serde_cbor::Value;
    let mut value: Value = serde_cbor::from_slice(&document)?;
    if let Value::Tag(_, inner) = value {
        value = *inner;
    }
    let Value::Array(cose) = value else {
        return Err("NSM_ENCODING".into());
    };
    require(cose.len() == 4)?;
    let Value::Bytes(payload) = &cose[2] else {
        return Err("NSM_ENCODING".into());
    };
    let Value::Map(doc) = serde_cbor::from_slice::<Value>(payload)? else {
        return Err("NSM_ENCODING".into());
    };
    let Some(Value::Integer(ms)) = doc.get(&Value::Text("timestamp".into())) else {
        return Err("NSM_TIME".into());
    };
    require(*ms >= 1_700_000_000_000 && *ms < 4_102_444_800_000)?;
    Ok(*ms)
}
fn clock() -> Result<()> {
    let ms = nsm_time()?;
    let ts = libc::timespec {
        tv_sec: (ms / 1000) as libc::time_t,
        tv_nsec: ((ms % 1000) * 1_000_000) as libc::c_long,
    };
    // Runs once at boot as root, before listeners/keys/TLSN. Runtime continually
    // compares fresh NSM timestamps with wall and monotonic clocks thereafter.
    require(unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) } == 0)?;
    println!("{{\"timestamp\":{ms},\"source\":\"NSM\"}}");
    Ok(())
}

fn loopback() -> Result<()> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    require(fd >= 0)?;
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    request.ifr_name[0] = b'l' as libc::c_char;
    request.ifr_name[1] = b'o' as libc::c_char;
    let result = unsafe {
        if libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &mut request) < 0 {
            -1
        } else {
            request.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
            libc::ioctl(fd, libc::SIOCSIFFLAGS as _, &request)
        }
    };
    unsafe { libc::close(fd) };
    require(result == 0)
}

async fn copy<A: AsyncRead + AsyncWrite + Unpin, B: AsyncRead + AsyncWrite + Unpin>(
    a: A,
    b: B,
    cap: u64,
) -> Result<()> {
    let (ar, mut aw) = tokio::io::split(a);
    let (br, mut bw) = tokio::io::split(b);
    let mut ar = ar.take(cap);
    let mut br = br.take(cap);
    let flow = async {
        // Reaching the byte cap closes both halves, even if the peer keeps writing.
        tokio::select! {
            r = tokio::io::copy(&mut ar, &mut bw) => {r?;},
            r = tokio::io::copy(&mut br, &mut aw) => {r?;},
        }
        Ok::<(), std::io::Error>(())
    };
    tokio::time::timeout(Duration::from_secs(130), flow).await??;
    Ok(())
}

// Fixed routes are measured. Parent input cannot supply a destination, URL,
// port, DNS name or protocol. Three listeners share one egress semaphore.
#[derive(Clone, Copy)]
struct ProviderRoute {
    vsock: u32,
    local: &'static str,
    destination: &'static str,
}
const PROVIDER_ROUTES: [ProviderRoute; 3] = [
    ProviderRoute {
        vsock: 8001,
        local: "127.0.0.1:18001",
        destination: "chatgpt.com:443",
    },
    ProviderRoute {
        vsock: 8002,
        local: "127.0.0.1:18002",
        destination: "claude.ai:443",
    },
    ProviderRoute {
        vsock: 8003,
        local: "127.0.0.1:18003",
        destination: "grok.com:443",
    },
];
async fn from_vsock(
    port: u32,
    expected_peer: u32,
    destination: &'static str,
    limit: u64,
    permits: Arc<Semaphore>,
) -> Result<()> {
    let listen = VsockListener::bind(VsockAddr::new(libc::VMADDR_CID_ANY, port))?;
    loop {
        let (socket, peer) = listen.accept().await?;
        if peer.cid() != expected_peer {
            continue;
        }
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        tokio::spawn(async move {
            let _permit = permit;
            if let Ok(Ok(tcp)) =
                tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(destination)).await
            {
                let _ = copy(socket, tcp, limit).await;
            }
        });
    }
}
async fn from_tcp(
    local: &'static str,
    peer: u32,
    port: u32,
    limit: u64,
    permits: Arc<Semaphore>,
) -> Result<()> {
    let listen = TcpListener::bind(local).await?;
    loop {
        let (socket, _) = listen.accept().await?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        tokio::spawn(async move {
            let _permit = permit;
            if let Ok(Ok(vsock)) = tokio::time::timeout(
                Duration::from_secs(10),
                VsockStream::connect(VsockAddr::new(peer, port)),
            )
            .await
            {
                let _ = copy(socket, vsock, limit).await;
            }
        });
    }
}
async fn bridge(mode: &str) -> Result<()> {
    match mode {
        "enclave-ingress" => {
            from_vsock(
                8000,
                3,
                "127.0.0.1:18000",
                70 * 1024 * 1024,
                Arc::new(Semaphore::new(8)),
            )
            .await
        }
        "parent-ingress" => {
            from_tcp(
                "127.0.0.1:8969",
                16,
                8000,
                70 * 1024 * 1024,
                Arc::new(Semaphore::new(8)),
            )
            .await
        }
        "parent-egress" => {
            let permits = Arc::new(Semaphore::new(1));
            let [a, b, c] = PROVIDER_ROUTES;
            tokio::try_join!(
                from_vsock(a.vsock, 16, a.destination, 131072, permits.clone()),
                from_vsock(b.vsock, 16, b.destination, 131072, permits.clone()),
                from_vsock(c.vsock, 16, c.destination, 131072, permits.clone())
            )?;
            Ok(())
        }
        "enclave-egress" => {
            let permits = Arc::new(Semaphore::new(1));
            let [a, b, c] = PROVIDER_ROUTES;
            tokio::try_join!(
                from_tcp(a.local, 3, a.vsock, 131072, permits.clone()),
                from_tcp(b.local, 3, b.vsock, 131072, permits.clone()),
                from_tcp(c.local, 3, c.vsock, 131072, permits.clone())
            )?;
            Ok(())
        }
        _ => Err("RUNTIME_REFUSED".into()),
    }
}

#[tokio::main]
async fn main() {
    if std::env::args().len() != 2 {
        eprintln!("NITRO_RUNTIME_REFUSED");
        std::process::exit(78);
    }
    let mode = std::env::args().nth(1).unwrap_or_default();
    let result = match mode.as_str() {
        "attest" => attest(),
        "clock" => clock(),
        "loopback" => loopback(),
        "time" => nsm_time().map(|ms| println!("{{\"timestamp\":{ms}}}")),
        _ => bridge(&mode).await,
    };
    if result.is_err() {
        eprintln!("NITRO_RUNTIME_REFUSED");
        std::process::exit(78);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    #[test]
    fn provider_routes_are_closed_and_do_not_share_a_destination_port() {
        let actual: Vec<_> = PROVIDER_ROUTES
            .iter()
            .map(|r| (r.vsock, r.local, r.destination))
            .collect();
        assert_eq!(
            actual,
            vec![
                (8001, "127.0.0.1:18001", "chatgpt.com:443"),
                (8002, "127.0.0.1:18002", "claude.ai:443"),
                (8003, "127.0.0.1:18003", "grok.com:443"),
            ]
        );
    }
    #[tokio::test]
    async fn unrecognized_bridge_arguments_do_not_open_routes() {
        for mode in [
            "",
            "https://grok.com",
            "parent-egress:8004",
            "enclave-egress-claude",
            "127.0.0.1:9",
        ] {
            assert!(bridge(mode).await.is_err());
        }
    }
    #[tokio::test]
    async fn fragmented_duplex_traffic_and_disconnect_are_bounded() {
        let (mut client, left) = duplex(64);
        let (right, mut server) = duplex(64);
        let relay = tokio::spawn(copy(left, right, 1024));
        for byte in b"fragmented TLS ciphertext" {
            client.write_all(&[*byte]).await.unwrap();
            let mut got = [0];
            server.read_exact(&mut got).await.unwrap();
            assert_eq!(got[0], *byte);
            server.write_all(&got).await.unwrap();
            client.read_exact(&mut got).await.unwrap();
            assert_eq!(got[0], *byte);
        }
        drop(client);
        tokio::time::timeout(Duration::from_secs(1), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    #[tokio::test]
    async fn byte_cap_closes_both_halves() {
        let (mut client, left) = duplex(128);
        let (right, mut server) = duplex(128);
        let relay = tokio::spawn(copy(left, right, 16));
        client.write_all(&[42; 32]).await.unwrap();
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, vec![42; 16]);
        tokio::time::timeout(Duration::from_secs(1), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut tail = Vec::new();
        client.read_to_end(&mut tail).await.unwrap();
        assert!(tail.is_empty());
    }
}
