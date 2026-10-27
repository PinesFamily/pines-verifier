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
    os::fd::AsRawFd,
    os::unix::process::CommandExt,
    process::Command,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};

mod spki;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const MAX_PROOF_SLOTS: usize = 8;
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

fn attestation_binding_sizes(key: usize, nonce: usize, data: usize) -> bool {
    // Proof channels bind a P-256 SPKI (91 bytes); controller enrollment binds
    // the measured per-boot Ed25519 public key (32 raw bytes). Both callers are
    // fixed measured code, and neither exposes arbitrary parent attestation.
    matches!(key, 32 | 91) && nonce == 32 && data == 32
}

fn read_binding() -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    // Private stdin inherited only by the measured Node process. No network
    // endpoint accepts caller-selected attestation fields or host time.
    let mut input = Vec::new();
    io::stdin().take(2049).read_to_end(&mut input)?;
    require(input.len() <= 2048)?;
    let b: Binding = serde_json::from_slice(&input)?;
    Ok((
        STANDARD.decode(b.public_key)?,
        STANDARD.decode(b.nonce)?,
        STANDARD.decode(b.user_data)?,
    ))
}

fn attest() -> Result<()> {
    let (key, nonce, data) = read_binding()?;
    require(attestation_binding_sizes(
        key.len(),
        nonce.len(),
        data.len(),
    ))?;
    issue_attestation(key, nonce, data)
}

/// Separate lane for the deferred keyed-identity work: an attested AWS KMS
/// `Recipient` must carry an RSA public key, which neither existing binding form
/// can express. It accepts only a canonical RSA-2048 SPKI, so the sizes above
/// stay exactly as qualified and arbitrary 294-byte parent data is not
/// attestable. Nothing in the current image calls this mode.
fn attest_kms_recipient() -> Result<()> {
    let (key, nonce, data) = read_binding()?;
    require(spki::is_rsa_2048_spki(&key) && nonce.len() == 32 && data.len() == 32)?;
    issue_attestation(key, nonce, data)
}

fn issue_attestation(key: Vec<u8>, nonce: Vec<u8>, data: Vec<u8>) -> Result<()> {
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

fn native_memory_limit(value: &str) -> Result<libc::rlim_t> {
    require(!value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))?;
    let mib: u64 = value.parse()?;
    // The parser's range is the union of the class floors below and the 4096 MiB
    // ceiling; each class then enforces its own measured floor independently.
    require((448..=4096).contains(&mib) && value == mib.to_string())?;
    Ok((mib * 1024 * 1024) as libc::rlim_t)
}

fn set_native_limits(value: &str) -> Result<()> {
    let limit = native_memory_limit(value)?;
    let memory = libc::rlimit {
        rlim_cur: limit,
        rlim_max: limit,
    };
    let core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    require(unsafe { libc::setrlimit(libc::RLIMIT_AS, &memory) } == 0)?;
    require(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &core) } == 0)?;
    Ok(())
}

// Match the measured resource-class floors independently of JavaScript. The
// per-boot selection supplies the ceiling; disclosure selects the native path.
fn native_disclosure_memory(policy: &str, value: &str) -> Result<()> {
    native_memory_limit(value)?;
    match policy {
        "redacted-response-v1" => require(value.parse::<u64>()? >= 3072),
        "full-response-v1" => require(value.parse::<u64>()? >= 512),
        // The private-headers class floor (capacity-policy.mjs RESOURCE_CLASSES): local
        // generated-data evidence, 448 MiB; the hardware campaign confirms or raises it.
        "private-headers-gzip-v1" => require(value.parse::<u64>()? >= 448),
        "grok-clearance-private-v1" => require(value.parse::<u64>()? >= 448),
        // The sybil-facts class: full-response's reveal-all path and experimental floor (capacity-policy.mjs).
        "facts-complete-v1" => require(value.parse::<u64>()? >= 512),
        "grok-email-complete-v1" => require(value.parse::<u64>()? >= 512),
        _ => require(false),
    }
}

fn native(args: &[String]) -> Result<()> {
    require(args.len() == 8 && std::path::Path::new("/dev/nsm").exists())?;
    require(matches!(args[2].as_str(), "chatgpt" | "claude" | "grok"))?;
    require(
        args[6].len() == 64
            && args[6]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
    )?;
    native_disclosure_memory(&args[7], &args[5])?;
    // Fixed child only, no shell or parent-selected executable. Hard address
    // space cap covers the redacted path even when allocation is adversarial.
    set_native_limits(&args[5])?;
    Err(Command::new("/app/bin/tee-hardware")
        .args(&args[2..5])
        .arg(&args[6])
        .arg(&args[7])
        .env("MALLOC_ARENA_MAX", "2")
        .env("RAYON_NUM_THREADS", "1")
        .exec()
        .into())
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
    // Transport lifetime covers the compiled 300-second session ceiling plus
    // bounded setup/retirement. The signed grant remains the work deadline.
    tokio::time::timeout(Duration::from_secs(310), flow).await??;
    Ok(())
}

// Fixed routes are measured. Parent input cannot supply a destination, URL,
// port, DNS name or protocol. Three listeners share the bounded egress pool.
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
// Deferred keyed-identity transport. The endpoint, both vsock ports and the
// parent's loopback handoff address are measured constants: the parent chooses
// none of them and cannot redirect either route. TLS for the KMS route is
// terminated by the measured Node process at the enclave end of this pipe, so a
// parent that resolves or reroutes the hostname still decrypts nothing. Nothing
// in the current entrypoint starts these modes.
const KMS_ENDPOINT: &str = "kms.ap-southeast-2.amazonaws.com:443";
const KMS_PARENT_HANDOFF: &str = "127.0.0.1:8971";
const KMS_EGRESS_LOCAL: &str = "127.0.0.1:18020";
const KMS_HANDOFF_LOCAL: &str = "127.0.0.1:18021";
const KMS_EGRESS_VSOCK: u32 = 8005;
const KMS_HANDOFF_VSOCK: u32 = 8006;
// One boot performs a handful of bounded requests; this is not a proof route.
const KMS_BYTE_CAP: u64 = 256 * 1024;
const KMS_SLOTS: usize = 2;
const PARENT_INGRESS: [&str; 2] = ["127.0.0.1:8969", "127.0.0.1:8981"];
const PARENT_CONTROL: [&str; 2] = ["127.0.0.1:8970", "127.0.0.1:8982"];

fn local_verifier_cid() -> Result<u32> {
    let socket = std::fs::File::open("/dev/vsock")?;
    let mut cid: u32 = 0;
    // Linux IOCTL_VM_SOCKETS_GET_LOCAL_CID writes exactly one u32. The CID is a
    // routing identity, never an authority: NSM binds the worker and boot keys.
    let result = unsafe { libc::ioctl(socket.as_raw_fd(), 0x7b9, &mut cid) };
    require(result == 0 && verifier_peer(cid))?;
    Ok(cid)
}

fn verifier_peer(cid: u32) -> bool {
    matches!(cid, 16 | 17)
}

async fn from_vsock(
    port: u32,
    expected_peers: &'static [u32],
    destination: &'static str,
    limit: u64,
    permits: Arc<Semaphore>,
) -> Result<()> {
    from_vsock_route(port, expected_peers, destination, limit, permits, false).await
}

// Fixed routing by worker CID, never by an inferred attempt or browser input.
// The trusted parent adapters on these loopback ports have pinned mTLS routes.
fn group_destination(cid: u32, port: u32) -> Result<&'static str> {
    match (cid, port) {
        (16, 8001) => Ok("chatgpt.com:443"),
        (16, 8002) => Ok("claude.ai:443"),
        (16, 8003) => Ok("grok.com:443"),
        (17, 8001) => Ok("127.0.0.1:28001"),
        (17, 8002) => Ok("127.0.0.1:28002"),
        (17, 8003) => Ok("127.0.0.1:28003"),
        _ => Err("GROUP_ROUTE_REFUSED".into()),
    }
}
async fn from_vsock_route(
    port: u32,
    expected_peers: &'static [u32],
    destination: &'static str,
    limit: u64,
    permits: Arc<Semaphore>,
    group_routed: bool,
) -> Result<()> {
    let listen = VsockListener::bind(VsockAddr::new(libc::VMADDR_CID_ANY, port))?;
    loop {
        let (socket, peer) = listen.accept().await?;
        if !expected_peers.contains(&peer.cid()) {
            continue;
        }
        let destination = if group_routed {
            group_destination(peer.cid(), port)?
        } else {
            destination
        };
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
        // Isolated, nonclaimable settings image only. Separate fixed ports keep
        // the shared production egress listener available during qualification.
        "enclave-settings-egress" => {
            from_tcp(
                "127.0.0.1:18003",
                3,
                8103,
                131072,
                Arc::new(Semaphore::new(1)),
            )
            .await
        }
        "parent-settings-egress" => {
            from_vsock(
                8103,
                &[17],
                "127.0.0.1:28003",
                131072,
                Arc::new(Semaphore::new(1)),
            )
            .await
        }
        "enclave-ingress" => {
            from_vsock(
                8000,
                &[3],
                "127.0.0.1:18000",
                70 * 1024 * 1024,
                Arc::new(Semaphore::new(MAX_PROOF_SLOTS + 2)),
            )
            .await
        }
        "parent-ingress" | "parent-ingress-v2" => {
            from_tcp(
                if mode == "parent-ingress" {
                    PARENT_INGRESS[0]
                } else {
                    PARENT_INGRESS[1]
                },
                if mode == "parent-ingress" { 16 } else { 17 },
                8000,
                70 * 1024 * 1024,
                Arc::new(Semaphore::new(MAX_PROOF_SLOTS + 2)),
            )
            .await
        }
        "enclave-control" => {
            from_vsock(
                8004,
                &[3],
                "127.0.0.1:18010",
                4 * 1024 * 1024,
                Arc::new(Semaphore::new(8)),
            )
            .await
        }
        "parent-control" | "parent-control-v2" => {
            from_tcp(
                if mode == "parent-control" {
                    PARENT_CONTROL[0]
                } else {
                    PARENT_CONTROL[1]
                },
                if mode == "parent-control" { 16 } else { 17 },
                8004,
                4 * 1024 * 1024,
                Arc::new(Semaphore::new(8)),
            )
            .await
        }
        "parent-egress" | "parent-colocated-egress" | "parent-colocated-assisted-egress" => {
            let permits = Arc::new(Semaphore::new(MAX_PROOF_SLOTS));
            let [a, b, c] = PROVIDER_ROUTES;
            let peers: &'static [u32] = if mode == "parent-egress" {
                &[16]
            } else {
                &[16, 17]
            };
            let grouped = mode == "parent-colocated-assisted-egress";
            tokio::try_join!(
                from_vsock_route(
                    a.vsock,
                    peers,
                    a.destination,
                    131072,
                    permits.clone(),
                    grouped
                ),
                from_vsock_route(
                    b.vsock,
                    peers,
                    b.destination,
                    131072,
                    permits.clone(),
                    grouped
                ),
                from_vsock_route(
                    c.vsock,
                    peers,
                    c.destination,
                    131072,
                    permits.clone(),
                    grouped
                )
            )?;
            Ok(())
        }
        "enclave-egress" => {
            let permits = Arc::new(Semaphore::new(MAX_PROOF_SLOTS));
            let [a, b, c] = PROVIDER_ROUTES;
            tokio::try_join!(
                from_tcp(a.local, 3, a.vsock, 131072, permits.clone()),
                from_tcp(b.local, 3, b.vsock, 131072, permits.clone()),
                from_tcp(c.local, 3, c.vsock, 131072, permits.clone())
            )?;
            Ok(())
        }
        "enclave-kms-egress" => {
            from_tcp(
                KMS_EGRESS_LOCAL,
                3,
                KMS_EGRESS_VSOCK,
                KMS_BYTE_CAP,
                Arc::new(Semaphore::new(KMS_SLOTS)),
            )
            .await
        }
        "parent-kms-egress" | "parent-colocated-kms-egress" => {
            from_vsock(
                KMS_EGRESS_VSOCK,
                if mode == "parent-kms-egress" {
                    &[16]
                } else {
                    &[16, 17]
                },
                KMS_ENDPOINT,
                KMS_BYTE_CAP,
                Arc::new(Semaphore::new(KMS_SLOTS)),
            )
            .await
        }
        "enclave-kms-handoff" => {
            from_tcp(
                KMS_HANDOFF_LOCAL,
                3,
                KMS_HANDOFF_VSOCK,
                KMS_BYTE_CAP,
                Arc::new(Semaphore::new(KMS_SLOTS)),
            )
            .await
        }
        "parent-kms-handoff" | "parent-colocated-kms-handoff" => {
            from_vsock(
                KMS_HANDOFF_VSOCK,
                if mode == "parent-kms-handoff" {
                    &[16]
                } else {
                    &[16, 17]
                },
                KMS_PARENT_HANDOFF,
                KMS_BYTE_CAP,
                Arc::new(Semaphore::new(KMS_SLOTS)),
            )
            .await
        }
        _ => Err("RUNTIME_REFUSED".into()),
    }
}

#[tokio::main(worker_threads = 2)]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 && !(args.len() == 8 && args[1] == "native") {
        eprintln!("NITRO_RUNTIME_REFUSED");
        std::process::exit(78);
    }
    let mode = args[1].as_str();
    let result = match mode {
        "native" => native(&args),
        "attest" => attest(),
        "attest-kms-recipient" => attest_kms_recipient(),
        "clock" => clock(),
        "loopback" => loopback(),
        "time" => nsm_time().map(|ms| println!("{{\"timestamp\":{ms}}}")),
        "verifier-cid" => local_verifier_cid().map(|cid| println!("{{\"cid\":{cid}}}")),
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
    fn assisted_group_has_fixed_routes_and_parent_direct_is_preserved() {
        for (port, direct, assisted) in [
            (8001, "chatgpt.com:443", "127.0.0.1:28001"),
            (8002, "claude.ai:443", "127.0.0.1:28002"),
            (8003, "grok.com:443", "127.0.0.1:28003"),
        ] {
            assert_eq!(group_destination(16, port).unwrap(), direct);
            assert_eq!(group_destination(17, port).unwrap(), assisted);
            for cid in [0, 1, 2, 3, 18, u32::MAX] {
                assert!(group_destination(cid, port).is_err());
            }
        }
        for port in [22, 443, 8000, 8004, 9000, u32::MAX] {
            assert!(group_destination(17, port).is_err());
        }
    }
    #[test]
    fn colocated_verifier_peers_exclude_signer_and_parent() {
        assert!(verifier_peer(16));
        assert!(verifier_peer(17));
        for cid in [0, 1, 2, 3, 15, 18, u32::MAX] {
            assert!(!verifier_peer(cid));
        }
    }
    #[test]
    fn parent_listeners_do_not_alias_each_other_or_kms_handoff() {
        let ports: Vec<_> = PARENT_INGRESS
            .iter()
            .chain(PARENT_CONTROL.iter())
            .copied()
            .chain([KMS_PARENT_HANDOFF])
            .collect();
        assert_eq!(
            ports.iter().collect::<std::collections::HashSet<_>>().len(),
            ports.len()
        );
    }
    #[test]
    fn native_memory_policy_is_integer_and_bounded() {
        for value in ["448", "512", "2048", "3072", "4096"] {
            assert_eq!(
                native_memory_limit(value).unwrap(),
                value.parse::<u64>().unwrap() * 1024 * 1024
            );
        }
        for value in ["", "447", "4097", "+512", " 512", "2e3", "2048.0"] {
            assert!(native_memory_limit(value).is_err());
        }
    }
    #[test]
    fn hard_native_memory_limit_refuses_excess_allocation_in_a_separate_child() {
        const CHILD: &str = "PINES_RESOURCE_LIMIT_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            set_native_limits("512").unwrap();
            let mut current = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut current) }, 0);
            assert_eq!(current.rlim_cur, 512 * 1024 * 1024);
            assert_eq!(current.rlim_max, current.rlim_cur);
            let memory = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    1024 * 1024 * 1024,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_eq!(memory, libc::MAP_FAILED);
            return;
        }
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::hard_native_memory_limit_refuses_excess_allocation_in_a_separate_child",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(child.status.success());
    }
    #[test]
    fn attestation_accepts_only_proof_and_membership_binding_sizes() {
        assert!(attestation_binding_sizes(91, 32, 32));
        assert!(attestation_binding_sizes(32, 32, 32));
        for key in [0, 31, 33, 44, 90, 92, 1024] {
            assert!(!attestation_binding_sizes(key, 32, 32));
        }
        for key in [32, 91] {
            for size in [0, 31, 33, 1024] {
                assert!(!attestation_binding_sizes(key, size, 32));
                assert!(!attestation_binding_sizes(key, 32, size));
            }
        }
    }
    #[test]
    fn deferred_kms_routes_are_fixed_and_collide_with_no_qualified_route() {
        assert_eq!(KMS_ENDPOINT, "kms.ap-southeast-2.amazonaws.com:443");
        assert_eq!(KMS_PARENT_HANDOFF, "127.0.0.1:8971");
        // The permanent wrapping key stays in US East; no mode names another region.
        assert!(!KMS_ENDPOINT.contains("us-east-1"));
        let vsock = [
            8000u32,
            8001,
            8002,
            8003,
            8004,
            KMS_EGRESS_VSOCK,
            KMS_HANDOFF_VSOCK,
        ];
        let local = [
            "127.0.0.1:18000",
            "127.0.0.1:18001",
            "127.0.0.1:18002",
            "127.0.0.1:18003",
            "127.0.0.1:18010",
            KMS_EGRESS_LOCAL,
            KMS_HANDOFF_LOCAL,
        ];
        assert_eq!(
            vsock.iter().collect::<std::collections::HashSet<_>>().len(),
            vsock.len()
        );
        assert_eq!(
            local.iter().collect::<std::collections::HashSet<_>>().len(),
            local.len()
        );
        // The recipient lane is additive: the qualified sizes are unchanged and
        // its own length is not accepted by the existing proof/enrollment path.
        assert!(!attestation_binding_sizes(spki::RSA_2048_SPKI_LEN, 32, 32));
    }
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
#[test]
fn independent_disclosure_floors_and_canonical_budgets() {
    for value in ["512", "768", "1024", "4096"] {
        assert!(native_disclosure_memory("full-response-v1", value).is_ok());
    }
    assert!(native_disclosure_memory("redacted-response-v1", "3072").is_ok());
    for value in ["511", "448", "4097", "01024", "1024.0"] {
        assert!(native_disclosure_memory("full-response-v1", value).is_err());
    }
    for value in ["512", "1024", "2048", "3071"] {
        assert!(native_disclosure_memory("redacted-response-v1", value).is_err());
    }
    for value in ["448", "512", "1024", "4096"] {
        assert!(native_disclosure_memory("private-headers-gzip-v1", value).is_ok());
    }
    for value in ["447", "384", "0447", "4097"] {
        assert!(native_disclosure_memory("private-headers-gzip-v1", value).is_err());
    }
    for policy in [
        "full-response-v2",
        "",
        "redacted-max-v1",
        "private-headers-gzip",
        "private-headers-gzip-v2",
    ] {
        assert!(native_disclosure_memory(policy, "1024").is_err());
    }
}
