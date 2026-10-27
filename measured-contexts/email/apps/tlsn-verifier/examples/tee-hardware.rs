//! Measured hardware verifier. Fixed enclave-local ciphertext egress, WebPKI roots.
//! stdout is private IPC to the evaluator process INSIDE the candidate boundary.
//! Never expose this binary, its stdout, or its loopback socket on a parent host
//! with real data. Launch only inside the measured image.
use async_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use base64::{engine::general_purpose::STANDARD, Engine};
use eyre::{ensure, eyre, Result};
use serde_json::json;
use std::{
    net::SocketAddr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tlsn::{
    config::verifier::VerifierConfig, connection::ServerName, verifier::VerifierCommitStart,
    webpki::RootCertStore, Session,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use ws_stream_tungstenite::WsStream;

// Numeric kernel high-water marks read after proof evaluation. Private proc
// text never crosses the native boundary. Failures remain unavailable, not 0.
fn process_peaks() -> Result<serde_json::Value> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let bytes = |field: &str| -> Result<u64> {
        let line = status.lines().find(|line| line.starts_with(field)).ok_or_else(|| eyre!("METRICS_UNAVAILABLE"))?;
        let fields: Vec<_> = line.split_whitespace().collect();
        ensure!(fields.len() == 3 && fields[2] == "kB", "METRICS_UNAVAILABLE");
        fields[1].parse::<u64>()?.checked_mul(1024).ok_or_else(|| eyre!("METRICS_UNAVAILABLE"))
    };
    Ok(json!({"peakRssBytes":bytes("VmHWM:")?,"peakVirtualBytes":bytes("VmPeak:")?}))
}

// Fixed categories only. The nested TLSN error can contain provider data, so
// neither its text nor any substring is included in the private IPC result.
fn refusal_stage(stage: &'static str, error: &eyre::Report) -> &'static str {
    if stage != "NATIVE_PROXY_RUN" { return stage; }
    let mut context = None;
    let mut io_kind = None;
    let mut tlsn_io = false;
    for source in error.chain() {
        if let Some(io) = source.downcast_ref::<std::io::Error>() { io_kind = Some(io.kind()); }
        if let Some(tlsn) = source.downcast_ref::<tlsn::Error>() { tlsn_io |= tlsn.is_io(); }
        let text = source.to_string();
        for (known, code) in [
            ("proxy traffic forwarding failed", "NATIVE_PROXY_FORWARD"),
            ("verifier could not build tls transcript", "NATIVE_PROXY_TRANSCRIPT"),
            ("preprocessing proxy-tls failed", "NATIVE_PROXY_PREPROCESS"),
            ("tag verification setup failed", "NATIVE_PROXY_TAG_SETUP"),
            ("tag verification zk execution failed", "NATIVE_PROXY_TAG_EXECUTION"),
            ("tag verification failed", "NATIVE_PROXY_TAG_VERIFY"),
        ] {
            if context.is_none() && text.contains(known) { context = Some(code); }
        }
    }
    if context == Some("NATIVE_PROXY_FORWARD") {
        return match io_kind {
            Some(std::io::ErrorKind::BrokenPipe) => "NATIVE_PROXY_FORWARD_BROKEN_PIPE",
            Some(std::io::ErrorKind::ConnectionReset) => "NATIVE_PROXY_FORWARD_RESET",
            Some(std::io::ErrorKind::UnexpectedEof) => "NATIVE_PROXY_FORWARD_EOF",
            Some(std::io::ErrorKind::TimedOut) => "NATIVE_PROXY_FORWARD_TIMEOUT",
            Some(std::io::ErrorKind::PermissionDenied) => "NATIVE_PROXY_FORWARD_POLICY",
            Some(_) => "NATIVE_PROXY_FORWARD_IO",
            None => "NATIVE_PROXY_FORWARD",
        };
    }
    context.unwrap_or(if tlsn_io || io_kind.is_some() { "NATIVE_PROXY_IO" } else { stage })
}

fn private_channel_upgrade(
    request: &Request,
    response: Response,
    token: &str,
) -> std::result::Result<Response, ErrorResponse> {
    let mut values = request.headers().get_all("x-pines-native-session").iter();
    let value = values.next();
    let valid = value.is_some_and(|v| {
        v.as_bytes().len() == token.len()
            && v.as_bytes()
                .iter()
                .zip(token.as_bytes())
                .fold(0u8, |diff, (a, b)| diff | (a ^ b))
                == 0
    }) && values.next().is_none();
    if valid {
        Ok(response)
    } else {
        Err(Response::builder().status(403).body(None).unwrap())
    }
}

async fn private_channel(
    listener: &TcpListener,
    token: &str,
) -> Result<async_tungstenite::WebSocketStream<async_tungstenite::tokio::TokioAdapter<TcpStream>>> {
    // A crashed child's port can be reused before its caller connects. Refuse
    // that caller's token and still let the intended owner connect. Attempts,
    // upgrade time and the outer signed session deadline are all bounded.
    for _ in 0..8 {
        let (socket, _) = listener.accept().await?;
        let config = async_tungstenite::tungstenite::protocol::WebSocketConfig::default()
            .max_message_size(Some(1024 * 1024))
            .max_frame_size(Some(1024 * 1024));
        let handshake = async_tungstenite::tokio::accept_hdr_async_with_config(
            socket,
            |request: &Request, response: Response| {
                private_channel_upgrade(request, response, token)
            },
            Some(config),
        );
        if let Ok(Ok(ws)) = tokio::time::timeout(Duration::from_secs(2), handshake).await {
            return Ok(ws);
        }
    }
    Err(eyre!("PRIVATE_CHANNEL_REFUSED"))
}

// Reuse the admitted path's byte and record limiter unchanged in this experiment.
#[allow(dead_code)]
mod gateway {
    pub struct Ticket {
        pub server_name: String,
        pub max_sent_bytes: usize,
        pub max_recv_bytes: usize,
        pub max_recv_records: usize,
    }
}
#[path = "../src/disclosure_policy.rs"]
mod disclosure_policy;
#[path = "../src/session_bounds.rs"]
mod session_bounds;
use disclosure_policy::DisclosurePolicy;
#[allow(dead_code)]
#[path = "../src/transport_policy.rs"]
mod transport_policy;

// Only the measured evaluator selects this enum after validating the signed
// ticket. No host name, URL, root certificate or origin port comes from a peer.
fn provider(id: &str) -> Result<(&'static str, &'static str)> {
    match id {
        "chatgpt" => Ok(("chatgpt.com", "127.0.0.1:18001")),
        "claude" => Ok(("claude.ai", "127.0.0.1:18002")),
        "grok" => Ok(("grok.com", "127.0.0.1:18003")),
        _ => Err(eyre!("PROVIDER_REFUSED")),
    }
}

// These bounds deliberately live in Rust as well as the measured JS validator.
// The deadline is the signed attempt-creation deadline, never a new native timer.
const SESSION_BUDGET_MIN_MS: u64 = 120_000;
const SESSION_BUDGET_MAX_MS: u64 = 300_000;
fn session_timeout(deadline: &str, budget: &str, now: u64) -> Result<Duration> {
    fn integer(value: &str) -> Result<u64> {
        ensure!(
            !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
            "SESSION_DEADLINE"
        );
        Ok(value.parse()?)
    }
    let budget = integer(budget)?;
    ensure!(
        (SESSION_BUDGET_MIN_MS..=SESSION_BUDGET_MAX_MS).contains(&budget),
        "SESSION_BUDGET"
    );
    let remaining = integer(deadline)?
        .checked_sub(now)
        .ok_or_else(|| eyre!("SESSION_DEADLINE"))?;
    ensure!(
        remaining > 0 && remaining <= budget && remaining <= SESSION_BUDGET_MAX_MS,
        "SESSION_DEADLINE"
    );
    Ok(Duration::from_millis(remaining))
}

// Each independent proof owns a small executor; do not multiply enclave CPU
// count by every child. Rayon is separately capped by the measured launcher.
#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    ensure!(std::path::Path::new("/dev/nsm").exists(), "NSM_REQUIRED");
    let args: Vec<String> = std::env::args().collect();
    ensure!(args.len() == 6, "NO_HOST_CONFIGURATION");
    ensure!(
        args[4].len() == 64
            && args[4]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "PRIVATE_CHANNEL_REFUSED"
    );
    // The measured launcher passes the signed ticket's policy; it also fixed
    // this process's address-space cap for that policy before exec.
    let disclosure = DisclosurePolicy::parse(&args[5]).map_err(|code| eyre!(code))?;
    let (host, route) = provider(&args[1])?;
    let origin: SocketAddr = route.parse()?;
    let roots = RootCertStore::mozilla();
    let ticket = gateway::Ticket {
        server_name: host.into(),
        max_sent_bytes: 8192,
        max_recv_bytes: 65536,
        max_recv_records: 1024,
    };
    ensure!(
        ticket.max_recv_records > 0 && ticket.max_recv_records <= 1024,
        "record cap"
    );
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    println!(
        "{}",
        json!({"type":"listening", "port":listener.local_addr()?.port(), "attested":false})
    );
    let started = Instant::now();
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let remaining = session_timeout(&args[2], &args[3], now)?;
    // A closed stage name is the only failure detail that leaves this process.
    let mut stage = "NATIVE_CHANNEL";
    let result = tokio::time::timeout(remaining, async {
        let ws = private_channel(&listener,&args[4]).await?;
        let stream = transport_policy::BoundedIo::protocol(WsStream::new(ws).compat(), 64 * 1024 * 1024);
        let session = Session::new(stream.compat());
        let (driver, mut handle) = session.split();
        let driver_task = tokio::spawn(driver);
        // Abort the mux on every early return; never detach a failed session.
        struct Guard(tokio::task::AbortHandle);
        impl Drop for Guard { fn drop(&mut self) { self.0.abort(); } }
        let _guard = Guard(driver_task.abort_handle());
        let verifier = handle.new_verifier(VerifierConfig::builder().root_store(roots).build()?)?;
        stage = "NATIVE_COMMIT_PROPOSAL";
        let VerifierCommitStart::Proxy(verifier) = verifier.commit().await? else {
            return Err(eyre!("MODE_REFUSED"));
        };
        ensure!(verifier.config().server_name().as_str() == ticket.server_name, "HOST_REFUSED");
        // Measured adapter routes ciphertext to the provider's fixed CID3 port.
        stage = "NATIVE_ORIGIN_CONNECT";
        let socket = TcpStream::connect(origin).await?;
        let socket = transport_policy::BoundedIo::origin(socket, Some(&ticket));
        let online = Instant::now();
        stage = "NATIVE_COMMIT_ACCEPT";
        let verifier = verifier.accept().await?;
        stage = "NATIVE_PROXY_RUN";
        let verifier = verifier.run(socket.compat()).await?;
        let online_ms = online.elapsed().as_millis();
        let finalization = Instant::now();
        // Lengths of the records this verifier relayed, measured and limited
        // before the prover's proposal arrives (tlsn#1194). Only these size
        // the transcript materialized below; declared totals never do.
        stage = "NATIVE_TRANSCRIPT_LIMIT";
        let bounds = disclosure
            .transcript(verifier.tls_transcript().sent(), verifier.tls_transcript().recv())
            .map_err(|code| eyre!(code))?;
        stage = "NATIVE_PROVE_PROPOSAL";
        let verifier = verifier.verify().await?;
        // The peer's reveal/commit request is checked before accept() creates
        // plaintext references or cipher circuits. No fallback is allowed.
        stage = "NATIVE_PROPOSAL_POLICY";
        disclosure
            .proposal(verifier.request(), bounds)
            .map_err(|code| eyre!(code))?;
        stage = "NATIVE_PROVE_ACCEPT";
        let (output, verifier) = verifier.accept().await?;
        stage = "NATIVE_DRIVER_CLOSE";
        verifier.close().await?;
        handle.close();
        driver_task.await??;
        stage = "NATIVE_OUTPUT_POLICY";
        let Some(ServerName::Dns(name)) = output.server_name else { return Err(eyre!("IDENTITY_REQUIRED")); };
        ensure!(name.as_str() == ticket.server_name, "HOST_REFUSED");
        let transcript = output.transcript.ok_or_else(|| eyre!("TRANSCRIPT_REQUIRED"))?;
        ensure!(transcript.len_sent() <= 8192 && transcript.len_received() <= 65536, "TRANSCRIPT_LIMIT");
        // Size plaintext by the records measured before verify(), never by the
        // peer's declared totals. Unauthenticated positions are zero.
        let sent = transcript.sent_unsafe(bounds.sent).map_err(|_| eyre!("TRANSCRIPT_LIMIT"))?;
        let recv = transcript.received_unsafe(bounds.received).map_err(|_| eyre!("TRANSCRIPT_LIMIT"))?;
        ensure!(output.transcript_commitments.is_empty(), "UNEXPECTED_COMMITMENTS");
        Ok::<_, eyre::Report>(json!({"type":"verified", "attested":false, "mode":"Proxy", "host":name.as_str(),
            "sent":STANDARD.encode(sent), "recv":STANDARD.encode(recv),
            "sentAuthed":transcript.sent_authed().iter().collect::<Vec<_>>(),
            "recvAuthed":transcript.received_authed().iter().collect::<Vec<_>>(), "extraCommitments":0,
            "onlineMs":online_ms, "finalizationMs":finalization.elapsed().as_millis(),
            "elapsedMs":started.elapsed().as_millis(),"processPeaks":process_peaks()?}))
    }).await;
    match result {
        Ok(Ok(output)) => println!("{output}"),
        // No error excerpts: TLS/provider/cryptographic messages are private by default.
        Ok(Err(error)) => println!("{}", json!({"type":"refused","code":refusal_stage(stage, &error)})),
        Err(_) => println!("{}", json!({"type":"refused","code":"SESSION_DEADLINE"})),
    }
    Ok(())
}

#[cfg(test)]
mod provider_tests {
    use super::{
        private_channel, private_channel_upgrade, provider, session_timeout, Request, Response,
    };
    use async_tungstenite::tungstenite::client::IntoClientRequest;
    use std::time::Duration;
    use tokio::net::TcpListener;

    #[test]
    fn proxy_refusal_metadata_never_exports_error_text() {
        use eyre::WrapErr;
        let error = Err::<(), _>(std::io::Error::new(std::io::ErrorKind::ConnectionReset,
            "Authorization: private-request-canary; private-response-canary"))
            .wrap_err("proxy traffic forwarding failed").unwrap_err();
        assert_eq!(super::refusal_stage("NATIVE_PROXY_RUN", &error), "NATIVE_PROXY_FORWARD_RESET");
        assert_eq!(super::refusal_stage("NATIVE_PROVE_ACCEPT", &error), "NATIVE_PROVE_ACCEPT");
        for (text, code) in [
            ("verifier could not build tls transcript", "NATIVE_PROXY_TRANSCRIPT"),
            ("preprocessing proxy-tls failed", "NATIVE_PROXY_PREPROCESS"),
            ("tag verification setup failed", "NATIVE_PROXY_TAG_SETUP"),
            ("tag verification zk execution failed", "NATIVE_PROXY_TAG_EXECUTION"),
            ("tag verification failed", "NATIVE_PROXY_TAG_VERIFY"),
        ] {
            let error = eyre::eyre!("private-response-canary").wrap_err(text);
            assert_eq!(super::refusal_stage("NATIVE_PROXY_RUN", &error), code);
        }
        assert_eq!(super::refusal_stage("NATIVE_PROXY_RUN", &eyre::eyre!("private-unclassified-canary")), "NATIVE_PROXY_RUN");
    }
    #[test]
    fn private_channel_rejects_missing_wrong_and_duplicate_process_tokens() {
        let token = "ab".repeat(32);
        for values in [
            vec![],
            vec!["cd".repeat(32)],
            vec![token.clone(), token.clone()],
        ] {
            let mut request = Request::builder().uri("/").body(()).unwrap();
            for value in values {
                request
                    .headers_mut()
                    .append("x-pines-native-session", value.parse().unwrap());
            }
            assert!(private_channel_upgrade(&request, Response::new(()), &token).is_err());
        }
        let request = Request::builder()
            .uri("/")
            .header("x-pines-native-session", &token)
            .body(())
            .unwrap();
        assert!(private_channel_upgrade(&request, Response::new(()), &token).is_ok());
    }
    #[tokio::test]
    async fn stale_process_connection_is_refused_without_consuming_the_new_owners_channel() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("ws://{}", listener.local_addr().unwrap());
        let token = "ab".repeat(32);
        let expected = token.clone();
        let server = tokio::spawn(async move { private_channel(&listener, &expected).await });
        let mut stale = address.clone().into_client_request().unwrap();
        stale
            .headers_mut()
            .insert("x-pines-native-session", "cd".repeat(32).parse().unwrap());
        assert!(async_tungstenite::tokio::connect_async(stale)
            .await
            .is_err());
        let mut owner = address.into_client_request().unwrap();
        owner
            .headers_mut()
            .insert("x-pines-native-session", token.parse().unwrap());
        let connected = async_tungstenite::tokio::connect_async(owner).await;
        assert!(connected.is_ok());
        assert!(tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap()
            .is_ok());
    }
    #[test]
    fn signed_remaining_budget_is_bounded_independently() {
        let now = 1_800_000_000_000;
        for elapsed in [0, 30_000, 90_000, 180_000, 299_999] {
            assert_eq!(
                session_timeout(&(now + 300_000).to_string(), "300000", now + elapsed).unwrap(),
                Duration::from_millis(300_000 - elapsed)
            );
        }
        for (deadline, budget) in [
            (now, "120000"),
            (now - 1, "120000"),
            (now + 300_001, "300000"),
            (now + 120_001, "120000"),
            (now + 1, "119999"),
            (now + 1, "300001"),
        ] {
            assert!(session_timeout(&deadline.to_string(), budget, now).is_err());
        }
        for invalid in [
            "",
            "1.2",
            "+120000",
            " 120000",
            "1e5",
            "18446744073709551616",
        ] {
            assert!(session_timeout(&(now + 1).to_string(), invalid, now).is_err());
            assert!(session_timeout(invalid, "120000", now).is_err());
        }
    }
    #[test]
    fn only_fixed_provider_destinations_exist() {
        assert_eq!(
            provider("chatgpt").unwrap(),
            ("chatgpt.com", "127.0.0.1:18001")
        );
        assert_eq!(
            provider("claude").unwrap(),
            ("claude.ai", "127.0.0.1:18002")
        );
        assert_eq!(provider("grok").unwrap(), ("grok.com", "127.0.0.1:18003"));
        for value in [
            "",
            "https://claude.ai",
            "127.0.0.1:9",
            "claude.ai",
            "CLAUDE",
            "grok.com:443",
        ] {
            assert!(provider(value).is_err());
        }
    }
}
