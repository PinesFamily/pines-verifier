//! Measured hardware verifier. Fixed enclave-local ciphertext egress, WebPKI roots.
//! stdout is private IPC to the evaluator process INSIDE the candidate boundary.
//! Never expose this binary, its stdout, or its loopback socket on a parent host
//! with real data. Launch only inside the measured image.
use base64::{engine::general_purpose::STANDARD, Engine};
use eyre::{ensure, eyre, Result};
use serde_json::json;
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
use tlsn::{
    config::verifier::VerifierConfig, connection::ServerName, verifier::VerifierCommitStart,
    webpki::RootCertStore, Session,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use ws_stream_tungstenite::WsStream;

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

#[tokio::main]
async fn main() -> Result<()> {
    ensure!(std::path::Path::new("/dev/nsm").exists(), "NSM_REQUIRED");
    let args: Vec<String> = std::env::args().collect();
    ensure!(args.len() == 2, "NO_HOST_CONFIGURATION");
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
    let result = tokio::time::timeout(Duration::from_secs(120), async {
        let (socket, _) = listener.accept().await?;
        let ws_config = async_tungstenite::tungstenite::protocol::WebSocketConfig::default()
            .max_message_size(Some(1024 * 1024)).max_frame_size(Some(1024 * 1024));
        let ws = async_tungstenite::tokio::accept_async_with_config(socket, Some(ws_config)).await?;
        let stream = transport_policy::BoundedIo::protocol(WsStream::new(ws).compat(), 64 * 1024 * 1024);
        let session = Session::new(stream.compat());
        let (driver, mut handle) = session.split();
        let driver_task = tokio::spawn(driver);
        // Abort the mux on every early return; never detach a failed session.
        struct Guard(tokio::task::AbortHandle);
        impl Drop for Guard { fn drop(&mut self) { self.0.abort(); } }
        let _guard = Guard(driver_task.abort_handle());
        let verifier = handle.new_verifier(VerifierConfig::builder().root_store(roots).build()?)?;
        let VerifierCommitStart::Proxy(verifier) = verifier.commit().await? else {
            return Err(eyre!("MODE_REFUSED"));
        };
        ensure!(verifier.config().server_name().as_str() == ticket.server_name, "HOST_REFUSED");
        // Measured adapter routes ciphertext to the provider's fixed CID3 port.
        let socket = TcpStream::connect(origin).await?;
        let socket = transport_policy::BoundedIo::origin(socket, Some(&ticket));
        let online = Instant::now();
        let verifier = verifier.accept().await?.run(socket.compat()).await?;
        let online_ms = online.elapsed().as_millis();
        let finalization = Instant::now();
        let (output, verifier) = verifier.verify().await?.accept().await?;
        verifier.close().await?;
        handle.close();
        driver_task.await??;
        let Some(ServerName::Dns(name)) = output.server_name else { return Err(eyre!("IDENTITY_REQUIRED")); };
        ensure!(name.as_str() == ticket.server_name, "HOST_REFUSED");
        let mut transcript = output.transcript.ok_or_else(|| eyre!("TRANSCRIPT_REQUIRED"))?;
        ensure!(transcript.len_sent() <= 8192 && transcript.len_received() <= 65536, "TRANSCRIPT_LIMIT");
        transcript.set_unauthed(0);
        ensure!(output.transcript_commitments.is_empty(), "UNEXPECTED_COMMITMENTS");
        Ok::<_, eyre::Report>(json!({"type":"verified", "attested":false, "mode":"Proxy", "host":name.as_str(),
            "sent":STANDARD.encode(transcript.sent_unsafe()), "recv":STANDARD.encode(transcript.received_unsafe()),
            "sentAuthed":transcript.sent_authed().iter().collect::<Vec<_>>(),
            "recvAuthed":transcript.received_authed().iter().collect::<Vec<_>>(), "extraCommitments":0,
            "onlineMs":online_ms, "finalizationMs":finalization.elapsed().as_millis(),
            "elapsedMs":started.elapsed().as_millis()}))
    }).await;
    match result {
        Ok(Ok(output)) => println!("{output}"),
        // No error excerpts: TLS/provider/cryptographic messages are private by default.
        Ok(Err(_)) => println!("{}", json!({"type":"refused","code":"PROTOCOL_REFUSED"})),
        Err(_) => println!("{}", json!({"type":"refused","code":"SESSION_DEADLINE"})),
    }
    Ok(())
}

#[cfg(test)]
mod provider_tests {
    use super::provider;
    #[test]
    fn only_fixed_provider_destinations_exist() {
        assert_eq!(provider("chatgpt").unwrap(), ("chatgpt.com", "127.0.0.1:18001"));
        assert_eq!(provider("claude").unwrap(), ("claude.ai", "127.0.0.1:18002"));
        assert_eq!(provider("grok").unwrap(), ("grok.com", "127.0.0.1:18003"));
        for value in ["", "https://claude.ai", "127.0.0.1:9", "claude.ai", "CLAUDE", "grok.com:443"] {
            assert!(provider(value).is_err());
        }
    }
}
