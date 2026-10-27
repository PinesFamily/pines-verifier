//! The signed ticket's disclosure policy, enforced between `verify()` and
//! `Verifier<Verify>::accept`, before accept allocates plaintext references or
//! cipher circuits. The measured launcher selects it from the validated ticket;
//! a TLSN peer never does. Byte and record limits are the session-measured ones
//! (`session_bounds`); this module adds only what differs per policy.
use crate::session_bounds::{self, TranscriptBounds};
use tlsn::{
    config::prove::ProveRequest,
    transcript::{ContentType, Record},
};

/// A complete response disclosure takes a small request: at most this many
/// relayed request records (the redacted path keeps `session_bounds::MAX_RECORDS`).
pub const FULL_MAX_SENT_RECORDS: usize = 32;
/// Revealed request ranges, in every policy.
pub const MAX_SENT_RANGES: usize = 64;

/// The private-headers class. Every response header value except the framing is
/// hidden, so the response direction loses TLSNotary's reveal-all fast path and every
/// revealed byte is authenticated in zero knowledge, one AES-128 circuit per 16-byte
/// block it touches (`transcript_internal::auth`, `alloc_plaintext`/`alloc_keystream`).
/// Revealed bytes, not total bytes, are therefore the budget, and these caps are
/// enforced in `proposal()` — between `verify()` and `accept()` — before `accept()`
/// allocates one plaintext reference or keystream block.
///
/// Mirrored in `tools/tee-native/disclosure-policy.mjs` as `REVEAL_CAPS`, which the
/// browser's planner and the enclave's evaluator use; a test asserts the two agree.
/// The JS mirror is never the only check: this one runs inside the measured verifier.
pub const PRIVATE_MAX_REVEALED_RECV_BYTES: usize = 4096;
pub const PRIVATE_MAX_REVEALED_SENT_BYTES: usize = 1024;
/// At most 32 hidden header values, so at most 33 revealed runs around them.
pub const PRIVATE_MAX_RECV_RANGES: usize = 33;
pub const PRIVATE_MAX_HIDDEN_RECV_RANGES: usize = 32;
/// Hiding N complete header values leaves at most N + 1 revealed runs around them.
const _: () = assert!(PRIVATE_MAX_RECV_RANGES == PRIVATE_MAX_HIDDEN_RECV_RANGES + 1);
/// Transport bounds for the class, equal to the signed ticket's.
pub const PRIVATE_MAX_RECV_BYTES: usize = 8192;
pub const PRIVATE_MAX_RECV_RECORDS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisclosurePolicy {
    Redacted,
    FullResponse,
    PrivateHeaders,
}

impl DisclosurePolicy {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "redacted-response-v1" => Ok(Self::Redacted),
            "full-response-v1" => Ok(Self::FullResponse),
            "private-headers-gzip-v1" => Ok(Self::PrivateHeaders),
            _ => Err("DISCLOSURE_POLICY"),
        }
    }

    /// Lengths of the records this verifier relayed, plus the policy's request
    /// record cap. Measured after `run()`, before the prover's proposal.
    pub fn transcript(
        self,
        sent: &[Record],
        received: &[Record],
    ) -> Result<TranscriptBounds, &'static str> {
        let bounds = session_bounds::measure(sent, received)?;
        let data_records = |records: &[Record]| {
            records
                .iter()
                .filter(|record| record.typ == ContentType::ApplicationData)
                .count()
        };
        if self != Self::Redacted && data_records(sent) > FULL_MAX_SENT_RECORDS {
            return Err("DISCLOSURE_LIMIT");
        }
        // The private-headers class relays a far smaller response than the measured
        // session maximum, and refuses the excess here, before any proof work.
        if self == Self::PrivateHeaders
            && (bounds.received > PRIVATE_MAX_RECV_BYTES
                || data_records(received) > PRIVATE_MAX_RECV_RECORDS)
        {
            return Err("DISCLOSURE_LIMIT");
        }
        Ok(bounds)
    }

    /// The peer's reveal/commit request, checked against measured lengths. A
    /// full-response session that asks for anything less than the entire
    /// response is refused here; it never falls back to the redacted path.
    pub fn proposal(
        self,
        request: &ProveRequest,
        bounds: TranscriptBounds,
    ) -> Result<(), &'static str> {
        if !request.server_identity() {
            return Err("IDENTITY_REQUIRED");
        }
        // Even an empty commitment configuration is refused: checking output
        // commitments after accept() would already have spent the memory.
        if request.transcript_commit().is_some() {
            return Err("UNEXPECTED_COMMITMENTS");
        }
        let Some((sent, received)) = request.reveal() else {
            return Err("TRANSCRIPT_REQUIRED");
        };
        let mut count = 0usize;
        let mut previous_end = None;
        let mut revealed_sent = 0usize;
        for range in sent.iter() {
            count += 1;
            if count > MAX_SENT_RANGES
                || range.start >= range.end
                || range.end > bounds.sent
                || previous_end.is_some_and(|end| range.start <= end)
            {
                return Err("DISCLOSURE_REQUEST_RANGES");
            }
            previous_end = Some(range.end);
            revealed_sent += range.end - range.start;
        }
        if count == 0 {
            return Err("DISCLOSURE_REQUEST_RANGES");
        }
        if self == Self::FullResponse && received != &(0..bounds.received) {
            return Err("FULL_RESPONSE_REQUIRED");
        }
        let mut recv_ranges = 0usize;
        let mut revealed_recv = 0usize;
        for range in received.iter() {
            if range.start >= range.end || range.end > bounds.received {
                return Err("DISCLOSURE_LIMIT");
            }
            recv_ranges += 1;
            revealed_recv += range.end - range.start;
        }
        // The pre-zero-knowledge budget. `accept()` has not run yet, so nothing
        // proportional to these numbers has been allocated when this refuses.
        if self == Self::PrivateHeaders {
            if recv_ranges == 0 || recv_ranges > PRIVATE_MAX_RECV_RANGES {
                return Err("DISCLOSURE_RESPONSE_RANGES");
            }
            if revealed_recv > PRIVATE_MAX_REVEALED_RECV_BYTES
                || revealed_sent > PRIVATE_MAX_REVEALED_SENT_BYTES
            {
                return Err("DISCLOSURE_REVEAL_LIMIT");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rangeset::set::RangeSet;
    use tlsn::{config::prove::ProveConfig, transcript::Transcript};

    fn proposal(
        sent: Vec<std::ops::Range<usize>>,
        recv: Vec<std::ops::Range<usize>>,
        identity: bool,
    ) -> ProveRequest {
        let transcript = Transcript::new(
            vec![0; session_bounds::MAX_SENT_BYTES],
            vec![0; session_bounds::MAX_RECEIVED_BYTES],
        );
        let mut config = ProveConfig::builder(&transcript);
        if identity {
            config.server_identity();
        }
        config
            .reveal_sent(RangeSet::new_from_slice(&sent))
            .unwrap()
            .reveal_recv(RangeSet::new_from_slice(&recv))
            .unwrap();
        config.build().unwrap().to_request()
    }
    fn bounds() -> TranscriptBounds {
        TranscriptBounds {
            sent: session_bounds::MAX_SENT_BYTES,
            received: session_bounds::MAX_RECEIVED_BYTES,
        }
    }
    fn record(length: usize) -> Record {
        Record {
            seq: 1,
            typ: ContentType::ApplicationData,
            plaintext: None,
            explicit_nonce: vec![],
            ciphertext: vec![0; length],
            tag: None,
        }
    }

    #[test]
    fn full_mode_rejects_partial_response_before_accept_and_never_falls_back() {
        let valid = proposal(vec![0..32, 8000..8192], vec![0..65536], true);
        assert_eq!(
            DisclosurePolicy::FullResponse.proposal(&valid, bounds()),
            Ok(())
        );
        for recv in [
            vec![0..65535],
            vec![1..65536],
            vec![0..128, 129..65536],
            vec![],
        ] {
            let partial = proposal(vec![0..32, 8000..8192], recv, true);
            assert_eq!(
                DisclosurePolicy::FullResponse.proposal(&partial, bounds()),
                Err("FULL_RESPONSE_REQUIRED")
            );
            assert_eq!(
                DisclosurePolicy::Redacted.proposal(&partial, bounds()),
                Ok(())
            );
        }
    }

    #[test]
    fn identity_commitments_and_request_ranges_are_checked_before_accept() {
        assert_eq!(
            DisclosurePolicy::FullResponse
                .proposal(&proposal(vec![0..32], vec![0..65536], false), bounds()),
            Err("IDENTITY_REQUIRED")
        );
        let mut value = serde_json::to_value(proposal(vec![0..32], vec![0..65536], true)).unwrap();
        value["transcript_commit"] = serde_json::json!({"hash":[]});
        let request = serde_json::from_value(value).unwrap();
        assert_eq!(
            DisclosurePolicy::FullResponse.proposal(&request, bounds()),
            Err("UNEXPECTED_COMMITMENTS")
        );
        let fragmented = proposal(
            (0..65).map(|i| i * 2..i * 2 + 1).collect(),
            vec![0..65536],
            true,
        );
        assert_eq!(
            DisclosurePolicy::FullResponse.proposal(&fragmented, bounds()),
            Err("DISCLOSURE_REQUEST_RANGES")
        );
        assert_eq!(
            DisclosurePolicy::FullResponse.proposal(
                &proposal(vec![0..8192], vec![0..65536], true),
                TranscriptBounds {
                    sent: 8191,
                    received: 65536
                }
            ),
            Err("DISCLOSURE_REQUEST_RANGES")
        );
    }

    #[test]
    fn measured_records_bound_both_policies_and_full_mode_caps_request_records() {
        let received = vec![record(65536)];
        for policy in [DisclosurePolicy::Redacted, DisclosurePolicy::FullResponse] {
            assert_eq!(policy.transcript(&[record(8192)], &received), Ok(bounds()));
            assert_eq!(
                policy.transcript(&[record(8193)], &received),
                Err("TRANSCRIPT_LIMIT")
            );
            assert_eq!(
                policy.transcript(&[record(1)], &[record(65537)]),
                Err("TRANSCRIPT_LIMIT")
            );
            assert_eq!(policy.transcript(&[], &received), Err("TRANSCRIPT_LIMIT"));
        }
        let fragmented: Vec<_> = (0..33).map(|_| record(1)).collect();
        assert_eq!(
            DisclosurePolicy::FullResponse.transcript(&fragmented, &received),
            Err("DISCLOSURE_LIMIT")
        );
        assert!(DisclosurePolicy::Redacted
            .transcript(&fragmented, &received)
            .is_ok());
    }

    #[test]
    fn unknown_and_downgraded_policy_names_are_not_accepted() {
        for value in [
            "",
            "full-response",
            "full-response-v2",
            "FULL-RESPONSE-V1",
            "redacted-max-v1",
            "private-headers-gzip",
            "private-headers-gzip-v2",
            "private-headers-v1",
            "PRIVATE-HEADERS-GZIP-V1",
        ] {
            assert!(DisclosurePolicy::parse(value).is_err());
        }
        assert_eq!(
            DisclosurePolicy::parse("private-headers-gzip-v1"),
            Ok(DisclosurePolicy::PrivateHeaders)
        );
    }

    /// Four small-response bounds, each refused before the work it limits: the relayed
    /// response bytes and records at `transcript()`, and the revealed bytes and ranges
    /// at `proposal()`, which runs before `accept()` allocates any circuit.
    #[test]
    fn private_headers_bounds_the_relayed_response_before_the_proposal() {
        let small = vec![record(PRIVATE_MAX_RECV_BYTES)];
        let bounds = DisclosurePolicy::PrivateHeaders.transcript(&[record(8192)], &small);
        assert_eq!(
            bounds,
            Ok(TranscriptBounds {
                sent: 8192,
                received: PRIVATE_MAX_RECV_BYTES
            })
        );
        // One byte over the class cap, though far under the session maximum the other
        // policies admit, so the excess never reaches the prover's proposal.
        assert_eq!(
            DisclosurePolicy::PrivateHeaders.transcript(&[record(1)], &[record(PRIVATE_MAX_RECV_BYTES + 1)]),
            Err("DISCLOSURE_LIMIT")
        );
        assert!(DisclosurePolicy::Redacted
            .transcript(&[record(1)], &[record(PRIVATE_MAX_RECV_BYTES + 1)])
            .is_ok());
        // Record counts, which are what a fragmenting origin can inflate for free.
        let many: Vec<_> = (0..PRIVATE_MAX_RECV_RECORDS + 1).map(|_| record(1)).collect();
        assert_eq!(
            DisclosurePolicy::PrivateHeaders.transcript(&[record(1)], &many),
            Err("DISCLOSURE_LIMIT")
        );
        let exactly: Vec<_> = (0..PRIVATE_MAX_RECV_RECORDS).map(|_| record(1)).collect();
        assert!(DisclosurePolicy::PrivateHeaders
            .transcript(&[record(1)], &exactly)
            .is_ok());
        // The request record cap is the full-response one, not the redacted maximum.
        let fragmented: Vec<_> = (0..FULL_MAX_SENT_RECORDS + 1).map(|_| record(1)).collect();
        assert_eq!(
            DisclosurePolicy::PrivateHeaders.transcript(&fragmented, &small),
            Err("DISCLOSURE_LIMIT")
        );
    }

    #[test]
    fn private_headers_caps_revealed_bytes_and_ranges_before_accept() {
        let bounds = TranscriptBounds {
            sent: session_bounds::MAX_SENT_BYTES,
            received: PRIVATE_MAX_RECV_BYTES,
        };
        // A realistic plan: a small revealed request around a hidden credential, and a
        // response revealed in runs between hidden header values.
        let runs: Vec<_> = (0..PRIVATE_MAX_RECV_RANGES)
            .map(|index| index * 64..index * 64 + 32)
            .collect();
        let valid = proposal(vec![0..200, 2500..2800], runs.clone(), true);
        assert_eq!(
            DisclosurePolicy::PrivateHeaders.proposal(&valid, bounds),
            Ok(())
        );
        // One revealed run too many, though every run is in bounds.
        let extra: Vec<_> = (0..PRIVATE_MAX_RECV_RANGES + 1)
            .map(|index| index * 64..index * 64 + 32)
            .collect();
        assert_eq!(
            DisclosurePolicy::PrivateHeaders.proposal(&proposal(vec![0..200], extra, true), bounds),
            Err("DISCLOSURE_RESPONSE_RANGES")
        );
        // One revealed byte over the budget.
        assert_eq!(
            DisclosurePolicy::PrivateHeaders.proposal(
                &proposal(
                    vec![0..200],
                    vec![0..PRIVATE_MAX_REVEALED_RECV_BYTES + 1],
                    true
                ),
                bounds
            ),
            Err("DISCLOSURE_REVEAL_LIMIT")
        );
        assert_eq!(
            DisclosurePolicy::PrivateHeaders.proposal(
                &proposal(vec![0..PRIVATE_MAX_REVEALED_RECV_BYTES], vec![0..32], true),
                bounds
            ),
            Err("DISCLOSURE_REVEAL_LIMIT")
        );
        assert_eq!(
            DisclosurePolicy::PrivateHeaders.proposal(
                &proposal(
                    vec![0..PRIVATE_MAX_REVEALED_SENT_BYTES],
                    vec![0..PRIVATE_MAX_REVEALED_RECV_BYTES],
                    true
                ),
                bounds
            ),
            Ok(())
        );
        // Revealing the whole response is what the class exists to avoid: it is refused
        // here rather than silently costing a full-response proof's worth of circuits.
        assert_eq!(
            DisclosurePolicy::PrivateHeaders
                .proposal(&proposal(vec![0..200], vec![0..bounds.received], true), bounds),
            Err("DISCLOSURE_REVEAL_LIMIT")
        );
        // The checks every policy shares still apply first.
        assert_eq!(
            DisclosurePolicy::PrivateHeaders
                .proposal(&proposal(vec![0..200], vec![0..32], false), bounds),
            Err("IDENTITY_REQUIRED")
        );
        assert_eq!(
            DisclosurePolicy::PrivateHeaders.proposal(&proposal(vec![], vec![0..32], true), bounds),
            Err("DISCLOSURE_REQUEST_RANGES")
        );
        // And the other two policies are unchanged by any of this.
        assert_eq!(
            DisclosurePolicy::Redacted.proposal(
                &proposal(vec![0..200], vec![0..bounds.received], true),
                bounds
            ),
            Ok(())
        );
    }
}
