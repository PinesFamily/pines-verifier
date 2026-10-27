//! Transcript lengths this verifier measured itself (tlsn#1194).
//!
//! In Proxy mode the verifier relays every TLS record between the prover and the
//! origin, so the application-data lengths of its own `TlsTranscript` are session
//! facts. A `PartialTranscript` from the prover merely declares its totals. The
//! native adapters measure these lengths after `run()` and before `verify()`
//! receives the prover's proposal, refuse anything above the fixed limits, and
//! size every materialized transcript by them alone. The vendored `accept()` also
//! refuses a declared total that differs from the recorded ciphertext length.
//!
//! Ported from `DisclosurePolicy::transcript` of the disabled full-response draft
//! (`da6070da`, reviewed on the `tee-us-east-qualification` lineage) with only the
//! redacted policy's limits; no disclosure policy is selected here.
use tlsn::transcript::{ContentType, Record};

/// Request and response plaintext limits, equal to the transport ticket's.
pub const MAX_SENT_BYTES: usize = 8192;
pub const MAX_RECEIVED_BYTES: usize = 65536;
/// Application-data records per direction, equal to the origin record cap.
pub const MAX_RECORDS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TranscriptBounds {
    pub sent: usize,
    pub received: usize,
}

/// Neither clones plaintext/ciphertext nor allocates a combined transcript.
pub fn measure(sent: &[Record], received: &[Record]) -> Result<TranscriptBounds, &'static str> {
    fn bound(records: &[Record], max_bytes: usize) -> Result<usize, &'static str> {
        let mut length = 0usize;
        let mut count = 0usize;
        for record in records {
            if record.typ != ContentType::ApplicationData {
                continue;
            }
            count = count.checked_add(1).ok_or("TRANSCRIPT_LIMIT")?;
            length = length
                .checked_add(record.ciphertext.len())
                .ok_or("TRANSCRIPT_LIMIT")?;
            if count > MAX_RECORDS || length > max_bytes {
                return Err("TRANSCRIPT_LIMIT");
            }
        }
        if length == 0 {
            return Err("TRANSCRIPT_LIMIT");
        }
        Ok(length)
    }
    Ok(TranscriptBounds {
        sent: bound(sent, MAX_SENT_BYTES)?,
        received: bound(received, MAX_RECEIVED_BYTES)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(typ: ContentType, length: usize) -> Record {
        Record {
            seq: 1,
            typ,
            plaintext: None,
            explicit_nonce: vec![],
            ciphertext: vec![0; length],
            tag: None,
        }
    }
    fn data(length: usize) -> Record {
        record(ContentType::ApplicationData, length)
    }

    #[test]
    fn relayed_application_data_bounds_both_directions_before_the_proposal() {
        assert_eq!(
            measure(&[data(8000), data(192)], &[data(65536)]),
            Ok(TranscriptBounds {
                sent: 8192,
                received: 65536
            })
        );
        assert_eq!(measure(&[data(8193)], &[data(1)]), Err("TRANSCRIPT_LIMIT"));
        assert_eq!(
            measure(&[data(1)], &[data(65536), data(1)]),
            Err("TRANSCRIPT_LIMIT")
        );
    }

    #[test]
    fn handshake_records_do_not_count_and_empty_directions_refuse() {
        let handshake = record(ContentType::Handshake, 18_432);
        assert_eq!(
            measure(&[handshake.clone(), data(3)], &[handshake.clone(), data(5)]),
            Ok(TranscriptBounds {
                sent: 3,
                received: 5
            })
        );
        assert_eq!(
            measure(&[handshake.clone()], &[data(5)]),
            Err("TRANSCRIPT_LIMIT")
        );
        assert_eq!(measure(&[data(3)], &[]), Err("TRANSCRIPT_LIMIT"));
        assert_eq!(measure(&[data(0)], &[data(5)]), Err("TRANSCRIPT_LIMIT"));
    }

    #[test]
    fn record_count_is_bounded_even_for_tiny_records() {
        let tiny = vec![data(1); MAX_RECORDS];
        assert_eq!(
            measure(&tiny, &tiny),
            Ok(TranscriptBounds {
                sent: MAX_RECORDS,
                received: MAX_RECORDS
            })
        );
        let mut more = tiny.clone();
        more.push(data(1));
        assert_eq!(measure(&more, &tiny), Err("TRANSCRIPT_LIMIT"));
        assert_eq!(measure(&tiny, &more), Err("TRANSCRIPT_LIMIT"));
    }
}
