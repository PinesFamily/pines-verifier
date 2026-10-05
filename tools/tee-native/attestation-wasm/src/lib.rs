//! Thin binding to the maintained Evervault validator. No trust-root injection,
//! clock override, simulation root, logging, or acceptance of parsed host claims.
//! JS additionally applies bounded duplicate-rejecting CBOR decoding and the
//! application policy to the SAME signed bytes. See ../nitro.mjs.
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn verify_document(document: &[u8]) -> bool {
    !document.is_empty()
        && document.len() <= 16384
        && attestation_doc_validation::validate_and_parse_attestation_doc(document).is_ok()
}
