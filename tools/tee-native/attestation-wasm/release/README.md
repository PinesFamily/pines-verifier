These are the pinned Nitro validator artifacts the extension and the measured enclave load. Source: `../src/lib.rs`,
`../Cargo.toml`, `../Cargo.lock` (Evervault's `attestation-doc-validation` at `a296a77c2b23fef8214131287423fe47c755eb3c`).
They are built in a pinned container (`../../reproduce/Dockerfile.attestation-wasm`: Rust 1.95.0, clang 14.0.6,
wasm-bindgen 0.2.104), so the embedded source paths are the container's, and `../../reproduce/attestation-wasm.sh`
rebuilds them and compares the result with `SHA256SUMS`. Nothing fetches executable code at runtime. Rebuilt bytes
must match these hashes; a different validator needs its own qualification.
