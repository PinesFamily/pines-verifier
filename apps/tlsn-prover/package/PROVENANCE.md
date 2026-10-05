# Provenance

The worker/offscreen design adapts the maintained `BringID/tlsn-extension` fork at
`604694d8da50aab76a4d5d477ad8142cd8de6127` (ProveManager worker and lifecycle, background offscreen mutex). Its MIT OR
Apache-2.0 declaration is retained in [UPSTREAM_LICENSE.md](UPSTREAM_LICENSE.md). This adaptation uses a fresh
dedicated worker per attempt and terminates it on cancellation.

Runtime components:

- `wasm/`: TLSNotary's prover, the integrity-pinned npm package `tlsn-wasm@0.1.0-alpha.15`, used unmodified in Proxy
  mode with native selective disclosure. There are no custom circuits or additional proof systems.
- `nitro-validation.wasm`: AWS Nitro attestation validation, a thin binding to Evervault's
  `attestation-doc-validation` at `a296a77c2b23fef8214131287423fe47c755eb3c`, built with Rust 1.95.0 and
  wasm-bindgen 0.2.104.
- `tee-worker.js`: bundles `@hpke/core` (HPKE channel) and `cbor2` (strict CBOR decoding) at the versions pinned in the
  source repository's lockfiles.
- `schemas/`: the provider request schemas and the strict HTTP/JSON evaluator, compiled from the source repository.
- `orb.js`: the side panel's loading orb with the thinking-orbs 0.3.2 engine (MIT); its notice is at the top of the file.
- `fonts/geist-latin.woff2`: Geist (SIL Open Font License 1.1, The Geist Project Authors); license in `fonts/OFL.txt`.

Capture uses Chrome's native `webRequest` events for the one request a schema names, on a provider site you grant
access to from the side panel. There are no content scripts and no remote code.
