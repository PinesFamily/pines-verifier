# Schema provenance

The TypeScript types, parsers, policy helpers, adapter and test data here were written for Pines; no BringID source
files or provider response samples were copied into it. The design reuses the separation between capture, replay,
disclosure and semantic checks. There is no Semaphore code or dependency.

`pines.fixture.httpbingo@1` describes the public [HTTPBingo JSON fixture](https://httpbingo.org/json). It fixes public
request headers and checks the slideshow author/title and minimum slide count. It contains no saved provider response,
credentials or account identifiers. `pines.fixture.httpbingo-private@1` is a separate synthetic policy for the same
endpoint, with a natively redacted synthetic Bearer value.

Inspected references:

- `BringID/browser-extension`, revision `50109f13dd4d082853a76e29fc323a824f7d686c` (AGPL-3.0):
  [declarative handler types](https://github.com/BringID/browser-extension/blob/50109f13dd4d082853a76e29fc323a824f7d686c/src/side-panel/services/notarization/types.ts),
  `src/side-panel/services/notarization/helpers.ts`, and the
  [Binance simple handler](https://github.com/BringID/browser-extension/blob/50109f13dd4d082853a76e29fc323a824f7d686c/src/side-panel/services/notarization/handlers/binance-kyc.ts).
  The representative numeric paths are kept only in a synthetic fixture on `schemas.example.test`; no account
  identifiers or production KYC integration are included.
- `BringID/tlsn-infra`, revision `3e47123cf0daa0ea98cf46f441d599ee9881419f`:
  `verifier/src/core/verification/check.rs`, `window.rs` and `verifications.json`. The legacy adapter keeps reviewed
  typed comparisons, requires explicit JSON ancestry, and refuses the ambiguous substring/custom/unchecked-key policies.
- TLSNotary revision `47aee45b53e06648c1b2ad3689b367b8c923fdec`:
  [formats security limitation](https://github.com/tlsnotary/tlsn/blob/47aee45b53e06648c1b2ad3689b367b8c923fdec/crates/formats/src/lib.rs).
  This informs the opaque-redaction semantics and regression described in the README.
