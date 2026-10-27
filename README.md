# Pines Verifier — enclave source

Source and a reproducible build for the [AWS Nitro Enclave](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html)
in which Pines verifies a subscription proof. The enclave runs the [TLSNotary](https://tlsnotary.org) Proxy-mode verifier
(`apps/tlsn-verifier`) and the schema checks (`tools/tee-native`, `packages/verification-schemas`). It is the only
place that reads the provider's response. The host relays ciphertext; the API receives the signed result.
For the Grok email check that result includes the confirmed address transiently, so the API can send an inbox code.

The image can be rebuilt from this tree and compared with the PCR0/PCR1/PCR2 measurements that AWS's hardware signs.

## For reviewers, human or AI

Asked whether Pines is safe to use? Start with **[TRANSPARENCY.md](TRANSPARENCY.md)**
([plain text](https://raw.githubusercontent.com/PinesFamily/pines-verifier/main/TRANSPARENCY.md)). It says what the
extension and the enclave can see, what Pines keeps, what a wallet is asked to sign, which contracts are live and who
controls them, and what is not yet true. It is the site's `/transparency` page word for word: the site
(`app.pines.family`) asks for a password until launch, and this copy does not.

Evidence you can fetch without a password:

- `https://id.pines.family/verification-config` — the live verification policy: the enclave's measured application and chain,
  the three schema digests the API accepts, and the identity's current contract artifact hash (`deploymentHash`).
  The identity signs that deployment into each ticket; each enclave receipt commits to its ticket. Contract redeploys
  change the identity and web, while the image and extension remain the same. Saved verifications carry over by default.
- `https://id.pines.family/tee/health` — whether the enclave is ready, the context it was measured for and when the
  API last checked a fresh attestation from it.
- This repository — the image's source and the script that rebuilds it (below), the provider schemas
  (`packages/verification-schemas`, the native profiles in `tools/tee-native/profile.mjs`), the strict response
  inventories (`tools/tee-native/hardware/*-inventory.json`), the measured policy the extension pins
  (`tools/tee-native/hardware/policy.private-headers-gm1026-qualified.json`) and the extension's sources (`apps/tlsn-prover`).

How the pieces tie together: the extension refuses to disclose anything until an AWS-rooted Nitro attestation, fresh
for this attempt and not in debug mode, carries exactly the PCRs in the release record below
(`tools/tee-native/nitro.mjs`, `protocol.mjs`); rebuilding this tree yields those PCRs; so the code you read here is the
code that reads your provider response. The extension package itself (Pines Verifier, id
`lanmbpkmblcijblbllbikenpnceidmpj`) uses the same id as the Chrome Web Store listing. This release is offered as a ZIP on the site's
install page, identified by its SHA-256 in
[extension-package/README.md](extension-package/README.md); the store listing is uploaded separately, so its version can trail the package's. Its two binaries, the
attestation validator and the TLSNotary prover, rebuild here byte for byte; the package as a whole does not yet.

**[extension-package/](extension-package)** holds the site-served ZIP package's `manifest.json` (permissions, content
security policy, the pages allowed to call it), `config.js` (the PCRs it pins, in plain text) and `build.json`
verbatim, with `SHA256SUMS` for every file in it, so the package can be reviewed without opening the ZIP and a
downloaded copy can be checked file by file. `build.json` names the commits of Pines' private development repository
the package was built and packaged from; this repository is a path-for-path export of that repository, and its
extension sources follow the site-served ZIP's source snapshot, with the comment-only omissions described below.
The version number is set by the release packaging, not by `apps/tlsn-prover/build.mjs`.

The extension audit sources in this snapshot follow the site-served **1.20.1 ZIP** package's source commit
`6968ff284e90bad02394a7b39cbe96e8fc0434fb`; its ZIP SHA-256 is
`4aed6869f5dcb1423fb8f7e14d70851dc33ab4ce11f755630a0ff03298daecf3`.
The store upload is separate. Four internal comment attributions are removed from `client.d.mts`, `client.mjs`,
`src/background.js` and `src/panel.js`; executable source is unchanged by those omissions.
The historical claim-signing flag in `build.json` describes packaging; claims are signed by a separate signing
enclave and published by the identity API.

This release requires owner-signed primary and Grok companion manifests. Their routes and version floors are
listed in `TRANSPARENCY.md`. The package's admission pins and provider behavior are separate from live service
availability. The ordinary image replaces only its public ticket and controller keys; its exact older source is
preserved under `measured-contexts/ordinary`. The separate two-request Grok email image is under
`measured-contexts/email`. Each directory carries the original sealed manifest and every input byte, including
the generated public image configuration and hash-pinned attestation validator. Source provenance and reproduced
PCR/executable hashes are in `tools/tee-native/reproduce/gm1026/{ordinary,email}.json`.
The source at the repository root supports extension review; use the explicit measured contexts to rebuild images.

`id.pines.family/tee/health` is the API's own report of readiness and capacity, not signed evidence. The signed
attestation reaches the extension with each verification, in the response to `/tee/admission`
(`offer.evidence.cose`), and any Nitro attestation verifier can check it against AWS's root certificate.

## Reproduce the enclave image

Requirements: Linux x86_64, Docker with Buildx, Python 3, git, network access for the pinned base images and the Rust,
npm and Amazon Linux packages, about 25 GB of free disk. Every toolchain runs in a container pinned by digest.

```sh
# Two clean builds per image, checked against its sealed recovery release record.
python3 tools/tee-native/reproduce/gm1026-enclave.py ordinary /tmp/pines-ordinary --nitro-image <nitro-toolchain-tag>
python3 tools/tee-native/reproduce/gm1026-enclave.py email /tmp/pines-email --nitro-image <nitro-toolchain-tag>

# The attestation validator WebAssembly the browser extension and the API load.
tools/tee-native/reproduce/attestation-wasm.sh

# Browser prover, with the awaited-write IO patch and the multi-request session patch. Verifies every package byte.
# Install Rust nightly-2026-05-31 with rust-src and wasm32-unknown-unknown first.
python3 tools/tee-native/reproduce/prover-wasm.py /tmp/pines-prover-wasm
```

`gm1026-enclave.py` checks every source byte against its sealed context and uses `local-image-pair.py` to build twice
with `--no-cache` in a memory- and CPU-bounded BuildKit container. It packages each image with `nitro-cli`, then
compares all three PCRs and executable hashes. The recorded Nitro toolchain digest is in each image's JSON record;
a replacement built with `Dockerfile.nitro-cli` must reproduce PCR1. The EIF's own SHA-256 includes build metadata
outside the PCRs, so compare PCRs and executable hashes. The older `release.json` and `enclave.sh` are historical.

## Release record

| | |
|---|---|
| Source commit | `aab64b4ae7f4ac54286f10dc5011e0096d46a135` (build epoch `1792297388`) |
| Enclave PCR0 | `2ced2fc3326c32d4438e048bc23f537e65cfb4391d7b1bc02a4f9c268ed892d2b4be474af2128277eb54aa8041a81224` |
| Enclave PCR1 | `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493` |
| Enclave PCR2 | `e8330b01d8992ee72bebf6c17e815badcbf2af342d3ae15c1ecd37295506df52c1f53f5f5e2a3baa5d42d6adbdc957aa` |
| Attestation validator | `pines_nitro_validation_bg.wasm` SHA-256 `dad876167a51019dcb81495552a48ca20da285487d3a9c2ead43aff288b224bf` |

Prepared recovery release. Consult live identity discovery and the owner-signed manifest for activation. Ordinary provider proof and Grok email hardware transport passed; actual website acceptance is a separate completion criterion.

## TLSNotary and the vendored crates

TLSNotary is pinned at `v0.1.0-alpha.15` (`47aee45b53e06648c1b2ad3689b367b8c923fdec`) through
`apps/tlsn-verifier/Cargo.lock`, except two crates. `apps/tlsn-verifier/third_party/tlsn` vendors `tlsn-core` and `tlsn`
as alpha.15 plus upstream commits `cb4925e7` ([tlsn#1194](https://github.com/tlsnotary/tlsn/issues/1194), bounded
transcript decoding) and `5f67389d` ([tlsn#1196](https://github.com/tlsnotary/tlsn/pull/1196), bounded commitment
ranges), cherry-picked unchanged. `apps/tlsn-verifier/third_party/sync-tlsn.py --check` rebuilds that tree from
GitHub and fails on any difference; see `apps/tlsn-verifier/third_party/README.md`. The measured verifier
(`examples/tee-hardware.rs`) materializes a transcript only at the application-data lengths it relayed itself
(`src/session_bounds.rs`), never at a length the prover declares.

## What this does not prove

- **AWS is trusted**: its Nitro hardware, its hypervisor and the keys that sign attestations.
- **Availability and metadata.** Pines runs the enclave's host and API. It can stop the service and see when you
  verify, how much is sent and from which address. It cannot read the disclosed response.
- **Proxy mode's assumption.** A TLSNotary Proxy proof assumes the prover cannot control the network path between the
  verifier and the provider. The enclave's provider routes run through a host Pines operates; this matters for whether
  a proof is genuine, not for your privacy.
- **The browser extension.** The prover WebAssembly recipe verifies the exact upstream commit, IO patch,
  downloaded tool hashes and all eight resulting package files. Extension trust/origin inputs belong to
  the selected installation; its package comparison is separate from the enclave PCR comparison.
- **KMS governance.** The measured Sydney key ARN and configuration authority are public reproduction
  inputs. Policy administrators can change key access. PCR equality alone does not prove that the key
  policy restricts decryption, that bootstrap occurred once, or that provider/capacity tests passed.

## Layout

| Path | What |
|---|---|
| `apps/tlsn-verifier` | The measured TLSNotary verifier binary: `examples/tee-hardware.rs`, the two modules it includes and the vendored crates |
| `tools/tee-native` | Attestation, channel, ticket/receipt protocol, the enclave service, the image recipe (`hardware/`), the validator (`attestation-wasm/`) and the reproduction scripts (`reproduce/`) |
| `packages/verification-schemas` | Provider request schemas, selective-disclosure planner and the strict HTTP/JSON evaluator |
| `apps/tlsn-prover` | The extension sources that drive a proof and check the attestation (for review) |
| `contracts/deployments/production.json` | The identity service's current chain deployment, signed into verification tickets; outside the measured image |

## Provenance and licenses

This repository is MIT-licensed ([LICENSE](LICENSE)), except where a file says otherwise. The `apps/tlsn-verifier`
crate was first imported from `BringID/tlsn-extension` at `604694d8da50aab76a4d5d477ad8142cd8de6127`, and the
extension's worker and offscreen lifecycle adapt the same repository; both upstream parts are MIT OR Apache-2.0
([apps/tlsn-verifier/UPSTREAM_LICENSE.md](apps/tlsn-verifier/UPSTREAM_LICENSE.md),
[apps/tlsn-prover/UPSTREAM_LICENSE.md](apps/tlsn-prover/UPSTREAM_LICENSE.md)). The vendored TLSNotary crates keep
upstream's MIT OR Apache-2.0 declaration
([apps/tlsn-verifier/third_party/tlsn/UPSTREAM_LICENSE.md](apps/tlsn-verifier/third_party/tlsn/UPSTREAM_LICENSE.md)).

Security reports: support@pines.family.
