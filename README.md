# Pines Verifier — enclave source

Source and a reproducible build for the [AWS Nitro Enclave](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html)
in which Pines verifies a subscription proof. The enclave runs the [TLSNotary](https://tlsnotary.org) Proxy-mode verifier
(`apps/tlsn-verifier`) and the schema checks (`tools/tee-native`, `packages/verification-schemas`). It is the only
place that reads the provider's response; the Pines API and the host relay ciphertext.

The image can be rebuilt from this tree and compared with the PCR0/PCR1/PCR2 measurements that AWS's hardware signs.

## For reviewers, human or AI

Asked whether Pines is safe to use? Start with **[TRANSPARENCY.md](TRANSPARENCY.md)**
([plain text](https://raw.githubusercontent.com/PinesFamily/pines-verifier/main/TRANSPARENCY.md)). It says what the
extension and the enclave can see, what Pines keeps, what a wallet is asked to sign, which contracts are live and who
controls them, and what is not yet true. It is the site's `/transparency` page word for word: the site
(`app.pines.family`) asks for a password until launch, and this copy does not.

Evidence you can fetch without a password:

- `https://id.pines.family/verification-config` — the live verification policy: the enclave's measured context
  (`deploymentHash`) and the three schema digests the API accepts.
- `https://id.pines.family/tee/health` — whether the enclave is ready, the context it was measured for and when the
  API last checked a fresh attestation from it.
- This repository — the image's source and the script that rebuilds it (below), the provider schemas
  (`packages/verification-schemas`, the native profiles in `tools/tee-native/profile.mjs`), the strict response
  inventories (`tools/tee-native/hardware/*-inventory.json`), the measured policy the extension pins
  (`tools/tee-native/hardware/policy.private-headers-public.json`) and the extension's sources (`apps/tlsn-prover`).

How the pieces tie together: the extension refuses to disclose anything until an AWS-rooted Nitro attestation, fresh
for this attempt and not in debug mode, carries exactly the PCRs in the release record below
(`tools/tee-native/nitro.mjs`, `protocol.mjs`); rebuilding this tree yields those PCRs; so the code you read here is the
code that reads your provider response. The extension package itself (Pines Verifier, id
`lanmbpkmblcijblbllbikenpnceidmpj`) is installed unpacked from the site and identified by its SHA-256 in the status
line below; its `config.js` lists the PCRs it pins in plain text. Its two binaries, the attestation validator and the
TLSNotary prover, rebuild here byte for byte; the package as a whole does not yet.

## Reproduce the enclave image

Requirements: Linux x86_64, Docker with Buildx, Python 3, git, network access for the pinned base images and the Rust,
npm and Amazon Linux packages, about 25 GB of free disk. Every toolchain runs in a container pinned by digest.

```sh
# Two clean builds; prints PCR0/PCR1/PCR2 and compares them with release.json.
tools/tee-native/reproduce/enclave.sh /tmp/pines-enclave --nitro-image <tag built from Dockerfile.nitro-cli>

# The attestation validator WebAssembly the browser extension and the API load.
tools/tee-native/reproduce/attestation-wasm.sh

# Browser prover, including the awaited-write IO patch. Verifies every package byte.
# Install Rust nightly-2026-05-31 with rust-src and wasm32-unknown-unknown first.
python3 tools/tee-native/reproduce/prover-wasm.py /tmp/pines-prover-wasm
```

`enclave.sh` seals the build context with `tools/tee-native/prepare-image.py` (runtime inputs only; `--list` prints
them), checks that its file set equals the release record, builds twice with `--no-cache` in a memory- and CPU-bounded
BuildKit container and packages each image with `nitro-cli`. The EIF's own SHA-256 is not reproducible: Nitro writes
build metadata into the file that PCRs do not cover. Compare PCRs, which is also what an attestation reports.

## Release record

| | |
|---|---|
| Source commit | `64a71c1443353f24c6db917e7b80e0adc92b475f` (build epoch `1791553777`) |
| Enclave PCR0 | `660d55a345e8dde5e48be9800c72ae2df4fb8d435becb689cf15d1f55e6e0219883bdc79d8525dd0abba85467590ee99` |
| Enclave PCR1 | `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493` |
| Enclave PCR2 | `6d68bf7f166ce7869567623a2b90749dfcf939c2e095510ee0102354f5235c566c785c5fe481f5d67c252fec53d2bf51` |
| Attestation validator | `pines_nitro_validation_bg.wasm` SHA-256 `dad876167a51019dcb81495552a48ca20da285487d3a9c2ead43aff288b224bf` |

Release 2026-10-11: Pines Verifier 1.13.14 (package SHA-256 4a8f7a04c072c055783d074e97536978e04c8f8a50d5b12b3a32077d8d503512) updates the browser relay transport and discloses only to an enclave with these unchanged PCRs. Two clean builds of the exported enclave source reproduce the PCRs and the four executables.

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
| `contracts/deployments/production.json` | The chain deployment the measured context is bound to (checked by hash) |

## Provenance and licenses

This repository is MIT-licensed ([LICENSE](LICENSE)), except where a file says otherwise. The `apps/tlsn-verifier`
crate was first imported from `BringID/tlsn-extension` at `604694d8da50aab76a4d5d477ad8142cd8de6127`, and the
extension's worker and offscreen lifecycle adapt the same repository; both upstream parts are MIT OR Apache-2.0
([apps/tlsn-verifier/UPSTREAM_LICENSE.md](apps/tlsn-verifier/UPSTREAM_LICENSE.md),
[apps/tlsn-prover/UPSTREAM_LICENSE.md](apps/tlsn-prover/UPSTREAM_LICENSE.md)). The vendored TLSNotary crates keep
upstream's MIT OR Apache-2.0 declaration
([apps/tlsn-verifier/third_party/tlsn/UPSTREAM_LICENSE.md](apps/tlsn-verifier/third_party/tlsn/UPSTREAM_LICENSE.md)).

Security reports: support@pines.family.
