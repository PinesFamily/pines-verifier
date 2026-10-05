# Pines Verifier

Source and reproducible builds for the two pieces of [Pines](https://pines.family) that handle a subscription proof:

- **The Chrome extension** (`apps/tlsn-prover`). It captures one fixed request to ChatGPT, Claude or Grok in your own
  signed-in browser and proves it with a native [TLSNotary](https://tlsnotary.org) Proxy-mode proof.
- **The enclave** (`tools/tee-native`, `apps/tlsn-verifier`). The TLSNotary verifier and the schema checks run inside an
  [AWS Nitro Enclave](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html). It is the only place that
  reads your provider's response.

Each piece can be rebuilt from this tree with one command, and the result compared with what Pines runs: the
extension's ZIP by SHA-256, and the enclave image by the PCR0/PCR1/PCR2 measurements that AWS's hardware signs.

## What the extension checks before it shares anything

1. It asks the Pines API for an attempt. The API's ticket and grant are signed with the key in
   `tools/tee-native/hardware/api-public-key.json`.
2. It receives an attestation document from the enclave and checks it in the browser
   (`tools/tee-native/nitro.mjs`, `protocol.mjs`):
   - the COSE signature and certificate chain up to the AWS Nitro Enclaves root, using Evervault's
     `attestation-doc-validation`, compiled to `nitro-validation.wasm`;
   - that it was made in the last 60 seconds for this attempt (the nonce is a hash of the ticket, which carries the
     extension's fresh key);
   - non-zero measurements, so not a debug enclave;
   - PCR0, PCR1 and PCR2 exactly equal to `tools/tee-native/hardware/policy.json`, which is compiled into the package;
   - that it vouches for the channel key and for the key that will sign the result.
3. Only then does it open an HPKE channel to the enclave's key. The TLSNotary session runs through that channel, with
   the enclave as the Proxy-mode verifier. The Pines API and the host only relay ciphertext.
4. Login tokens and cookies are never revealed: they stay inside the provider's TLS session, and TLSNotary's native
   selective disclosure keeps them hidden when the transcript is opened. The rest of the request and the response are
   revealed to the enclave only. The schemas in `packages/verification-schemas` and `tools/tee-native/profile.mjs` list
   what each provider's proof judges and hides.
5. The enclave signs a short result: the plan, a one-way hash of the account id, your wallet, the attempt, its own
   measurement and byte counts. The extension checks that result against what it computed itself.

The page that calls the extension cannot change any of this: the policy, the transport origin
(`https://id.pines.family`) and the allowed page origins are compiled in. The manifest's content security policy lets
the extension connect to that origin only. It has no content scripts and loads no remote code.

## Reproduce

Requirements: Linux x86_64 (or Docker Desktop), Docker with the
[containerd image store](https://docs.docker.com/engine/storage/containerd/) (the default since Docker Engine 29) and
Buildx, Python 3, git, network access. Every toolchain runs in a container pinned by digest.

```sh
# The enclave image: about 15 minutes. Prints PCR0/PCR1/PCR2 and compares them with release.json.
tools/tee-native/reproduce/enclave.sh

# The extension package: a few minutes. Compares the ZIP's SHA-256 with release.json; with --compare it also compares
# every file with a ZIP you downloaded from the site.
tools/tee-native/reproduce/extension.sh --compare ~/Downloads/tee-package.zip

# The attestation validator WebAssembly that both of them load.
tools/tee-native/reproduce/attestation-wasm.sh
```

`tools/tee-native/reproduce/release.json` records the expected values; CI rebuilds the extension and the validator on
every push. The EIF's SHA-256 is not reproducible: Nitro writes build metadata into the file that PCRs do not cover.
Compare PCRs, which is also what an attestation reports.

## Release

| | |
|---|---|
| Extension | Pines Verifier **1.2.2**, id `lanmbpkmblcijblbllbikenpnceidmpj`, ZIP SHA-256 `87c4599cf98942b39ca8e75d9ffc6f1c6a468e36094a2caffd9c5b2b98898f9d` |
| Enclave PCR0 | `ef13f7a593fbf5881087f5e96c9dee75597b9780c0cfe953638d79d3a226ceadfbbe0390098a5e1a2d9306c8f625f30c` |
| Enclave PCR1 | `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493` |
| Enclave PCR2 | `4c39fefdd473226957d2ea4e688dce321eb9b5930af28008a4b34cc61e1c1846a565458ff2afa2f43a0f4220e37c9b6a` |
| Attestation validator | `pines_nitro_validation_bg.wasm` SHA-256 `132fd8b3d6178f6bcb28291501f733e518fa644afc2a52d59003ea415494c19f` |

**Release candidate.** Hardware qualification and deployment are pending. Until this release is deployed, the live service runs the previous one (extension 1.2.1, enclave PCR0 `f866e1cf…`), which was built from source that is not published.

To check a live session yourself, open the developer tools of the extension's offscreen page from
`chrome://extensions` during a verification. The attestation arrives in the response to `/tee/admission` as the hex
string `offer.evidence.cose`; any Nitro attestation verifier can check it against
[AWS's root certificate](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html), and its PCRs must equal
the ones above.

## What this does not prove

- **AWS is trusted**: its Nitro hardware, its hypervisor and the keys that sign attestations.
- **Availability and metadata.** Pines runs the enclave's host and API. It can stop the service and see when you
  verify, how much is sent and from which address. It cannot read the disclosed response.
- **Proxy mode's assumption.** A TLSNotary Proxy proof assumes the prover cannot control the network path between the
  verifier and the provider. The enclave's provider routes run through a host Pines operates; this matters for whether
  a proof is genuine, not for your privacy.
- **Anyone other than you.** The attestation is checked off-chain, by the extension and the API. On chain, a claim is
  checked against Pines' attestor signature, so the enclave does not prove to a third party that a given claim followed
  a verification.

## Layout

| Path | What |
|---|---|
| `apps/tlsn-prover` | The extension: `build.mjs`, `src/`, the public notes shipped in the package (`package/`) |
| `apps/tlsn-verifier` | The measured TLSNotary verifier binary: `examples/tee-hardware.rs` and the module it includes |
| `tools/tee-native` | Attestation, channel, ticket/receipt protocol, the enclave service, the image recipe (`hardware/`), the validator (`attestation-wasm/`) and the reproduction scripts (`reproduce/`) |
| `packages/verification-schemas` | Provider request schemas, selective-disclosure planner and the strict HTTP/JSON evaluator |
| `contracts/deployments/production.json` | The chain deployment the measured context is bound to (checked by hash) |

## Provenance and licenses

This repository is MIT-licensed ([LICENSE](LICENSE)), except where a file says otherwise. The extension's worker and
offscreen lifecycle adapt `BringID/tlsn-extension` at `604694d8da50aab76a4d5d477ad8142cd8de6127`, and the
`apps/tlsn-verifier` crate was first imported from that repository's verifier server; both upstream parts are MIT OR
Apache-2.0 ([apps/tlsn-prover/UPSTREAM_LICENSE.md](apps/tlsn-prover/UPSTREAM_LICENSE.md),
[apps/tlsn-verifier/UPSTREAM_LICENSE.md](apps/tlsn-verifier/UPSTREAM_LICENSE.md)). The measured verifier itself,
`examples/tee-hardware.rs` and the egress and stream bounds in `src/transport_policy.rs`, is Pines code. TLSNotary
(alpha.15) is a pinned dependency, unmodified: `apps/tlsn-verifier/Cargo.lock` and the npm package
`tlsn-wasm@0.1.0-alpha.15`. Third-party
assets inside the extension are listed in [apps/tlsn-prover/package/PROVENANCE.md](apps/tlsn-prover/package/PROVENANCE.md).

Security reports: support@pines.family.
