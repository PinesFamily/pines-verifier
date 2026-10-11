# Vendored TLSNotary crates

`tlsn/` holds two crates from [tlsnotary/tlsn](https://github.com/tlsnotary/tlsn) at
`v0.1.0-alpha.15` (`47aee45b53e06648c1b2ad3689b367b8c923fdec`), the release this
verifier and the extension's `tlsn-wasm` already use, plus two upstream commits
cherry-picked without change and the explicit local patch below:

| Upstream commit | Fix |
| --- | --- |
| [`cb4925e7`](https://github.com/tlsnotary/tlsn/commit/cb4925e78befdf6f45f1a8e8589eabc7cab4bcfa) | `PartialTranscript` keeps only authenticated bytes, their ranges and the two totals. Decoding no longer sizes a buffer from a prover-declared total, which let a message of a few bytes abort the verifier process ([tlsn#1194](https://github.com/tlsnotary/tlsn/issues/1194)). |
| [`5f67389d`](https://github.com/tlsnotary/tlsn/commit/5f67389de3f8962227fddffd71d78a852acc9b01) | Prover-supplied commitment ranges are checked against the recorded transcript before they size an allocation ([tlsn#1196](https://github.com/tlsnotary/tlsn/pull/1196)). |

Only `tlsn-core` (`crates/core`, git tree `7f31992c1d544e791dce0cc0b2a4ed6a8df69483`)
and `tlsn` (`crates/tlsn`, git tree `36063b844e6736aa87a154c82c72b44b6a2963f9`) change.
The `[patch]` table in `../Cargo.toml` substitutes them; every other TLSN crate still
resolves to the tag through `Cargo.lock`. `tlsn/Cargo.toml` is generated: it carries
upstream's workspace lint and dependency tables so the crates' `workspace = true` keys
resolve, with the siblings that are not vendored pointed back at the tag. The
serialized transcript keeps its field order, so the alpha.15 browser prover needs no
change.

The local patch `patches/0001-bounded-record-stream-headroom.patch` changes the
session's finite multiplexed-stream allowance from 512 to 2048. A maximum-size,
heavily fragmented response reproduced `TooManyStreams` during tag verification
when the encrypted channel had 125 ms delay in each direction. Twelve generated
full-limit exchanges passed with the patched verifier and the unchanged prover.
The existing connection receive-window, transcript/record limits, outer protocol
byte limit and native process memory ceiling remain in force. This is local
protocol evidence; hardware capacity still requires qualification. Browser wire
compatibility is unchanged, and its pinned WASM package is unchanged.

The tree hashes above describe the upstream backports before this local patch.
Vendoring keeps the exact
source in this tree, and so in the hashed measured-image context
(`tools/tee-native/prepare-image.py`), without publishing a fork.

## Verify or regenerate

```sh
./sync-tlsn.py --check   # rebuild from GitHub in a temporary directory; fail on any difference
./sync-tlsn.py           # rewrite tlsn/ from BASE, PICKS and LOCAL_PATCHES
```

The script fetches the tag and both commits by hash, cherry-picks them, applies
the named local patch and compares every file, including the generated manifest
and `tlsn/UPSTREAM_LICENSE.md`. Make local changes through an explicit patch and
regenerate `tlsn/`. The crates are licensed `MIT OR Apache-2.0`; upstream's
declaration is preserved in `tlsn/UPSTREAM_LICENSE.md`.

The measured context carries `tlsn/` without tracked paths containing `/test` or
`/examples/`. Here that is `crates/core/src/transcript/test.rs`, compiled only under
`cfg(test)`, and `crates/tlsn/tests/`; the release build needs neither. This README
and `sync-tlsn.py` are provenance, not build input, and stay outside the measurement.

## Removal

Once upstream tags a release containing both commits, move the pin to it, delete
`third_party/` and the `[patch]` table, and qualify the new release together with the
matching `tlsn-wasm` as one change.
