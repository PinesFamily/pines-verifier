#!/bin/bash
# Rebuild the AWS Nitro attestation validator (Rust -> WebAssembly) in a pinned container, then compare it with
# attestation-wasm/release/SHA256SUMS. Usage: attestation-wasm.sh [OUTPUT_DIR]   (needs Docker and network access)
set -euo pipefail
native=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$native/reproduce/out/attestation-wasm}
mkdir -p "$out"
docker build --platform linux/amd64 --quiet --tag pines-attestation-wasm-toolchain:1.95.0 \
  --file "$native/reproduce/Dockerfile.attestation-wasm" "$native/reproduce" >/dev/null
docker run --rm --platform linux/amd64 --mount "type=bind,src=$native/attestation-wasm,dst=/src,readonly" \
  --mount "type=bind,src=$out,dst=/out" pines-attestation-wasm-toolchain:1.95.0 bash -euo pipefail -c "
  mkdir /build && cp -r /src /build/attestation-wasm && cd /build/attestation-wasm && rm -rf target pkg
  cargo build --locked --release --target wasm32-unknown-unknown -j 2
  wasm-bindgen target/wasm32-unknown-unknown/release/pines_nitro_validation.wasm --target web --out-dir /out
  printf '{\"type\":\"module\"}\n' > /out/package.json
  chown -R $(id -u):$(id -g) /out"
cd "$out"
sha256sum package.json pines_nitro_validation.js pines_nitro_validation_bg.wasm > SHA256SUMS
cat SHA256SUMS
if diff -q SHA256SUMS "$native/attestation-wasm/release/SHA256SUMS" >/dev/null; then echo 'MATCH: attestation-wasm/release'; else echo 'DIFFERS from attestation-wasm/release'; exit 1; fi
