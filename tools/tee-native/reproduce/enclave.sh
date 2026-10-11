#!/bin/bash
# Rebuild the measured enclave image twice from this tree and compare PCR0/PCR1/PCR2 with release.json.
# Usage: enclave.sh OUTPUT_DIR [--nitro-image IMAGE]   (OUTPUT_DIR must not exist)
# Needs Docker with Buildx, Python 3, git and network access for the pinned base images and the Rust, npm and
# Amazon Linux packages. A Nitro packaging image other than the recorded one must reproduce PCR1 to be equivalent;
# Dockerfile.nitro-cli builds one from pinned Amazon Linux packages.
set -euo pipefail
native=$(cd "$(dirname "$0")/.." && pwd)
out=$(realpath -m "$1"); shift
test ! -e "$out" || { echo "$out exists" >&2; exit 1; }
record=$native/reproduce/release.json
read -r epoch key files_sha < <(python3 -c 'import json,sys; e=json.load(open(sys.argv[1]))["enclave"]; print(e["sourceEpoch"], e["apiPublicKeyFile"], e["contextFilesSha256"])' "$record")
mkdir -p "$out"
# The validator package is generated from its hash-pinned release copy.
(cd "$native/attestation-wasm/release" && sha256sum -c --quiet SHA256SUMS)
mkdir -p "$native/attestation-wasm/pkg"
cp "$native"/attestation-wasm/release/{package.json,pines_nitro_validation.js,pines_nitro_validation_bg.wasm} "$native/attestation-wasm/pkg/"
PINES_SOURCE_EPOCH=$epoch PINES_TEE_PUBLIC_KEY="$native/reproduce/$key" python3 "$native/prepare-image.py" "$out/context" >/dev/null
# The sealed file set must equal the release's: same paths, same bytes. The manifest's commit and dirty flag are
# about this checkout and do not enter the image.
python3 - "$out/context/context-manifest.json" "$files_sha" <<'PY'
import hashlib, json, sys
files = json.load(open(sys.argv[1]))['files']
digest = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
print(f'context files {len(files)} sha256 {digest}  ' + ('MATCH' if digest == sys.argv[2] else 'DIFFERS') + ' (release.json)')
sys.exit(0 if digest == sys.argv[2] else 1)
PY
manifest=$(sha256sum "$out/context/context-manifest.json" | cut -d' ' -f1)
python3 "$native/reproduce/local-image-pair.py" --context "$out/context" --manifest-sha256 "$manifest" \
  --output "$out/pair" --label "reproduce-$(date +%s)" "$@"
python3 - "$out/pair/reproduction-result.json" "$record" <<'PY'
import json, sys
result, expected = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))['enclave']['pcrs']
got = [result['measurements'][f'PCR{i}'] for i in range(3)]
for i in range(3): print(f'PCR{i} {got[i]}  {"MATCH" if got[i] == expected[i] else "DIFFERS"}')
print('MATCH: release.json' if got == expected else 'DIFFERS from release.json')
sys.exit(0 if got == expected else 1)
PY
