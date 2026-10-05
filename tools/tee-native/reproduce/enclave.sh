#!/bin/bash
# Rebuild the measured enclave image (EIF) from this tree and print its PCR0/PCR1/PCR2.
# Usage: enclave.sh [OUTPUT_DIR]
# Needs Docker with the containerd image store (the default since Docker Engine 29) and network access for the pinned
# base images and the Rust, npm and Amazon Linux packages. Takes about 10-20 minutes and ~10 GB of disk.
set -euo pipefail
native=$(cd "$(dirname "$0")/.." && pwd)
repo=$(cd "$native/../.." && pwd)
out=${1:-$native/reproduce/out/enclave}
record=$native/reproduce/release.json
epoch=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["enclave"]["sourceEpoch"])' "$record")
docker info --format '{{json .DriverStatus}}' | grep -q 'io.containerd.snapshotter' || {
  echo 'This Docker engine uses the classic image store; enable the containerd image store (see README).' >&2; exit 1; }
rm -rf "$out"; mkdir -p "$out"
tag=pines-enclave-reproduce:$(date +%s)

# 1. The Nitro CLI, pinned with its kernel and init blobs.
docker build --platform linux/amd64 --quiet --tag pines-nitro-cli:1.5.0 --file "$native/reproduce/Dockerfile.nitro-cli" "$native/reproduce" >/dev/null

# 2. The image's build context: the runtime files only, with the release's epoch and the API's public ticket key.
mkdir -p "$native/attestation-wasm/pkg"
cp "$native"/attestation-wasm/release/{package.json,pines_nitro_validation.js,pines_nitro_validation_bg.wasm} "$native/attestation-wasm/pkg/"
PINES_SOURCE_EPOCH=$epoch python3 "$native/prepare-image.py" "$out/context" >/dev/null

# 3. The image, from scratch, with every timestamp clamped to the epoch.
docker build --no-cache --progress=plain --platform linux/amd64 --build-arg "SOURCE_DATE_EPOCH=$epoch" \
  --file "$out/context/tools/tee-native/hardware/Dockerfile.preparation" \
  --output type=image,rewrite-timestamp=true,unpack=false --tag "$tag" "$out/context" > "$out/docker-build.log" 2>&1

# 4. The EIF and its measurements.
docker run --rm --network none --mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock \
  --mount "type=bind,src=$out,dst=/out" --entrypoint /bin/bash pines-nitro-cli:1.5.0 -c \
  'nitro-cli build-enclave --docker-uri "$1" --output-file /out/pines-enclave.eif > /out/eif-build.log 2>&1 &&
   nitro-cli describe-eif --eif-path /out/pines-enclave.eif > /out/eif-describe.json; code=$?; chown -R "$2" /out; exit $code' \
  -- "$tag" "$(id -u):$(id -g)"
docker image rm "$tag" >/dev/null 2>&1 || true

python3 - "$out/eif-describe.json" "$record" <<'PY'
import json, sys
described = json.load(open(sys.argv[1])); expected = json.load(open(sys.argv[2]))['enclave']['pcrs']
assert described.get('CheckCRC') is True, 'EIF CRC check failed'
got = [described['Measurements'][f'PCR{i}'] for i in range(3)]
for i in range(3): print(f'PCR{i} {got[i]}  {"MATCH" if got[i] == expected[i] else "DIFFERS"}')
print('MATCH: release.json' if got == expected else 'DIFFERS from release.json')
sys.exit(0 if got == expected else 1)
PY
