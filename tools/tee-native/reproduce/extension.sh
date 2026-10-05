#!/bin/bash
# Rebuild the Pines Verifier extension package (ZIP) from this repository's committed tree in a pinned container, then
# compare its SHA-256 with release.json. With --compare FILE.zip, also compare every file with a ZIP you downloaded.
# Usage: extension.sh [OUTPUT_DIR] [--compare FILE.zip]   (needs Docker and network access to the npm registry)
set -euo pipefail
native=$(cd "$(dirname "$0")/.." && pwd)
repo=$(cd "$native/../.." && pwd)
out=$native/reproduce/out/extension; compare=
while [ $# -gt 0 ]; do case "$1" in --compare) compare=$(realpath "$2"); shift 2 ;; *) out=$1; shift ;; esac; done
node=node:22.23.1-bookworm@sha256:5647be709086c696ff32edaaf1c70cd26d1da6ab2b39c32f3c7b4c4a31957e37
revision=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["extension"]["sourceRevision"])' "$native/reproduce/release.json")
# The release's own first build names the commit it is built from; later rebuilds name that recorded commit.
[ "$revision" = pending ] && revision=$(git -C "$repo" rev-parse HEAD)
rm -rf "$out"; mkdir -p "$out"
# Only committed files enter the build, at the paths the bundler records in its output.
git -C "$repo" archive --format=tar HEAD apps/tlsn-prover tools/tee-native packages/verification-schemas \
  contracts/deployments/production.json > "$out/source.tar"
docker run --rm --platform linux/amd64 --mount "type=bind,src=$out,dst=/out" -e "REVISION=$revision" -e "OWNER=$(id -u):$(id -g)" \
  "$node" bash -euo pipefail -c '
  mkdir /work && cd /work && tar -xf /out/source.tar
  git init -q && git add -A && git -c user.name=build -c user.email=build@localhost commit -qm source
  (cd apps/tlsn-prover && npm ci --ignore-scripts --no-audit --no-fund >/dev/null)
  (cd tools/tee-native && npm ci --ignore-scripts --no-audit --no-fund >/dev/null)
  mkdir -p tools/tee-native/attestation-wasm/pkg && cp tools/tee-native/attestation-wasm/release/{package.json,pines_nitro_validation.js,pines_nitro_validation_bg.wasm} tools/tee-native/attestation-wasm/pkg/
  node -e "const fs=require(\"fs\");fs.writeFileSync(\"/tmp/tee-public.json\",JSON.stringify({apiKey:JSON.parse(fs.readFileSync(\"tools/tee-native/hardware/api-public-key.json\")).apiKey,policy:JSON.parse(fs.readFileSync(\"tools/tee-native/hardware/policy.json\"))}))"
  cd apps/tlsn-prover
  PINES_TEE_PUBLIC_CONFIG=/tmp/tee-public.json PINES_TEE_PUBLIC_RELEASE=1 PINES_SOURCE_REVISION="$REVISION" \
  PINES_TEE_TRANSPORT_ORIGIN=https://id.pines.family PINES_TLSN_VERIFIER_ORIGIN=https://id.pines.family PINES_TLSN_VERIFIER_REVISION=tee-v1-20261004 \
  PROVER_FUNNEL_ORIGINS=https://app.pines.family,https://front.pines.family,https://pines.family,http://localhost:5270 PROVER_FUNNEL_ORIGINS_EXCLUSIVE=1 \
    node build.mjs
  # Sorted paths, fixed time and mode, deflate level 9: the same bytes on every run.
  python3 -c "
import pathlib, zipfile, sys
root = pathlib.Path(\"dist\")
with zipfile.ZipFile(sys.argv[1], \"w\", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for p in sorted(root.rglob(\"*\")):
        if p.is_file():
            info = zipfile.ZipInfo(p.relative_to(root).as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16; info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, p.read_bytes(), compresslevel=9)
" /out/pines-verifier.zip
  chown "$OWNER" /out/pines-verifier.zip'
rm -f "$out/source.tar"
python3 - "$out/pines-verifier.zip" "$native/reproduce/release.json" "$compare" <<'PY'
import hashlib, json, sys, zipfile
built, record, compare = sys.argv[1], json.load(open(sys.argv[2]))['extension'], sys.argv[3]
digest = hashlib.sha256(open(built, 'rb').read()).hexdigest()
print(f'pines-verifier.zip sha256 {digest}  {"MATCH" if digest == record["sha256"] else "DIFFERS"} (release.json)')
ok = digest == record['sha256']
if compare:
    a, b = zipfile.ZipFile(built), zipfile.ZipFile(compare)
    names = sorted(set(a.namelist()) | set(b.namelist()))
    differ = [n for n in names if n not in a.namelist() or n not in b.namelist() or a.read(n) != b.read(n)]
    print(f'{len(names)} files compared with {compare}: ' + ('all identical' if not differ else 'differ: ' + ', '.join(differ)))
    ok = ok and not differ
sys.exit(0 if ok else 1)
PY
