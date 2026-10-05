"""Create a bounded, hashed image build context without reading env or state."""
from pathlib import Path
import hashlib, json, shutil, sys, subprocess, os

here = Path(__file__).resolve().parent
repo = here.parents[1]
artifact = repo / 'contracts/deployments/production.json'
expected_deployment = 'cac8f477c5ec123a0e3fd188890ed54a1e1b57ebffa56c78587e453b9239002c'
assert hashlib.sha256(artifact.read_bytes()).hexdigest() == expected_deployment, 'RELEASE_ARTIFACT_DRIFT'
context_source = (here / 'hardware/context.mjs').read_text()
assert expected_deployment in context_source, 'MEASURED_CONTEXT_DRIFT'
destination = Path(sys.argv[1]).resolve()
if destination.exists():
    raise SystemExit('destination must be new')
# Runtime inputs only. The verifier binary is the tee-hardware example plus the one module it includes; the schema
# package contributes its tracked sources and schemas. Documentation and the standalone server stay out of the image.
paths = [repo / 'apps/tlsn-verifier' / name for name in ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'examples/tee-hardware.rs', 'src/transport_policy.rs']]
paths.append(repo / 'packages/verification-schemas/package.json')
tracked = subprocess.check_output(['git', '-C', str(repo), 'ls-files', '-z', 'packages/verification-schemas/src', 'packages/verification-schemas/schemas']).decode().split('\0')
paths += [repo / p for p in tracked if p and p.endswith(('.ts', '.json'))]
# Explicit active files only: historical experiments, synthetic issuer/fixture,
# tests and writable state do not enter the prepared hardware root filesystem.
for name in ['package.json', 'package-lock.json', 'wire.mjs', 'profile.mjs', 'channel.mjs', 'protocol.mjs', 'nitro.mjs', 'native.mjs', 'enclave-service.mjs', 'inventory.mjs']:
    paths.append(here / name)
paths += [here / 'hardware' / name for name in ['entrypoint.mjs','enclave.mjs','context.mjs','clock-guard.mjs','provider-inventory.json','claude-inventory.json','grok-inventory.json','Dockerfile.preparation']]
paths += [here / 'hardware/runtime' / name for name in ['Cargo.toml','Cargo.lock','src/main.rs']]
paths += [here / 'attestation-wasm/pkg/pines_nitro_validation.js', here / 'attestation-wasm/pkg/pines_nitro_validation_bg.wasm', here / 'attestation-wasm/pkg/package.json']
public_path = Path(os.environ.get('PINES_TEE_PUBLIC_KEY', str(here / 'hardware/api-public-key.json')))
public = json.loads(public_path.read_text())
api_key = public['apiKey']
assert len(api_key) == 64 and all(c in '0123456789abcdef' for c in api_key)
# A rebuild names the release's recorded epoch; by default it is the source commit's time.
epoch = int(os.environ.get('PINES_SOURCE_EPOCH') or subprocess.check_output(['git','-C',str(repo),'show','-s','--format=%ct','HEAD']))
manifest = {}
for p in sorted(set(paths)):
    rel = p.relative_to(repo)
    out = destination / rel
    out.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(p, out)
    os.chmod(out, 0o644)
    os.utime(out, (epoch,epoch))
    manifest[str(rel)] = hashlib.sha256(p.read_bytes()).hexdigest()
config_path=destination / 'tools/tee-native/hardware/image-config.json'
config_path.write_text(json.dumps({'capabilityVersion':2,'profiles':['pines.'+provider+'.tee.native.nitro.v1' for provider in ['chatgpt','claude','grok']],'apiKey':api_key},sort_keys=True)+'\n')
os.utime(config_path,(epoch,epoch))
manifest[str(config_path.relative_to(destination))]=hashlib.sha256(config_path.read_bytes()).hexdigest()
(destination / 'context-manifest.json').write_text(json.dumps({'status': 'hardware-unqualified', 'deploymentHash':expected_deployment, 'sourceEpoch':epoch,'sourceCommit':subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD']).decode().strip(),'sourceDirty':bool(subprocess.check_output(['git','-C',str(repo),'status','--porcelain']).strip()),'files': manifest}, indent=2) + '\n')
for directory in sorted((p for p in destination.rglob('*') if p.is_dir()),reverse=True):
    os.chmod(directory,0o755);os.utime(directory,(epoch,epoch))
print(destination)
