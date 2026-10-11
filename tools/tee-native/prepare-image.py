"""Create a bounded, hashed image build context without reading env or state."""
from pathlib import Path
import hashlib, json, shutil, sys, subprocess, os, re

here = Path(__file__).resolve().parent
repo = here.parents[1]
artifact = repo / 'contracts/deployments/production.json'
expected_deployment = 'cac8f477c5ec123a0e3fd188890ed54a1e1b57ebffa56c78587e453b9239002c'
assert hashlib.sha256(artifact.read_bytes()).hexdigest() == expected_deployment, 'RELEASE_ARTIFACT_DRIFT'
context_source = (here / 'hardware/context.mjs').read_text()
assert expected_deployment in context_source, 'MEASURED_CONTEXT_DRIFT'
# Runtime inputs only, selected from tracked source rather than ignored runtime/key directories.
# The verifier binary is the tee-hardware example, the two modules it includes and the vendored
# TLSNotary crates its Cargo [patch] names (their tests excluded); the schema package contributes
# its tracked sources and schemas. Documentation, the standalone server and tests stay out of the
# image, so editing them never changes a measurement. `--list` prints the selection and exits.
def tracked(*roots):
    return [p for p in subprocess.check_output(['git', '-C', str(repo), 'ls-files', '-z', *roots]).decode().split('\0') if p]
paths = [repo / 'apps/tlsn-verifier' / name for name in ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'examples/tee-hardware.rs', 'examples/tee-identity.rs', 'src/transport_policy.rs', 'src/session_bounds.rs', 'src/disclosure_policy.rs']]
paths += [repo / p for p in tracked('apps/tlsn-verifier/third_party/tlsn') if '/examples/' not in p and '/test' not in p]
paths.append(repo / 'packages/verification-schemas/package.json')
paths += [repo / p for p in tracked('packages/verification-schemas/src', 'packages/verification-schemas/schemas') if p.endswith(('.ts', '.json')) and '/test' not in p]
# Explicit active files only: historical experiments, synthetic issuer/fixture,
# tests and writable state do not enter the prepared hardware root filesystem.
for name in ['package.json', 'package-lock.json', 'wire.mjs', 'profile.mjs', 'channel.mjs', 'identity-binding.mjs', 'input-flow-control.mjs', 'protocol.mjs', 'session-policy.mjs', 'capacity-policy.mjs', 'disclosure-policy.mjs', 'runtime-metrics.mjs', 'session-diagnostics.mjs', 'nitro.mjs', 'native.mjs', 'enclave-service.mjs', 'fleet-membership.mjs', 'inventory.mjs']:
    paths.append(here / name)
paths += [here / 'hardware' / name for name in ['entrypoint.mjs','enclave.mjs','context.mjs','clock-guard.mjs','provider-inventory.json','claude-inventory.json','grok-inventory.json','chatgpt-private-inventory.json','claude-org-inventory.json','grok-active-inventory.json','Dockerfile.preparation']]
paths += [here / 'hardware/runtime' / name for name in ['Cargo.toml','Cargo.lock','src/main.rs','src/spki.rs']]
# Measured identity runtime. Test-only JavaScript key-open helpers and fixtures
# are excluded; plaintext key material is held by the native helper.
paths += [here / 'kms' / name for name in ['config.mjs','issuer.mjs','lifecycle.mjs','parent-channel.mjs',
    'recipient.mjs','native-recipient.mjs','identity-adapter.mjs','startup.mjs','deployment.mjs','transport.mjs','vsock-agent.mjs','wrapped-store.mjs']]
paths += [here / 'attestation-wasm/pkg/pines_nitro_validation.js', here / 'attestation-wasm/pkg/pines_nitro_validation_bg.wasm', here / 'attestation-wasm/pkg/package.json']
if sys.argv[1:] == ['--list']:
    # The attestation package is generated from the hash-pinned attestation-wasm/release copy.
    print('\n'.join(sorted(str(p.relative_to(repo)) for p in set(paths))))
    raise SystemExit(0)
destination = Path(sys.argv[1]).resolve()
if destination.exists():
    raise SystemExit('destination must be new')
# The ticket authority's public key is always named explicitly: an image pins exactly one.
if not os.environ.get('PINES_TEE_PUBLIC_KEY'):
    raise SystemExit('PINES_TEE_PUBLIC_KEY must name the authority public key JSON')
public_path = Path(os.environ['PINES_TEE_PUBLIC_KEY'])
public = json.loads(public_path.read_text())
api_key = public['apiKey']
assert len(api_key) == 64 and all(c in '0123456789abcdef' for c in api_key)
# A rebuild elsewhere (for example a public export) names the original source commit's epoch.
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
image_config={'capabilityVersion':2,'profiles':['pines.'+provider+'.tee.native.nitro.v1' for provider in ['chatgpt','claude','grok']],'apiKey':api_key}
# Capacity is selected per boot by the pinned controller key (the capacity selection design). Only its
# validators are sealed; a sealed selection would defeat that, so an authority file naming one is refused.
if 'resourcePolicy' in public:
    raise SystemExit('RESOURCE_POLICY_IS_RUNTIME_SELECTED')
if 'fleetControllerKey' in public:
    controller_key=public['fleetControllerKey']
    assert isinstance(controller_key,str) and len(controller_key)==64 and all(c in '0123456789abcdef' for c in controller_key), 'FLEET_CONTROLLER_PUBLIC_KEY'
    image_config['fleetControllerKey']=controller_key
if 'keyedIdentity' in public:
    # Only a public authority and existing key ARN are measured. Final PCRs
    # are signed after both reproducible builds, avoiding a self-reference.
    # Keep context creation independent of installed npm modules. The measured
    # startup revalidates these same three public fields before use.
    trust=public['keyedIdentity']
    assert set(trust)=={'format','keyArn','configurationAuthority'}, 'KMS_IDENTITY_TRUST'
    assert trust['format']=='pines-sydney-identity-trust-v2', 'KMS_IDENTITY_TRUST'
    existing_key=re.search(r"^export const EXISTING_KEY_ARN='([^']+)';", (here/'kms/config.mjs').read_text(),re.M).group(1)
    assert trust['keyArn']==existing_key, 'EXACT_KMS_KEY_ARN_REQUIRED'
    assert isinstance(trust['configurationAuthority'],str) and re.fullmatch('[a-f0-9]{64}',trust['configurationAuthority']), 'KMS_CONFIGURATION_AUTHORITY'
    image_config['keyedIdentity']=trust
config_path.write_text(json.dumps(image_config,sort_keys=True)+'\n')
os.utime(config_path,(epoch,epoch))
manifest[str(config_path.relative_to(destination))]=hashlib.sha256(config_path.read_bytes()).hexdigest()
(destination / 'context-manifest.json').write_text(json.dumps({'status': 'hardware-unqualified', 'deploymentHash':expected_deployment, 'sourceEpoch':epoch,'sourceCommit':subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD']).decode().strip(),'sourceDirty':bool(subprocess.check_output(['git','-C',str(repo),'status','--porcelain']).strip()),'files': manifest}, indent=2) + '\n')
for directory in sorted((p for p in destination.rglob('*') if p.is_dir()),reverse=True):
    os.chmod(directory,0o755);os.utime(directory,(epoch,epoch))
print(destination)
