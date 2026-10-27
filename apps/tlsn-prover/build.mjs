import {cp, mkdir, readFile, rm, writeFile} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {dirname, join, resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {build} from 'esbuild';
import {funnelOrigins, matchPatternsFor} from './src/funnel-origins.mjs';
import {copyPinnedWasm} from './wasm-io-package.mjs';
import {regionalConnectSources} from './regional-entry-build.mjs';
import {GENERATIONS, LIVE_GENERATION, teeCapabilityPin, teePolicyFile} from './tee-policy-file.mjs';
import {assistanceBuild} from './grok-assistance-build.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../..');
const out = join(here, 'dist');
const env = process.env;
const teePath = env.PINES_TEE_PUBLIC_CONFIG;
const publicRelease = env.PINES_TEE_PUBLIC_RELEASE === '1';
const localQualification = env.PINES_TEE_LOCAL_QUALIFICATION === '1';
if (env.PINES_TEE_LOCAL_QUALIFICATION !== undefined && !localQualification) throw Error('TEE_LOCAL_QUALIFICATION');
// The public private-headers package, built directly from clean committed source: the
// qualified API policy, the public transport and the exact page origins and version pinned in
// config/tee-public-release-private-headers.json. No qualification receiver, fixture or regional entry.
const publicPrivateHeaders = env.PINES_TEE_PUBLIC_RELEASE === 'private-headers';
if (env.PINES_TEE_PUBLIC_RELEASE !== undefined && !publicRelease && !publicPrivateHeaders) throw Error('TEE_PUBLIC_RELEASE');
const privateHeadersRelease = publicPrivateHeaders ? JSON.parse(await readFile(join(here, 'config/tee-public-release-private-headers.json'), 'utf8')) : null;
const teePublic = teePath ? JSON.parse(await readFile(teePath, 'utf8')) : null;
const teeFixture = env.PINES_TEE_FIXTURE_CONFIG ? JSON.parse(await readFile(env.PINES_TEE_FIXTURE_CONFIG, 'utf8')) : null;
const qualification = env.PINES_TEE_QUALIFICATION_CONFIG
  ? await (await import('../../tools/tee-native/hardware/qualification-build.mjs')).qualificationBuild(env.PINES_TEE_QUALIFICATION_CONFIG) : null;
if (qualification && (publicRelease || publicPrivateHeaders || !teePublic || Boolean(teeFixture) !== (qualification.variant === 'fixture'))) throw Error('QUALIFICATION_BUILD_REFUSED');
if (env.PINES_TEE_REGIONAL_ENTRY_SUFFIX !== undefined && (!teePublic || publicRelease || publicPrivateHeaders || qualification || teeFixture)) throw Error('TEE_REGIONAL_ENTRY_SCOPE');
if (teeFixture && (!teePublic || teeFixture.syntheticOnly !== true || teeFixture.hardware !== true || !Array.isArray(teeFixture.root))) throw Error('TEE_FIXTURE_BUILD_REFUSED');
if (env.PINES_TLSN_PRIVATE_FIXTURE && env.PINES_TLSN_PRIVATE_FIXTURE !== '1') throw Error('PINES_TLSN_PRIVATE_FIXTURE must be 1 or unset');
const privateFixture = env.PINES_TLSN_PRIVATE_FIXTURE === '1';
if (env.PINES_TLSN_PROVIDER && env.PINES_TLSN_PROVIDER !== 'chatgpt') throw Error('Only the ChatGPT provider pilot is supported');
const chatgpt = teePublic !== null || env.PINES_TLSN_PROVIDER === 'chatgpt';
if (env.PINES_TLSN_CHATGPT_CLAIMS && env.PINES_TLSN_CHATGPT_CLAIMS !== '1') throw Error('PINES_TLSN_CHATGPT_CLAIMS must be 1 or unset');
const chatgptClaims = env.PINES_TLSN_CHATGPT_CLAIMS === '1';
if (env.PINES_TLSN_CHATGPT_IDENTITY && env.PINES_TLSN_CHATGPT_IDENTITY !== '1') throw Error('PINES_TLSN_CHATGPT_IDENTITY must be 1 or unset');
const chatgptIdentity = teePublic !== null || env.PINES_TLSN_CHATGPT_IDENTITY === '1';
if (chatgptIdentity && (!chatgpt || chatgptClaims)) throw Error('Identity verification requires ChatGPT provider mode without the legacy claims flag');
if (chatgptClaims && !chatgpt) throw Error('ChatGPT claims require PINES_TLSN_PROVIDER=chatgpt');
if (chatgpt && privateFixture) throw Error('Select one pilot schema');
if (env.PINES_TLSN_CLAUDE && env.PINES_TLSN_CLAUDE !== '1') throw Error('PINES_TLSN_CLAUDE must be 1 or unset');
const claude = env.PINES_TLSN_CLAUDE === '1';
// One installed extension ID serves every provider, so Claude is added to the
// identity build rather than built as a separate extension.
if (claude && !chatgptIdentity) throw Error('Claude verification requires PINES_TLSN_PROVIDER=chatgpt and PINES_TLSN_CHATGPT_IDENTITY=1');
if (env.PINES_TLSN_GROK && env.PINES_TLSN_GROK !== '1') throw Error('PINES_TLSN_GROK must be 1 or unset');
const grok = env.PINES_TLSN_GROK === '1';
if (grok && !chatgptIdentity) throw Error('Grok verification requires PINES_TLSN_PROVIDER=chatgpt and PINES_TLSN_CHATGPT_IDENTITY=1');
if (env.PINES_TLSN_TEST_BUILD && env.PINES_TLSN_TEST_BUILD !== '1') throw Error('PINES_TLSN_TEST_BUILD must be 1 or unset');
// Loopback verifier origins and benchmark verifiers are an explicit test-build choice.
const testBuild = env.PINES_TLSN_TEST_BUILD === '1';
// Regional direct entry is opt-in and outside every current public or
// qualification package scope; those builds stay byte-identical and keep the central relay only.
const regionalSuffix = env.PINES_TEE_REGIONAL_ENTRY_SUFFIX;
// The disclosure class this package is built for. Default-off: the qualified full-response
// class, byte-identical to every earlier build. The private-headers class is an explicit
// choice for a TEE build only; a package never carries both, and nothing falls back.
const disclosurePolicyId = env.PINES_TEE_DISCLOSURE_POLICY ?? 'full-response-v1';
// The trust manifest: every TEE package requires the identity's owner-signed admitted set in place of the policy
// set bundled below (src/trust-manifest.mjs). PINES_TEE_MANIFEST=0 keeps the bundled policy authoritative for the
// qualification, fixture and local-qualification harnesses only; a public package never opts out.
if (env.PINES_TEE_MANIFEST !== undefined && !['0', '1'].includes(env.PINES_TEE_MANIFEST)) throw Error('TEE_MANIFEST');
const manifestRequired = env.PINES_TEE_MANIFEST !== '0';
// PINES_TEE_MANIFEST_TEST_KEYS=<fixture>: a TEST build verifies manifests against that test pair's public pins instead of
// the owner's (a local stack signed with the committed pair). Never a public package; the pins stay compiled in untouched.
const manifestTestKeysFile = env.PINES_TEE_MANIFEST_TEST_KEYS;
if (manifestTestKeysFile !== undefined && (!testBuild || publicRelease || publicPrivateHeaders)) throw Error('TEE_MANIFEST_TEST_KEYS_SCOPE');
// The provider generation this package admits (tee-policy-file.mjs): the live one unless PINES_TEE_PROVIDER_GENERATION
// names the sybil-facts one, whose policy set, capability pin and manifest the identity and this package select together.
const generation = env.PINES_TEE_PROVIDER_GENERATION ?? LIVE_GENERATION;
if (!GENERATIONS.includes(generation)) throw Error('TEE_PROVIDER_GENERATION');
if (generation !== LIVE_GENERATION && (!teePublic || !['facts-complete-v1', 'grok-clearance-private-v1', 'grok-email-complete-v1'].includes(disclosurePolicyId) || publicRelease || qualification || teeFixture)) throw Error('TEE_PROVIDER_GENERATION_SCOPE');
if (!['full-response-v1', 'private-headers-gzip-v1', 'facts-complete-v1', 'grok-clearance-private-v1', 'grok-email-complete-v1'].includes(disclosurePolicyId)) throw Error('TEE_DISCLOSURE_POLICY');
if (disclosurePolicyId !== 'full-response-v1' && !teePublic) throw Error('TEE_DISCLOSURE_POLICY_SCOPE');
if (publicPrivateHeaders && (!teePublic || teeFixture || disclosurePolicyId !== privateHeadersRelease.disclosurePolicy)) throw Error('TEE_PUBLIC_RELEASE_SCOPE');
function origin(value) {
  const url = new URL(value);
  if (url.origin !== value || url.username || url.password || (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname)))) throw Error('An exact HTTPS or loopback HTTP origin is required');
  return value;
}
function verifier(value) {
  origin(value);
  if (!testBuild && !teePublic && (new URL(value).protocol !== 'https:' || new URL(value).port)) throw Error(`Verifier origin ${value} needs PINES_TLSN_TEST_BUILD=1`);
  return value;
}
const identity = JSON.parse(await readFile(join(here, 'config/identity.json')));
const sourceRevision = execFileSync('git', ['rev-parse', 'HEAD'], {cwd: root, encoding: 'utf8'}).trim();
const sourceDirty = Boolean(execFileSync('git', ['status', '--porcelain'], {cwd: root, encoding: 'utf8'}).trim());
const origins = funnelOrigins(env).map(origin);
if (teePublic && (!env.PROVER_FUNNEL_ORIGINS || env.PROVER_FUNNEL_ORIGINS_EXCLUSIVE !== '1' || claude || grok || privateFixture || chatgptClaims)) throw Error('TEE_EXACT_ORIGINS_AND_PROVIDER_REQUIRED');
// The pinned origin/revision serve pre-assignment APIs (and pages); assigned attempts name their own verifier, checked
// against `verifierPolicy` and the verifier's /info. See policy.js verifierOriginAllowed.
const verifierOrigin = verifier(env.PINES_TLSN_VERIFIER_ORIGIN ?? 'https://v1.verifier.pines.family');
const legacyVerifiers = [...new Set([verifierOrigin, ...(env.PINES_TLSN_LEGACY_VERIFIER_ORIGINS ?? '').split(',').filter(Boolean).map(verifier)])];
const testVerifiers = (env.PINES_TLSN_TEST_VERIFIER_ORIGINS ?? '').split(',').filter(Boolean).map(value => { if (!testBuild) throw Error('PINES_TLSN_TEST_VERIFIER_ORIGINS needs PINES_TLSN_TEST_BUILD=1'); return origin(value); });
const verifierPolicy = {host: '*.verifier.pines.family', legacy: legacyVerifiers, test: testVerifiers};
const verifierRevision = env.PINES_TLSN_VERIFIER_REVISION ?? sourceRevision;
const application = env.PINES_TLSN_APPLICATION ?? 'pines';
// Base (8453) since the Base migration. A TEE build must still match the measured image's CONTEXT.chain
// (TEE_CONTEXT_DRIFT below), which is 8453 since the v3 re-cut.
const chainId = Number(env.PINES_TLSN_CHAIN_ID ?? 8453);
if (!/^[a-zA-Z0-9._-]{1,80}$/.test(verifierRevision) || !/^[a-zA-Z0-9._-]{1,64}$/.test(application) || !Number.isSafeInteger(chainId) || chainId <= 0) throw Error('Invalid verifier audience or revision');
const migrationQualification = env.PINES_TEE_MIGRATION_QUALIFICATION === undefined ? null
  : (await import('../../tools/tee-native/hardware/migration-qualification.mjs')).migrationQualificationBuild({env,publicConfig:teePublic,origins,sourceDirty});
const recoveryQualification = env.PINES_TEE_RECOVERY_QUALIFICATION === undefined ? null
  : (await import('../../tools/tee-native/hardware/recovery-qualification.mjs')).recoveryQualificationBuild({env,publicConfig:teePublic,origins,sourceDirty});
let tee;
if (teePublic) {
  const {providersFor, hardwareCapability} = await import('../../tools/tee-native/profile.mjs');
  const {policyForSchema} = await import('../../tools/tee-native/policy.mjs');
  const {CONTEXT} = await import('../../tools/tee-native/hardware/context.mjs');
  const policySet = recoveryQualification ? recoveryQualification.policy : migrationQualification ? migrationQualification.policy : qualification ? qualification.policy : teeFixture ? teePublic.policy
    : JSON.parse(await readFile(join(root, publicPrivateHeaders ? privateHeadersRelease.policyFile : teePolicyFile(disclosurePolicyId, generation)), 'utf8'));
  if (teeFixture && (!teeFixture.origin || origins.length !== 1 || origins[0] !== teeFixture.origin || !['http://localhost:5262'].includes(teeFixture.origin))) throw Error('TEE_FIXTURE_ORIGIN_REFUSED');
  if (!/^[a-f0-9]{64}$/.test(teePublic.apiKey) || JSON.stringify(teePublic.policy) !== JSON.stringify(policySet)) throw Error('TEE_TRUST_POLICY_UNQUALIFIED');
  if (qualification && qualification.disclosurePolicy !== disclosurePolicyId) throw Error('QUALIFICATION_DISCLOSURE_POLICY');
  const providers = await Promise.all(providersFor(disclosurePolicyId, generation).map(async entry => {
    const policy = await policyForSchema(policySet, entry.reference, disclosurePolicyId);
    if (policy?.admissionEnabled && (policy.identity?.generation!=='v2' || !entry.inventory.qualified || policy.syntheticOnly || !policy.providerQualified || !policy.clockQualified || !policy.lifecycleQualified
      || policy.debugAllowed !== false || policy.simulationAllowed !== false || !Array.isArray(policy.pcrTuples) || policy.pcrTuples.length !== 1
      || policy.pcrTuples[0].length !== 3 || !policy.pcrTuples[0].every(pcr => /^[a-f0-9]{96}$/.test(pcr)))) throw Error('TEE_HARDWARE_QUALIFICATION_REQUIRED');
    return {schema: entry.schema, reference: entry.reference, profile: entry.profile, publicPlanValues: entry.publicPlanValues, policy};
  }));
  const apiOrigin = origin(env.PINES_TEE_TRANSPORT_ORIGIN ?? 'http://localhost:8971');
  if (qualification) {
    if (origins.length !== 1) throw Error('QUALIFICATION_BUILD_SCOPE');
    (await import('../../tools/tee-native/hardware/qualification-build.mjs')).qualificationBuildScope(qualification,
      {publicRelease,fixture:Boolean(teeFixture),apiKey:teePublic.apiKey,origin:origins[0],transport:apiOrigin});
  }
  if(publicRelease && (teeFixture || disclosurePolicyId!=='full-response-v1' || apiOrigin!=='https://id.pines.family'
    || JSON.stringify(origins)!==JSON.stringify(['https://app.pines.family','https://front.pines.family','https://pines.family','http://localhost:5270']))) throw Error('TEE_PUBLIC_RELEASE_SCOPE');
  if (publicPrivateHeaders && (sourceDirty || apiOrigin !== privateHeadersRelease.apiOrigin
    || JSON.stringify(origins) !== JSON.stringify(privateHeadersRelease.pageOrigins))) throw Error('TEE_PUBLIC_RELEASE_SCOPE');
  // A public package admits every provider its policy names, or it is not released.
  if (publicPrivateHeaders && !providers.every(entry => entry.policy?.admissionEnabled)) throw Error('TEE_PUBLIC_RELEASE_UNQUALIFIED');
  if (verifierOrigin !== apiOrigin || verifierRevision !== CONTEXT.revision || application !== CONTEXT.application || chainId !== CONTEXT.chain) throw Error('TEE_CONTEXT_DRIFT');
  if (!manifestRequired && !(qualification || migrationQualification || recoveryQualification || teeFixture || localQualification)) throw Error('TEE_MANIFEST_SCOPE');
  // A public package pins the owner keys it ships with; the committed test pair signs for anyone who holds the repository.
  const {OWNER_KEYS_PROVENANCE} = await import('../../packages/verification-schemas/src/sybil/owner-keys.ts');
  if ((publicRelease || publicPrivateHeaders) && OWNER_KEYS_PROVENANCE !== 'production') throw Error('OWNER_KEYS_TEST_PROVENANCE');
  const entry = regionalSuffix === undefined ? undefined : await import('../../tools/tee-native/fleet-entry.mjs');
  tee = {api: apiOrigin + '/tee', relay: apiOrigin.replace(/^http/, 'ws') + '/channel', apiKey: teePublic.apiKey, policySet, providers, disclosurePolicy: disclosurePolicyId,
    // `generation` is written only for the other generation, so a live package's config.js is byte-identical to one built before the option.
    capability: hardwareCapability(disclosurePolicyId, generation), ...(generation === LIVE_GENERATION ? {} : {generation}),
    manifest: {required: manifestRequired, ...(manifestTestKeysFile === undefined ? {} : {testKeys: (await import('../../packages/verification-schemas/src/sybil/owner-keys.ts')).testOwnerKeysFrom(JSON.parse(await readFile(manifestTestKeysFile, 'utf8')))})}, ...(teeFixture ? {fixture: teeFixture} : {}),
    ...(entry ? {regionalEntry: {version: 1, protocol: entry.ENTRY_PROTOCOL, suffix: entry.validateEntrySuffix(regionalSuffix)}} : {})};
}
// Each class and generation has its own pinned capability file; the full-response pin is the unchanged one.
const capabilityPin = teeCapabilityPin(disclosurePolicyId, generation);
if (tee && JSON.stringify(tee.capability) !== JSON.stringify(JSON.parse(await readFile(join(here, capabilityPin), 'utf8')))) throw Error('TEE_PUBLIC_PIN_DRIFT');
if (localQualification && (sourceDirty || publicRelease || publicPrivateHeaders || qualification || teeFixture || regionalSuffix !== undefined || !tee
  || disclosurePolicyId !== 'private-headers-gzip-v1' || tee.api !== 'https://identity-qualification.up.railway.app/tee'
  || JSON.stringify(origins) !== JSON.stringify(['http://localhost:5270']))) throw Error('TEE_LOCAL_QUALIFICATION_SCOPE');
const config = {protocol: 'pines-tlsn-bridge-v1', wasmVersion: '0.1.0-alpha.15', origins, verifierOrigin, verifierRevision, verifierPolicy, routing: tee ? ['pinned'] : ['pinned', 'assigned'], testBuild, application, chainId, captureProvider: chatgpt || privateFixture,
  ...(qualification?.mode==='prebuild'
    ? {qualificationResponseMetadata:{...qualification.responseMetadata,sourceRevision}} : {}),
  ...(tee ? {tee} : {}), schemas: tee ? tee.providers.filter(entry => entry.policy?.admissionEnabled).map(entry => entry.reference) : chatgpt ? [{schemaId: 'pines.chatgpt.plan', version: chatgptIdentity ? 3 : chatgptClaims ? 2 : 1}, ...(claude ? [{schemaId: 'pines.claude.plan', version: 1}] : []),
    ...(grok ? [{schemaId: 'pines.grok.plan', version: 1}] : [])]
    : [{schemaId: privateFixture ? 'pines.fixture.httpbingo-private' : 'pines.fixture.httpbingo', version: 1}], chatgptClaims, chatgptIdentity, extensionId: identity.id};
const assistance = await assistanceBuild({file: env.PINES_GROK_ASSISTANCE_CONFIG, tee, root,
  publicRelease: publicRelease || publicPrivateHeaders, qualification: qualification || migrationQualification || teeFixture || localQualification,
  recoveryQualification});
if (assistance) config.grokAssistance = assistance;
if(config.qualificationResponseMetadata)(await import('./src/replay-metadata.mjs')).metadataConfiguration(config);
await rm(out, {recursive: true, force: true}); await mkdir(out);
await cp(join(here, 'src'), out, {recursive: true});
// Shared wire-policy code must be inside the installed package; raw source
// imports cannot escape the extension root after Chrome installs the build.
await build({entryPoints: [join(here, 'src/session-timing.js')], bundle: true, format: 'esm', platform: 'browser', target: 'chrome116', outfile: join(out, 'session-timing.js'), logLevel: 'warning'});
await build({entryPoints: [join(here, 'src/region-preference.mjs')], bundle: true, format: 'esm', platform: 'browser', target: 'chrome116', outfile: join(out, 'region-preference.mjs'), logLevel: 'warning'});
await build({entryPoints: [join(here, 'src/grok-assistance.mjs')], bundle: true, format: 'esm', platform: 'browser', target: 'chrome141', outfile: join(out, 'grok-assistance.mjs'), logLevel: 'warning'});
if (tee) {
  await build({entryPoints: [join(here, 'src/tee-worker.js')], bundle: true, format: 'esm', platform: 'browser', target: 'chrome141', external: ['./config.js', './wasm/tlsn_wasm.js'], outfile: join(out, 'tee-worker.js'), logLevel: 'warning'});
  await cp(join(root, 'tools/tee-native/attestation-wasm/pkg/pines_nitro_validation_bg.wasm'), join(out, 'nitro-validation.wasm'));
} else await rm(join(out, 'tee-worker.js'));
await build({entryPoints: [join(here, 'src/provider-capture.js')], bundle: true, format: 'esm', platform: 'browser', target: 'chrome116', outfile: join(out, 'provider-capture.js'), logLevel: 'warning'});
// The panel's loading orb with the thinking-orbs engine (MIT), its notice on top.
const orbLicense = (await readFile(join(dirname(fileURLToPath(import.meta.resolve('thinking-orbs/package.json'))), 'LICENSE'), 'utf8')).trim();
await build({entryPoints: [join(here, 'src/orb.js')], bundle: true, format: 'esm', platform: 'browser', target: 'chrome116', outfile: join(out, 'orb.js'), banner: {js: `/* thinking-orbs 0.3.2\n\n${orbLicense}\n*/`}, logLevel: 'warning'});
execFileSync(join(here, 'node_modules/.bin/tsc'), ['--project', 'tsconfig.browser.json', '--noEmit', 'false', '--rewriteRelativeImportExtensions', 'true', '--rootDir', '.', '--outDir', join(out, 'schemas')], {cwd: join(root, 'packages/verification-schemas'), stdio: 'inherit'});
// MV3 service workers do not support JSON import assertions. Inline the packaged
// registry data as parsed JSON, preserving the shared runtime validation/digests.
// An initial unpacked load alone does not qualify subsequent worker restarts.
const registryFile = join(out, 'schemas/src/registry.js');
let registrySource = await readFile(registryFile, 'utf8');
const jsonImports = [...registrySource.matchAll(/^import (\w+) from "(\.\.\/schemas\/[\w.-]+\.json)" with \{ type: "json" \};$/gm)];
if (jsonImports.length === 0) throw Error('Registry JSON imports changed; review MV3 packaging');
for (const [statement, name, path] of jsonImports) {
  const data = JSON.stringify(JSON.parse(await readFile(resolve(dirname(registryFile), path), 'utf8')));
  registrySource = registrySource.replace(statement, `const ${name} = JSON.parse(${JSON.stringify(data)});`);
}
await writeFile(registryFile, registrySource);
// tsc also emitted the registry's JSON (schemas/schemas/*.json). It is inlined above, so nothing loads it, and the
// Chrome Web Store refuses a package with a second manifest.json (the registry's pins) anywhere in it.
await rm(join(out, 'schemas/schemas'), {recursive: true, force: true});
let wasmRuntime;
if (tee) {
  wasmRuntime = await copyPinnedWasm({source: join(here, 'wasm-io'), destination: join(out, 'wasm'),
    pin: JSON.parse(await readFile(join(here, 'config/tee-wasm-io.json'), 'utf8')),
    patchFile: join(here, 'patches/0001-await-io-write.patch'),
    sessionPatchFile: join(here, 'patches/0002-multi-request-session.patch')});
} else await cp(dirname(fileURLToPath(import.meta.resolve('tlsn-wasm'))), join(out, 'wasm'), {recursive: true});
await writeFile(join(out, 'config.js'), `export default ${JSON.stringify(config, null, 2)};\n`);
const listedVerifiers = [...legacyVerifiers, ...testVerifiers];
const connectSources = [...(tee ? [] : ['https://*.verifier.pines.family', 'wss://*.verifier.pines.family']), ...listedVerifiers.flatMap(value => [value, value.replace(/^http/, 'ws')])];
if(config.qualificationResponseMetadata?.receiver)connectSources.push(new URL(config.qualificationResponseMetadata.receiver).origin);
// Only the dedicated entry zone: channel sockets and credential-free latency probes. Never `*.pines.family`.
if(tee?.regionalEntry)connectSources.push(...regionalConnectSources(tee.regionalEntry.suffix));
if(assistance)connectSources.push('https://grok.com');
// Chrome requires proxy at installation; authentication remains optional.
const manifest = {
  manifest_version: 3, minimum_chrome_version: '141', name: migrationQualification || recoveryQualification || qualification || localQualification ? 'Pines Verifier LOCAL QUALIFICATION' : teeFixture ? 'Pines Verifier HARDWARE FIXTURE' : 'Pines Verifier', version: recoveryQualification ? recoveryQualification.version : migrationQualification ? migrationQualification.version : qualification ? qualification.version : localQualification ? '1.17.0' : publicPrivateHeaders ? privateHeadersRelease.version : tee ? '1.4.0' : '0.9.3', key: identity.key,
  icons: {16: 'icons/icon-16.png', 32: 'icons/icon-32.png', 48: 'icons/icon-48.png', 128: 'icons/icon-128.png'},
  description: tee ? 'Verify your ChatGPT, Claude or Grok subscription privately with native TLSNotary and an attested AWS enclave.' : claude || grok ? `Prove your paid ${['ChatGPT', ...(claude ? ['Claude'] : []), ...(grok ? ['Grok'] : [])].join(', ').replace(/, ([^,]+)$/, ' or $1')} subscription to Pines with a zkTLS proof.` : chatgptClaims || chatgptIdentity ? 'Prove your paid ChatGPT subscription to Pines with a zkTLS proof.' : 'Review disclosures and create non-claimable TLSNotary Proxy pilot receipts.',
  background: {service_worker: 'background.js', type: 'module'},
  action: {default_title: 'Open Pines Verifier', default_icon: {16: 'icons/icon-16.png', 32: 'icons/icon-32.png'}}, side_panel: {default_path: 'panel.html'},
  permissions: ['offscreen', 'storage', 'sidePanel', 'alarms', ...(config.captureProvider ? ['webRequest'] : []), ...(assistance ? ['proxy'] : [])],
  ...(assistance ? {optional_permissions: ['webRequestAuthProvider']} : {}),
  optional_host_permissions: tee ? tee.providers.map(entry => entry.schema.request.origin + '/*') : chatgpt ? ['https://chatgpt.com/*', ...(claude ? ['https://claude.ai/*'] : []), ...(grok ? ['https://grok.com/*'] : [])] : (privateFixture ? ['https://httpbingo.org/*'] : []),
  externally_connectable: {matches: [...new Set(matchPatternsFor(origins))]},
  cross_origin_embedder_policy: {value: 'require-corp'}, cross_origin_opener_policy: {value: 'same-origin'},
  content_security_policy: {extension_pages: `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self' ${[...new Set(connectSources)].join(' ')}; object-src 'none'; frame-ancestors 'none';`},
};
await writeFile(join(out, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
await build({entryPoints: [join(here, 'client.mjs')], bundle: true, format: 'esm', platform: 'browser', target: 'chrome116', outfile: join(out, 'client.mjs'), logLevel: 'warning'});
await cp(join(here, 'client.d.mts'), join(out, 'client.d.mts'));
for (const name of ['README.md', 'PROVENANCE.md', 'UPSTREAM_LICENSE.md']) await cp(join(here, name), join(out, name));
const publishedConfig=structuredClone(config);
// The installed runtime needs this dedicated capability. Published metadata
// describes its scope without copying the token into reports or log output.
if(publishedConfig.qualificationResponseMetadata)delete publishedConfig.qualificationResponseMetadata.receiverToken;
await writeFile(join(out, 'build.json'), JSON.stringify({...publishedConfig, sourceRevision, sourceDirty,
  ...(qualification ? {qualificationOnly:true,qualification:qualification.declaration} : {}),
  ...(migrationQualification ? {qualificationOnly:true,qualification:migrationQualification.declaration} : {}),
  ...(recoveryQualification ? {qualificationOnly:true,qualification:recoveryQualification.declaration} : {}),
  ...(localQualification ? {localQualification:{format:'pines-local-qualification-build-v1',version:'1.17.0',origin:origins[0],transport:tee.api}} : {}),
  ...(publicPrivateHeaders ? {publicRelease:{format:'pines-private-headers-public-package-v2',version:privateHeadersRelease.version,
    policySha256:createHash('sha256').update(await readFile(join(root, privateHeadersRelease.policyFile))).digest('hex'),
    builtFromSource:true,claimSigningEnabled:false}} : {}),
  ...(wasmRuntime ? {wasmRuntime} : {}),
  wasmSha256: createHash('sha256').update(await readFile(join(out, 'wasm/tlsn_wasm_bg.wasm'))).digest('hex')}, null, 2) + '\n');
console.log(`Built ${identity.id}: Proxy, ${config.schemas.map(schema => `${schema.schemaId}@${schema.version}`).join(' + ')}, ${verifierRevision}`);
