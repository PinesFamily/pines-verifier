import {cp, mkdir, readFile, rm, writeFile} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {dirname, join, resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {build} from 'esbuild';
import {funnelOrigins, matchPatternsFor} from './src/funnel-origins.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const root = here;
const out = join(here, 'dist');
const env = process.env;
if (env.PINES_TLSN_PRIVATE_FIXTURE && env.PINES_TLSN_PRIVATE_FIXTURE !== '1') throw Error('PINES_TLSN_PRIVATE_FIXTURE must be 1 or unset');
const privateFixture = env.PINES_TLSN_PRIVATE_FIXTURE === '1';
if (env.PINES_TLSN_PROVIDER && env.PINES_TLSN_PROVIDER !== 'chatgpt') throw Error('Only the ChatGPT provider pilot is supported');
const chatgpt = env.PINES_TLSN_PROVIDER === 'chatgpt';
if (env.PINES_TLSN_CHATGPT_CLAIMS && env.PINES_TLSN_CHATGPT_CLAIMS !== '1') throw Error('PINES_TLSN_CHATGPT_CLAIMS must be 1 or unset');
const chatgptClaims = env.PINES_TLSN_CHATGPT_CLAIMS === '1';
if (env.PINES_TLSN_CHATGPT_IDENTITY && env.PINES_TLSN_CHATGPT_IDENTITY !== '1') throw Error('PINES_TLSN_CHATGPT_IDENTITY must be 1 or unset');
const chatgptIdentity = env.PINES_TLSN_CHATGPT_IDENTITY === '1';
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
function origin(value) {
  const url = new URL(value);
  if (url.origin !== value || url.username || url.password || (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname)))) throw Error('An exact HTTPS or loopback HTTP origin is required');
  return value;
}
function verifier(value) {
  origin(value);
  if (!testBuild && (new URL(value).protocol !== 'https:' || new URL(value).port)) throw Error(`Verifier origin ${value} needs PINES_TLSN_TEST_BUILD=1`);
  return value;
}
const identity = JSON.parse(await readFile(join(here, 'config/identity.json')));
const sourceRevision = execFileSync('git', ['rev-parse', 'HEAD'], {cwd: root, encoding: 'utf8'}).trim();
const sourceDirty = Boolean(execFileSync('git', ['status', '--porcelain'], {cwd: root, encoding: 'utf8'}).trim());
const origins = funnelOrigins(env).map(origin);
// The pinned origin/revision serve pre-assignment APIs (and pages); assigned attempts name their own verifier, checked
// against `verifierPolicy` and the verifier's /info. See policy.js verifierOriginAllowed.
const verifierOrigin = verifier(env.PINES_TLSN_VERIFIER_ORIGIN ?? 'https://v1.verifier.pines.family');
const legacyVerifiers = [...new Set([verifierOrigin, ...(env.PINES_TLSN_LEGACY_VERIFIER_ORIGINS ?? '').split(',').filter(Boolean).map(verifier)])];
const testVerifiers = (env.PINES_TLSN_TEST_VERIFIER_ORIGINS ?? '').split(',').filter(Boolean).map(value => { if (!testBuild) throw Error('PINES_TLSN_TEST_VERIFIER_ORIGINS needs PINES_TLSN_TEST_BUILD=1'); return origin(value); });
const verifierPolicy = {host: '*.verifier.pines.family', legacy: legacyVerifiers, test: testVerifiers};
const verifierRevision = env.PINES_TLSN_VERIFIER_REVISION ?? sourceRevision;
const application = env.PINES_TLSN_APPLICATION ?? 'pines';
const chainId = Number(env.PINES_TLSN_CHAIN_ID ?? 4663);
if (!/^[a-zA-Z0-9._-]{1,80}$/.test(verifierRevision) || !/^[a-zA-Z0-9._-]{1,64}$/.test(application) || !Number.isSafeInteger(chainId) || chainId <= 0) throw Error('Invalid verifier audience or revision');
const config = {protocol: 'pines-tlsn-bridge-v1', wasmVersion: '0.1.0-alpha.15', origins, verifierOrigin, verifierRevision, verifierPolicy, routing: ['pinned', 'assigned'], testBuild, application, chainId, captureProvider: chatgpt || privateFixture,
  schemas: chatgpt ? [{schemaId: 'pines.chatgpt.plan', version: chatgptIdentity ? 3 : chatgptClaims ? 2 : 1}, ...(claude ? [{schemaId: 'pines.claude.plan', version: 1}] : []),
    ...(grok ? [{schemaId: 'pines.grok.plan', version: 1}] : [])]
    : [{schemaId: privateFixture ? 'pines.fixture.httpbingo-private' : 'pines.fixture.httpbingo', version: 1}], chatgptClaims, chatgptIdentity, extensionId: identity.id};
await rm(out, {recursive: true, force: true}); await mkdir(out);
await cp(join(here, 'src'), out, {recursive: true});
await build({entryPoints: [join(here, 'src/provider-capture.js')], bundle: true, format: 'esm', platform: 'browser', target: 'chrome116', outfile: join(out, 'provider-capture.js'), logLevel: 'warning'});
// The panel's loading orb with the thinking-orbs engine (MIT), its notice on top.
const orbLicense = (await readFile(join(dirname(fileURLToPath(import.meta.resolve('thinking-orbs/package.json'))), 'LICENSE'), 'utf8')).trim();
await build({entryPoints: [join(here, 'src/orb.js')], bundle: true, format: 'esm', platform: 'browser', target: 'chrome116', outfile: join(out, 'orb.js'), banner: {js: `/* thinking-orbs 0.3.2\n\n${orbLicense}\n*/`}, logLevel: 'warning'});
execFileSync(join(here, 'node_modules/.bin/tsc'), ['--project', 'tsconfig.browser.json', '--noEmit', 'false', '--rewriteRelativeImportExtensions', 'true', '--rootDir', '.', '--outDir', join(out, 'schemas')], {cwd: join(here, 'verification-schemas'), stdio: 'inherit'});
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
await cp(dirname(fileURLToPath(import.meta.resolve('tlsn-wasm'))), join(out, 'wasm'), {recursive: true});
await writeFile(join(out, 'config.js'), `export default ${JSON.stringify(config, null, 2)};\n`);
const listedVerifiers = [...legacyVerifiers, ...testVerifiers];
const connectSources = ['https://*.verifier.pines.family', 'wss://*.verifier.pines.family', ...listedVerifiers.flatMap(value => [value, value.replace(/^http/, 'ws')])];
const manifest = {
  manifest_version: 3, minimum_chrome_version: '141', name: 'Pines Verifier', version: '0.9.3', key: identity.key,
  icons: {16: 'icons/icon-16.png', 32: 'icons/icon-32.png', 48: 'icons/icon-48.png', 128: 'icons/icon-128.png'},
  description: claude || grok ? `Prove your paid ${['ChatGPT', ...(claude ? ['Claude'] : []), ...(grok ? ['Grok'] : [])].join(', ').replace(/, ([^,]+)$/, ' or $1')} subscription to Pines with a zkTLS proof.` : chatgptClaims || chatgptIdentity ? 'Prove your paid ChatGPT subscription to Pines with a zkTLS proof.' : 'Review disclosures and create non-claimable TLSNotary Proxy pilot receipts.',
  background: {service_worker: 'background.js', type: 'module'},
  action: {default_title: 'Open Pines Verifier', default_icon: {16: 'icons/icon-16.png', 32: 'icons/icon-32.png'}}, side_panel: {default_path: 'panel.html'},
  permissions: ['offscreen', 'storage', 'sidePanel', 'alarms', ...(config.captureProvider ? ['webRequest'] : [])],
  optional_host_permissions: chatgpt ? ['https://chatgpt.com/*', ...(claude ? ['https://claude.ai/*'] : []), ...(grok ? ['https://grok.com/*'] : [])] : (privateFixture ? ['https://httpbingo.org/*'] : []),
  externally_connectable: {matches: [...new Set(matchPatternsFor(origins))]},
  cross_origin_embedder_policy: {value: 'require-corp'}, cross_origin_opener_policy: {value: 'same-origin'},
  content_security_policy: {extension_pages: `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self' ${[...new Set(connectSources)].join(' ')}; object-src 'none'; frame-ancestors 'none';`},
};
await writeFile(join(out, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
await build({entryPoints: [join(here, 'client.mjs')], bundle: true, format: 'esm', platform: 'browser', target: 'chrome116', outfile: join(out, 'client.mjs'), logLevel: 'warning'});
await cp(join(here, 'client.d.mts'), join(out, 'client.d.mts'));
for (const name of ['README.md', 'PROVENANCE.md', 'UPSTREAM_LICENSE.md']) await cp(join(here, name), join(out, name));
await writeFile(join(out, 'build.json'), JSON.stringify({...config, sourceRevision, sourceDirty, wasmSha256: createHash('sha256').update(await readFile(join(out, 'wasm/tlsn_wasm_bg.wasm'))).digest('hex')}, null, 2) + '\n');
console.log(`Built ${identity.id}: Proxy, ${config.schemas.map(schema => `${schema.schemaId}@${schema.version}`).join(' + ')}, ${verifierRevision}`);
