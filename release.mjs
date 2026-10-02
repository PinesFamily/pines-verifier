// Reproducible release packaging for Pines Verifier.
//
//   node release.mjs [--allow-dirty]
//
// Builds the production configuration from config/release.json, then writes two deterministic ZIPs (sorted entries,
// fixed timestamps and modes, deflate level 9) with SHA-256 checksums and a manifest of the build:
//   release/pines-tlsn-extension-<version>.zip        unpacked-install archive; keeps `key`, so the extension ID is
//                                                     the one the web client's bridge messages (TLSN_EXTENSION_ID)
//   release/pines-tlsn-extension-<version>-store.zip  Chrome Web Store upload; `key` removed as the store requires
// It never uploads or publishes anything. Two runs from the same clean commit produce byte-identical archives.
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {mkdir, readFile, readdir, writeFile, stat} from 'node:fs/promises';
import {dirname, join, relative} from 'node:path';
import {fileURLToPath} from 'node:url';
import {crc32, deflateRawSync} from 'node:zlib';
import {TLSN_EXTENSION_ID} from './client.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const root = here;
const allowDirty = process.argv.includes('--allow-dirty');
const dirty = Boolean(execFileSync('git', ['status', '--porcelain'], {cwd: root, encoding: 'utf8'}).trim());
if (dirty && !allowDirty) throw Error('Release builds need a clean checkout (or --allow-dirty for a rehearsal)');
const release = JSON.parse(await readFile(join(here, 'config/release.json'), 'utf8'));
const identity = JSON.parse(await readFile(join(here, 'config/identity.json'), 'utf8'));
// The ID Chrome derives from the manifest key must be the one the page bridge messages.
const derived = [...createHash('sha256').update(Buffer.from(identity.key, 'base64')).digest('hex').slice(0, 32)].map(c => String.fromCharCode(97 + parseInt(c, 16))).join('');
if (derived !== identity.id || identity.id !== TLSN_EXTENSION_ID) throw Error(`Extension identity mismatch: key ${derived}, identity ${identity.id}, client ${TLSN_EXTENSION_ID}`);

execFileSync(process.execPath, ['build.mjs'], {cwd: here, stdio: 'inherit', env: {
  ...process.env, PINES_TLSN_TEST_BUILD: '', PINES_TLSN_TEST_VERIFIER_ORIGINS: '', PINES_TLSN_PRIVATE_FIXTURE: '', PINES_TLSN_CHATGPT_CLAIMS: '',
  PINES_TLSN_PROVIDER: 'chatgpt', PINES_TLSN_CHATGPT_IDENTITY: '1', PINES_TLSN_CLAUDE: release.claude ? '1' : '', PINES_TLSN_GROK: release.grok ? '1' : '',
  PROVER_FUNNEL_ORIGINS: release.pageOrigins.join(','), PROVER_FUNNEL_ORIGINS_EXCLUSIVE: '1',
  PINES_TLSN_VERIFIER_ORIGIN: release.pinnedVerifier.origin, PINES_TLSN_VERIFIER_REVISION: release.pinnedVerifier.revision,
  PINES_TLSN_LEGACY_VERIFIER_ORIGINS: (release.legacyVerifierOrigins ?? []).join(','),
  PINES_TLSN_APPLICATION: release.application, PINES_TLSN_CHAIN_ID: String(release.chainId),
}});
const dist = join(here, 'dist');
const manifest = JSON.parse(await readFile(join(dist, 'manifest.json'), 'utf8'));
const build = JSON.parse(await readFile(join(dist, 'build.json'), 'utf8'));
if (manifest.version !== release.version) throw Error(`manifest ${manifest.version} does not match config/release.json ${release.version}`);
if (build.testBuild) throw Error('A release must not carry test origins');
if (manifest.host_permissions !== undefined || manifest.permissions.some(p => ['tabs', 'webNavigation', 'history', 'activeTab', 'scripting'].includes(p))) throw Error('Release permission model changed');
const expectedHosts = ['https://chatgpt.com/*', ...(release.claude ? ['https://claude.ai/*'] : []), ...(release.grok ? ['https://grok.com/*'] : [])];
if (JSON.stringify(manifest.optional_host_permissions) !== JSON.stringify(expectedHosts)) throw Error('Release optional provider origins changed');

async function files(directory) {
  const out = [];
  for (const entry of await readdir(directory, {withFileTypes: true})) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) out.push(...await files(path));
    else if (entry.isFile()) out.push(path);
  }
  return out;
}
/** A minimal deterministic ZIP writer: no timestamps, owners or ordering from the filesystem leak into the archive. */
function zip(entries) {
  const local = [], central = [];
  let offset = 0;
  for (const {name, data} of entries) {
    const nameBytes = Buffer.from(name, 'utf8');
    const compressed = deflateRawSync(data, {level: 9});
    const crc = crc32(data);
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0); header.writeUInt16LE(20, 4); header.writeUInt16LE(0x0800, 6); header.writeUInt16LE(8, 8);
    header.writeUInt16LE(0, 10); header.writeUInt16LE(0x21, 12); // 1980-01-01 00:00
    header.writeUInt32LE(crc, 14); header.writeUInt32LE(compressed.length, 18); header.writeUInt32LE(data.length, 22);
    header.writeUInt16LE(nameBytes.length, 26); header.writeUInt16LE(0, 28);
    local.push(header, nameBytes, compressed);
    const record = Buffer.alloc(46);
    record.writeUInt32LE(0x02014b50, 0); record.writeUInt16LE(0x0314, 4); record.writeUInt16LE(20, 6); record.writeUInt16LE(0x0800, 8); record.writeUInt16LE(8, 10);
    record.writeUInt16LE(0, 12); record.writeUInt16LE(0x21, 14); record.writeUInt32LE(crc, 16); record.writeUInt32LE(compressed.length, 20);
    record.writeUInt32LE(data.length, 24); record.writeUInt16LE(nameBytes.length, 28); record.writeUInt32LE((0o100644 << 16) >>> 0, 38); record.writeUInt32LE(offset, 42);
    central.push(record, nameBytes);
    offset += header.length + nameBytes.length + compressed.length;
  }
  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, directory, end]);
}
const paths = (await files(dist)).map(path => relative(dist, path).split('\\').join('/')).sort();
// build.json carries the source revision; manifest variants differ only in `key`.
// The Chrome Web Store refuses a package that has any manifest.json besides the root one.
if (paths.some(name => name !== 'manifest.json' && /(^|\/)manifest\.json$/i.test(name))) throw Error('Only the root manifest.json may be packaged: the Chrome Web Store refuses a second one');
const entries = await Promise.all(paths.map(async name => ({name, data: await readFile(join(dist, name))})));
const withoutKey = entries.map(entry => entry.name === 'manifest.json'
  ? {name: entry.name, data: Buffer.from(JSON.stringify(Object.fromEntries(Object.entries(manifest).filter(([k]) => k !== 'key')), null, 2) + '\n')} : entry);
const out = join(here, 'release');
await mkdir(out, {recursive: true});
const sha = data => createHash('sha256').update(data).digest('hex');
const archives = {};
for (const [suffix, set] of [['', entries], ['-store', withoutKey]]) {
  const name = `pines-tlsn-extension-${manifest.version}${suffix}.zip`;
  const data = zip(set);
  await writeFile(join(out, name), data);
  await writeFile(join(out, name + '.sha256'), `${sha(data)}  ${name}\n`);
  archives[suffix ? 'store' : 'unpacked'] = {file: name, sha256: sha(data), bytes: data.length};
}
const summary = {
  version: manifest.version, extensionId: identity.id, sourceRevision: build.sourceRevision, sourceDirty: build.sourceDirty,
  wasmSha256: build.wasmSha256, routing: build.routing, verifierPolicy: build.verifierPolicy, pinnedVerifier: release.pinnedVerifier,
  pageOrigins: build.origins, schemas: build.schemas, hostPermissions: manifest.host_permissions ?? [], optionalHostPermissions: manifest.optional_host_permissions,
  contentSecurityPolicy: manifest.content_security_policy.extension_pages, archives,
  node: process.version, files: Object.fromEntries(await Promise.all(entries.map(async ({name, data}) => [name, sha(data)]))),
};
await writeFile(join(out, `pines-tlsn-extension-${manifest.version}.json`), JSON.stringify(summary, null, 2) + '\n');
console.log(`Release ${manifest.version} (${identity.id}) from ${build.sourceRevision}${build.sourceDirty ? ' (dirty)' : ''}`);
for (const {file, sha256} of Object.values(archives)) console.log(`  ${file}  ${sha256}`);
void stat;
