// Build-only gate for the reviewed prover patches: the IO adapter (0001) and the
// multi-request session (0002). The installed npm package remains
// untouched; TEE builds require the exact separately reproduced local artifact.
import assert from 'node:assert/strict';
import {lstat, mkdir, readFile, readdir, writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {join} from 'node:path';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const upstream = '47aee45b53e06648c1b2ad3689b367b8c923fdec';
const hex = value => /^[a-f0-9]{64}$/.test(value) && !/^0+$/.test(value);
// The upstream files 0002 changes, each pinned as patched (0001 changes crates/wasm/src/io.rs only).
const SESSION_SOURCES = ['crates/sdk-core/src/prover.rs', 'crates/wasm/src/prover/mod.rs'];
export async function copyPinnedWasm({source, destination, pin, patchFile, sessionPatchFile}) {
  assert.deepEqual(Object.keys(pin).sort(), ['files', 'format', 'ioSourceSha256', 'patchSha256',
    'probeEvidenceSha256', 'reproductionEvidenceSha256', 'sessionPatchSha256', 'sessionProbeEvidenceSha256',
    'sessionSourceSha256', 'upstreamCommit'].sort(), 'WASM_PROVENANCE');
  assert.equal(pin.format, 'pines-tlsn-wasm-io-v2', 'WASM_PROVENANCE');
  assert.equal(pin.upstreamCommit, upstream, 'WASM_UPSTREAM');
  for (const key of ['patchSha256', 'ioSourceSha256', 'sessionPatchSha256', 'probeEvidenceSha256',
    'sessionProbeEvidenceSha256', 'reproductionEvidenceSha256'])
    assert(hex(pin[key]), 'WASM_PROVENANCE');
  assert(pin.sessionSourceSha256 && typeof pin.sessionSourceSha256 === 'object' && !Array.isArray(pin.sessionSourceSha256)
    && Object.keys(pin.sessionSourceSha256).sort().join() === SESSION_SOURCES.join()
    && SESSION_SOURCES.every(name => hex(pin.sessionSourceSha256[name])), 'WASM_PROVENANCE');
  assert.equal(sha(await readFile(patchFile)), pin.patchSha256, 'WASM_PATCH_PIN');
  assert.equal(sha(await readFile(sessionPatchFile)), pin.sessionPatchSha256, 'WASM_SESSION_PATCH_PIN');
  assert(pin.files && typeof pin.files === 'object' && !Array.isArray(pin.files), 'WASM_FILES');
  const names = Object.keys(pin.files).sort();
  assert(names.length > 0 && names.length <= 32 && names.includes('tlsn_wasm_bg.wasm')
    && names.includes('tlsn_wasm.js') && names.includes('package.json'), 'WASM_FILES');
  for (const name of names) assert(name.length <= 256 && /^[a-zA-Z0-9_.\/-]+$/.test(name)
    && name.split('/').every(part => part && part !== '.' && part !== '..')
    && !name.startsWith('/') && /^[a-f0-9]{64}$/.test(pin.files[name])
    && !/^0+$/.test(pin.files[name]), 'WASM_FILE_SCOPE');
  const found = [];
  async function scan(relative = '') {
    const path = join(source, relative), info = await lstat(path);
    assert(info.isDirectory() && !info.isSymbolicLink(), 'WASM_FILE_TYPE');
    for (const entry of await readdir(path, {withFileTypes: true})) {
      const name = relative ? relative + '/' + entry.name : entry.name;
      if (entry.isDirectory()) await scan(name);
      else {assert(entry.isFile() && !entry.isSymbolicLink(), 'WASM_FILE_TYPE'); found.push(name);}
    }
  }
  await scan(); assert.deepEqual(found.sort(), names, 'WASM_FILE_SET');
  let total = 0;
  const files = new Map();
  for (const name of names) {
    const path = join(source, name), info = await lstat(path);
    assert(info.isFile() && !info.isSymbolicLink() && info.size <= 64 * 1024 * 1024, 'WASM_FILE_TYPE');
    total += info.size; assert(total <= 128 * 1024 * 1024, 'WASM_PACKAGE_LIMIT');
    const bytes = await readFile(path); assert.equal(sha(bytes), pin.files[name], 'WASM_FILE_PIN');
    files.set(name, bytes);
  }
  assert(files.get('tlsn_wasm_bg.wasm').subarray(0, 8).equals(Buffer.from([0, 97, 115, 109, 1, 0, 0, 0])), 'WASM_FORMAT');
  // Validate the complete package before creating an output. Copy the validated
  // bytes themselves so a source file change cannot silently enter the archive.
  await mkdir(destination);
  for (const [name, bytes] of files) {
    const parts = name.split('/'); parts.pop();
    if (parts.length) await mkdir(join(destination, ...parts), {recursive: true});
    await writeFile(join(destination, name), bytes, {flag: 'wx'});
  }
  return structuredClone(pin);
}
