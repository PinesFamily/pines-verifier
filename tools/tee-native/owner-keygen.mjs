#!/usr/bin/env node
// OWNER-RUN. Generates the two owner key pairs that sign pines-trust-manifest-v1 (active and standby, ECDSA P-256),
// interactively: the output directory and each key's passphrase are typed at the terminal (passphrase with echo off),
// never taken from arguments or the environment. Each private key is written once, encrypted, mode 0600, and the
// program never reads or prints a private key after writing it. It prints ONLY the two public keys, in the exact
// shape `owner-keys.ts` pins (`{keyId, role, jwk}`), and their fingerprints.
//
//   cd tools/tee-native && node owner-keygen.mjs
//
// Key file format: PEM, PKCS#8 `ENCRYPTED PRIVATE KEY`, PBES2 with PBKDF2-HMAC-SHA256 and AES-256-CBC as node:crypto
// writes it (`generateKeyPairSync` `privateKeyEncoding {type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase}`)
// and reads it back (`createPrivateKey({key, format: 'pem', passphrase})`). sign-manifest.mjs reads nothing else.
// Files: <dir>/<keyId>.pem per key and <dir>/owner-keys-public.json with the two public pins; the directory must lie
// outside every git repository and none of the files may exist.
import {generateKeyPairSync, createHash} from 'node:crypto';
import {mkdir, writeFile, stat} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {ownerKeyOf} from '../../packages/verification-schemas/src/sybil/manifest.ts';
import {terminalPrompts} from './owner-prompt.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '../..');
export class OwnerKeygenError extends Error {constructor(code) {super(code); this.code = code;}}
const fail = code => {throw new OwnerKeygenError(code);};
export function insideRepository(path) {
  if (path.startsWith(repo + '/')) return true;
  try {const top = execFileSync('git', ['-C', dirname(path), 'rev-parse', '--show-toplevel'], {encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore']}).trim(); return path.startsWith(top + '/');}
  catch {return false;}
}
export const fingerprintOf = publicKey => 'sha256:' + createHash('sha256').update(publicKey.export({type: 'spki', format: 'der'})).digest('hex');
const exists = path => stat(path).then(() => true, () => false);
/**
 * One key pair: the encrypted PEM is written with `wx` (never over an existing file) and mode 0600; only the public
 * pin and the fingerprint are returned. The passphrase is used for the encoding call and dropped.
 */
export async function writeOwnerKey({directory, keyId, role, passphrase}) {
  if (typeof passphrase !== 'string' || passphrase.length < 12) fail('PASSPHRASE_TOO_SHORT');
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(keyId)) fail('KEY_ID');
  const path = join(directory, `${keyId}.pem`);
  if (await exists(path)) fail('KEY_FILE_EXISTS');
  const {publicKey, privateKey} = generateKeyPairSync('ec', {namedCurve: 'prime256v1',
    publicKeyEncoding: {type: 'spki', format: 'jwk'},
    privateKeyEncoding: {type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase}});
  await writeFile(path, privateKey, {mode: 0o600, flag: 'wx'});
  const pin = ownerKeyOf({keyId, role, jwk: {kty: 'EC', crv: 'P-256', x: publicKey.x, y: publicKey.y}});
  const {createPublicKey} = await import('node:crypto');
  return {pin, fingerprint: fingerprintOf(createPublicKey({key: publicKey, format: 'jwk'})), path};
}
/** The interactive run. `prompts` is the terminal, or a test's injected `{ask, askHidden}`. */
export async function generateOwnerKeys({prompts, now = () => new Date(), log = line => console.log(line)}) {
  const date = now().toISOString().slice(0, 10).replace(/-/g, '');
  const answer = String(await prompts.ask('Output directory for the key files (outside every repository): ') ?? '').trim();
  if (!answer) fail('DIRECTORY_REQUIRED');
  const directory = resolve(answer);
  if (directory === '/') fail('DIRECTORY_REQUIRED');
  if (insideRepository(directory)) fail('KEY_PATH_INSIDE_REPOSITORY');
  await mkdir(directory, {recursive: true, mode: 0o700});
  const publicFile = join(directory, 'owner-keys-public.json');
  if (await exists(publicFile)) fail('KEY_FILE_EXISTS');
  const pins = [];
  for (const role of ['active', 'standby']) {
    const keyId = `pines-owner-${role}-${date}`;
    if (await exists(join(directory, `${keyId}.pem`))) fail('KEY_FILE_EXISTS');
    let passphrase, again;
    try {
      passphrase = await prompts.askHidden(`Passphrase for the ${role} key (${keyId}, at least 12 characters): `);
      again = await prompts.askHidden(`Passphrase for the ${role} key, again: `);
      if (passphrase !== again) fail('PASSPHRASE_MISMATCH');
      const written = await writeOwnerKey({directory, keyId, role, passphrase});
      pins.push(written);
    } finally {passphrase = undefined; again = undefined;}
  }
  const publicPins = pins.map(entry => entry.pin);
  await writeFile(publicFile, JSON.stringify({format: 'pines-owner-keys-public-v1', keys: publicPins}, null, 2) + '\n', {mode: 0o644, flag: 'wx'});
  log('Two owner keys written. Keep the .pem files and their passphrases like the other owner keys; never copy them into a repository.');
  log('Paste these two public keys into packages/verification-schemas/src/sybil/owner-keys.ts (OWNER_KEYS) and set OWNER_KEYS_PROVENANCE to "production":');
  log(JSON.stringify(publicPins, null, 2));
  for (const entry of pins) log(`${entry.pin.keyId} (${entry.pin.role}): fingerprint ${entry.fingerprint}, private key ${entry.path}`);
  log(`Public pins also written to ${publicFile}.`);
  return {keys: pins.map(entry => ({pin: entry.pin, fingerprint: entry.fingerprint, path: entry.path})), publicFile};
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  Promise.resolve().then(() => generateOwnerKeys({prompts: terminalPrompts()})).catch(error => {
    // Codes only: no stack, no path echo beyond what the owner typed, never key material.
    console.error(`refused: ${error?.code ?? 'FAILED'}`);
    process.exit(1);
  });
}
