#!/usr/bin/env node
// The trust-manifest tool. Sessions PREPARE the canonical body (`build`, no key involved); the OWNER SIGNS it from the
// owner's shell (`sign`, interactive: the private key file path and its passphrase are typed at the terminal, the
// passphrase with echo off, never taken from arguments or the environment); anyone VERIFIES (`verify`). The tool
// never prints, logs or copies key material, and a failure is reported as a code, never as a crypto error text.
//
//   node sign-manifest.mjs build  --policy hardware/policy.private-headers-public.json --disclosure-policy private-headers-gzip-v1
//                                 [--generation v5-20261012|sybil-facts-20261020]   (the schema set of the class; default the live one)
//                                 --images hardware/trust-manifest-images.json --version N [--issued-at S]
//                                 (--previous manifest.json | --last-version M) --out manifest.unsigned.json
//   node sign-manifest.mjs sign   manifest.unsigned.json --out manifest.json (--previous manifest.json | --last-version M)
//                                 [--append manifest.json] [--allow-test-key]
//                                 → prompts: "Private key file:" then "Passphrase:" (hidden)
//   node sign-manifest.mjs verify --manifest manifest.json --disclosure-policy ID [--generation ID] [--keys test/fixtures/owner-test-keys.json]
//                                 [--previous manifest.json | --last-version M]
//
// The private key file is what owner-keygen.mjs wrote: PEM, PKCS#8 ENCRYPTED PRIVATE KEY (PBES2, PBKDF2-HMAC-SHA256,
// AES-256-CBC), read back with node:crypto `createPrivateKey({key, format: 'pem', passphrase})`. Its public half must
// be one of the pinned owner keys; a pinned TEST key is refused unless `--allow-test-key` says this is a local stack.
// A version that is not strictly above `--previous`/`--last-version` is refused by build, sign and verify alike.
// Tests drive `sign` through an injected `prompts` object; there is no non-interactive switch.
import {readFile, writeFile} from 'node:fs/promises';
import {createPrivateKey, createPublicKey} from 'node:crypto';
import {join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {canonicalManifest, parseTrustManifest, signTrustManifest, verifyTrustManifest} from '../../packages/verification-schemas/src/sybil/manifest.ts';
import {OWNER_KEYS, OWNER_KEYS_PROVENANCE, pinnedOwnerKeyOf, testOwnerKeysFrom} from '../../packages/verification-schemas/src/sybil/owner-keys.ts';
import {dirname} from 'node:path';
import {fileURLToPath as toPath} from 'node:url';
/** The committed test pair's public pins, the key set `--allow-test-key` signs for and `verify --keys` may name. */
export const TEST_KEYS_FILE = join(dirname(toPath(import.meta.url)), 'test/fixtures/owner-test-keys.json');
export const testKeys = async (path = TEST_KEYS_FILE) => testOwnerKeysFrom(JSON.parse(await readFile(resolve(path), 'utf8')));
import {MANIFEST_AUDIENCE, admittedSet, checkVersionAdvances, manifestBodyFromPolicySet} from './trust-manifest.mjs';
import {terminalPrompts} from './owner-prompt.mjs';

export class SignManifestError extends Error {constructor(code) {super(code); this.code = code;}}
const fail = code => {throw new SignManifestError(code);};
export function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = {}, positional = [];
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    if (!arg.startsWith('--')) {positional.push(arg); continue;}
    const name = arg.slice(2);
    if (name === 'allow-test-key') {options[name] = true; continue;}
    const value = rest[++i];
    if (value === undefined || value.startsWith('--')) fail('USAGE');
    if (name in options) fail('USAGE');
    options[name] = value;
  }
  return {command, options, positional};
}
const integer = (value, code) => {const n = Number(value); if (!Number.isSafeInteger(n) || n < 0) fail(code); return n;};
const readJson = async path => JSON.parse(await readFile(resolve(path), 'utf8'));
async function floorOf(options, {required = true} = {}) {
  if (options.previous !== undefined && options['last-version'] !== undefined) fail('USAGE');
  if (options.previous !== undefined) return {previous: await readJson(options.previous)};
  if (options['last-version'] !== undefined) return {lastVersion: integer(options['last-version'], 'TRUST_MANIFEST_VERSION')};
  if (required) fail('PREVIOUS_REQUIRED');
  return {};
}
const floorVersion = floor => floor.previous ? parseTrustManifest(floor.previous).version : floor.lastVersion;
/** `build`: the unsigned canonical body from the policy set, the class and the images' provenance. No key involved. */
export async function build(options, {now = () => Math.floor(Date.now() / 1000)} = {}) {
  for (const name of ['policy', 'disclosure-policy', 'images', 'version', 'out']) if (options[name] === undefined) fail('USAGE');
  const version = integer(options.version, 'TRUST_MANIFEST_VERSION');
  checkVersionAdvances(version, await floorOf(options));
  // The images file is the provenance table (`{purpose, images: [...]}`) or a bare array.
  const imagesInput = await readJson(options.images);
  const body = await manifestBodyFromPolicySet({policySet: await readJson(options.policy), disclosurePolicy: options['disclosure-policy'], version,
    issuedAt: options['issued-at'] === undefined ? now() : integer(options['issued-at'], 'TRUST_MANIFEST_VERSION'), images: Array.isArray(imagesInput) ? imagesInput : imagesInput?.images,
    ...(options.generation === undefined ? {} : {generation: options.generation})});
  await writeFile(resolve(options.out), JSON.stringify(body, null, 2) + '\n', {mode: 0o644});
  return {version: body.version, providers: body.providers.map(entry => `${entry.schema.schemaId}@${entry.schema.version}`), images: body.images.map(entry => entry.label), out: resolve(options.out)};
}
/**
 * Open the owner's encrypted key file with the passphrase and hand back a non-extractable WebCrypto signing key and
 * the pinned public key it belongs to. The decrypted PKCS#8 bytes live in one buffer that is zeroed after import.
 */
async function openSigningKey(path, passphrase, keys) {
  let pem;
  try {pem = await readFile(resolve(path), 'utf8');} catch {fail('KEY_FILE_UNREADABLE');}
  let keyObject;
  try {keyObject = createPrivateKey({key: pem, format: 'pem', passphrase});} catch {fail('KEY_DECRYPT_FAILED');}
  if (keyObject.asymmetricKeyType !== 'ec' || keyObject.asymmetricKeyDetails?.namedCurve !== 'prime256v1') fail('KEY_TYPE');
  const jwk = createPublicKey(keyObject).export({format: 'jwk'});
  const pinned = pinnedOwnerKeyOf({x: jwk.x, y: jwk.y}, keys);
  if (!pinned) fail('KEY_NOT_PINNED');
  const der = keyObject.export({type: 'pkcs8', format: 'der'});
  try {return {privateKey: await crypto.subtle.importKey('pkcs8', der, {name: 'ECDSA', namedCurve: 'P-256'}, false, ['sign']), pinned};}
  catch {fail('KEY_IMPORT_FAILED');}
  finally {der.fill(0);}
}
/** `sign`: one owner signature over the canonical bytes of the prepared body, then the full consumer check on the result. */
export async function sign(positional, options, {prompts, keys, provenance = OWNER_KEYS_PROVENANCE} = {}) {
  const [bodyPath] = positional;
  if (positional.length !== 1 || options.out === undefined) fail('USAGE');
  if (!prompts) fail('PROMPTS_REQUIRED');
  if (provenance !== 'production') fail('TEST_KEY_REFUSED');
  // The key set the file must belong to: the owner's pins, or with --allow-test-key the committed test pair (a local stack).
  keys ??= options['allow-test-key'] === true ? await testKeys() : OWNER_KEYS;
  const floor = await floorOf(options);
  const raw = await readJson(bodyPath);
  const {signatures, ...body} = raw; void signatures;
  checkVersionAdvances(body.version, floor);
  const existing = options.append === undefined ? [] : parseTrustManifest(await readJson(options.append)).signatures;
  if (existing.length && canonicalManifest(parseTrustManifest({...body, signatures: existing})) !== canonicalManifest(parseTrustManifest(await readJson(options.append)))) fail('APPEND_BODY_MISMATCH');
  const keyPath = await prompts.ask('Private key file: ');
  let passphrase = await prompts.askHidden('Passphrase: ');
  let opened;
  try {opened = await openSigningKey(keyPath, passphrase, keys);} finally {passphrase = undefined;}
  if (options['key-id'] !== undefined && options['key-id'] !== opened.pinned.keyId) fail('KEY_ID_MISMATCH');
  const signed = await signTrustManifest(body, {keyId: opened.pinned.keyId, privateKey: opened.privateKey}, existing);
  const verified = await verifyTrustManifest(JSON.parse(canonicalManifest(signed)), {keys, audience: MANIFEST_AUDIENCE, lastAcceptedVersion: floorVersion(floor)});
  await writeFile(resolve(options.out), canonicalManifest(verified.manifest) + '\n', {mode: 0o644});
  return {version: verified.manifest.version, digest: verified.digest, signedBy: verified.signedBy, out: resolve(options.out)};
}
/** `verify`: exactly what the identity does at boot and the extension before a proof, for one class. */
export async function verify(options, {keys} = {}) {
  for (const name of ['manifest', 'disclosure-policy']) if (options[name] === undefined) fail('USAGE');
  // `--keys <file>`: verify against an injected key set (a test pair's public pins) instead of the owner's.
  keys ??= options.keys === undefined ? OWNER_KEYS : await testKeys(options.keys);
  const floor = await floorOf(options, {required: false});
  const raw = await readJson(options.manifest);
  const verified = await verifyTrustManifest(raw, {keys, audience: MANIFEST_AUDIENCE, lastAcceptedVersion: floorVersion(floor)});
  const set = await admittedSet(verified.manifest, options['disclosure-policy'], options.generation === undefined ? {} : {generation: options.generation});
  return {version: verified.manifest.version, digest: verified.digest, signedBy: verified.signedBy, providers: set.capability.providers.map(entry => `${entry.id}:${entry.schema.schemaId}@${entry.schema.version}`),
    images: verified.manifest.images.map(entry => entry.label), canonical: canonicalManifest(verified.manifest) === JSON.stringify(raw)};
}
export async function main(argv, {prompts} = {}) {
  const {command, options, positional} = parseArgs(argv);
  if (command === 'build' && positional.length === 0) return build(options);
  if (command === 'sign') return sign(positional, options, {prompts: prompts ?? terminalPrompts()});
  if (command === 'verify' && positional.length === 0) return verify(options);
  fail('USAGE');
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then(result => {console.log(JSON.stringify(result, null, 2));}, error => {
    // A code only: never a crypto library message, never a stack, never key material.
    console.error(`refused: ${error?.code ?? (/^[A-Z_]+$/.test(error?.message ?? '') ? error.message : 'FAILED')}`);
    process.exit(1);
  });
}
