// Maintained Evervault COSE/X.509 validation, with application policy on the same
// signed bytes. This utility does not enable the unqualified hardware profile.
import {decode as cbor, Tag} from 'cbor2';
import {check, digest, encode, hex, lp, unhex} from './wire.mjs';
import {isHardwareProfile} from './profile.mjs';
import {importChannelKey} from './channel.mjs';

// AWS specifies CBOR, not deterministic CBOR. Long-form integer/length encodings
// are legal and the signature covers the ORIGINAL protected/payload bytes.
// cbor2's duplicate check compares encoded keys, so also reject equal decoded
// keys (including differently encoded integers or strings) before Map creation.
const strict = {preferMap: true, rejectDuplicateKeys: true, requirePreferred: false, rejectStreaming: true,
  rejectFloats: true, rejectBigInts: true, rejectUndefined: true, rejectSimple: true, maxDepth: 12,
  ignoreGlobalTags: true,
  createObject(pairs) {
    const map = new Map();
    for (const [key, value] of pairs) {
      check((typeof key === 'string' || Number.isSafeInteger(key)) && !map.has(key), 'QUOTE_ENCODING');
      map.set(key, value);
    }
    return map;
  }};
function parseCbor(bytes,payload=false){
  // Real NSM documents use an indefinite-length payload map. The entire input
  // is already bounded to 16 KiB; this permits its CBOR representation, not an
  // unbounded network stream. Container depth, semantic duplicates and every
  // decoded field remain checked, and COSE authenticates the original bytes.
  try{return cbor(bytes,payload?{...strict,rejectStreaming:false}:strict);}catch{throw Error('QUOTE_ENCODING');}
}
let validator;
export async function initializeNitro(bytes) {
  const module = await import('./attestation-wasm/pkg/pines_nitro_validation.js');
  await module.default({module_or_path: bytes}); validator = module.verify_document;
}
export function inspectNitroEncoding(bytes) {
  check(bytes instanceof Uint8Array && bytes.length > 0 && bytes.length <= 16384, 'QUOTE_LIMIT');
  let sign1 = parseCbor(bytes);
  if (sign1 instanceof Tag) {check(sign1.tag === 18, 'COSE_TAG'); sign1 = sign1.contents;}
  check(Array.isArray(sign1) && sign1.length === 4, 'COSE');
  const [protectedBytes, unprotected, payload, signature] = sign1;
  check(protectedBytes instanceof Uint8Array && protectedBytes.length <= 128 && unprotected instanceof Map && unprotected.size === 0
    && payload instanceof Uint8Array && signature instanceof Uint8Array && signature.length === 96, 'COSE');
  const protectedMap = parseCbor(protectedBytes);
  check(protectedMap instanceof Map && protectedMap.size === 1 && protectedMap.get(1) === -35, 'COSE_ALGORITHM');
  const doc = parseCbor(payload,true);
  const fields = ['module_id', 'digest', 'timestamp', 'pcrs', 'certificate', 'cabundle', 'public_key', 'user_data', 'nonce'];
  check(doc instanceof Map && [...doc.keys()].every(k => fields.includes(k))
    && fields.slice(0, 6).every(k => doc.has(k)), 'QUOTE_FIELDS');
  check(typeof doc.get('module_id') === 'string' && doc.get('module_id').length <= 256
    && doc.get('digest') === 'SHA384' && Number.isSafeInteger(doc.get('timestamp')), 'QUOTE_FIELDS');
  const pcrs = doc.get('pcrs');
  check(pcrs instanceof Map && pcrs.size >= 3 && pcrs.size <= 32, 'PCRS');
  for (const [index, value] of pcrs) check(Number.isInteger(index) && index >= 0 && index <= 31 && value instanceof Uint8Array && value.length === 48, 'PCRS');
  check(doc.get('certificate') instanceof Uint8Array && doc.get('certificate').length <= 4096, 'CERTIFICATE');
  check(Array.isArray(doc.get('cabundle')) && doc.get('cabundle').length > 0 && doc.get('cabundle').length <= 10
    && doc.get('cabundle').every(c => c instanceof Uint8Array && c.length <= 4096), 'CERTIFICATE');
  for (const key of ['public_key', 'user_data', 'nonce']) check(doc.get(key) == null || (doc.get(key) instanceof Uint8Array && doc.get(key).length <= 1024), 'QUOTE_FIELDS');
  return doc;
}
export async function quoteBinding(ticket, offerBody) {
  const publicKey = await crypto.subtle.exportKey('spki', await importChannelKey(offerBody.channelKey));
  return {publicKey: new Uint8Array(publicKey), nonce: unhex(await digest(lp(['pines/tee/nitro/nonce/v1', encode(ticket)])), 32),
    userData: unhex(await digest(lp(['pines/tee/nitro/context/v1', encode(offerBody)])), 32)};
}
export async function verifyNitroQuote(bytes, expected, policy, now = Date.now()) {
  check(isHardwareProfile(policy.profile) && policy.syntheticOnly !== true && Array.isArray(policy.pcrTuples) && policy.pcrTuples.length > 0, 'HARDWARE_POLICY');
  const doc = inspectNitroEncoding(bytes), pcrs = doc.get('pcrs');
  check(validator && validator(bytes) === true, 'NITRO_SIGNATURE_OR_CHAIN');
  const tuple = [0, 1, 2].map(i => {const pcr = pcrs.get(i); check(pcr?.length === 48 && pcr.some(b => b !== 0), 'DEBUG_MEASUREMENT'); return hex(pcr);});
  check(policy.pcrTuples.some(p => Array.isArray(p) && p.length === 3 && p.every((v, i) => v === tuple[i])), 'MEASUREMENT');
  const time = doc.get('timestamp'); check(time <= now + 2000 && time >= now - 60000, 'QUOTE_STALE');
  for (const [field, key] of [['public_key', 'publicKey'], ['nonce', 'nonce'], ['user_data', 'userData']]) {
    check(expected[key] instanceof Uint8Array && expected[key].length > 0 && doc.get(field) instanceof Uint8Array
      && hex(doc.get(field)) === hex(expected[key]), 'ATTESTATION_BINDING');
  }
  return {pcrTuple: tuple, timestamp: time};
}
