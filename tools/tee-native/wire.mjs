import {canonicalJson, parseJson} from '../../packages/verification-schemas/src/json.ts';

export const encoder = new TextEncoder();
export const check = (condition, code) => {if (!condition) throw Error(code);};
export const hex = bytes => Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
export function unhex(value, size) {
  check(typeof value === 'string' && /^(?:[0-9a-f]{2})+$/.test(value) && (size === undefined || value.length === size * 2), 'ENCODING');
  return Uint8Array.from(value.match(/../g), b => parseInt(b, 16));
}
export const random = (size = 32) => hex(crypto.getRandomValues(new Uint8Array(size)));
export const encode = value => encoder.encode(canonicalJson(value));
export const decode = bytes => {
  check(bytes.byteLength <= 32768, 'CONTROL_LIMIT');
  return parseJson(new TextDecoder('utf-8', {fatal: true}).decode(bytes), 16);
};
export const digest = async bytes => hex(await crypto.subtle.digest('SHA-256', bytes));
export function lp(parts) {
  const values = parts.map(p => typeof p === 'string' ? encoder.encode(p) : p);
  const bytes = new Uint8Array(values.reduce((n, v) => n + 4 + v.length, 0));
  let at = 0;
  for (const v of values) {new DataView(bytes.buffer).setUint32(at, v.length); at += 4; bytes.set(v, at); at += v.length;}
  return bytes;
}
export const signingKey = () => crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify']);
export const publicKey = async key => hex(await crypto.subtle.exportKey('raw', key));
export const sign = async (domain, body, key) => ({body, signature: hex(await crypto.subtle.sign('Ed25519', key, lp([domain, encode(body)])))});
export async function verify(domain, envelope, key) {
  exact(envelope, ['body', 'signature']);
  const imported = typeof key === 'string' ? await crypto.subtle.importKey('raw', unhex(key, 32), 'Ed25519', false, ['verify']) : key;
  check(await crypto.subtle.verify('Ed25519', imported, unhex(envelope.signature, 64), lp([domain, encode(envelope.body)])), 'SIGNATURE');
  return envelope.body;
}
export function exact(value, keys) {
  check(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length && keys.every(k => Object.hasOwn(value, k)), 'FIELDS');
}
