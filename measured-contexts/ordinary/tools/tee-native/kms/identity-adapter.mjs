// Canonical, domain-separated v2 provider identities using the native keyed
// handle. Only the pseudonym and session MAC leave the enclave.
import assert from 'node:assert/strict';
import {hex, lp} from '../wire.mjs';
import {ALL_PROVIDERS} from '../profile.mjs';

export const KEYED_DOMAIN='pines/private-account/v2';
export const CURRENT_DOMAIN='pines/private-account/v1';
// Same acceptance as providerPseudonym; the keyed form must not widen it.
const ACCOUNT_ID=Object.freeze({chatgpt:/^user-[A-Za-z\d]{24}$/,
  other:/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/});

export const DISABLED_ADAPTER=Object.freeze({enabled:false,generation:'v2',
  pseudonym(){throw Error('KEYED_IDENTITY_DISABLED');}});

export function keyedAccountMessage(provider,id){
  // Either class: the message binds host and identitySourceVersion, which the classes share, so pseudonyms are stable.
  assert(ALL_PROVIDERS.includes(provider),'PROVIDER_SCOPE');
  assert(typeof id==='string'&&(provider.id==='chatgpt'?ACCOUNT_ID.chatgpt:ACCOUNT_ID.other).test(id),'ACCOUNT_ID');
  return lp([KEYED_DOMAIN,provider.host,provider.identitySourceVersion,id]);
}
/**
 * `handle` is the frozen key handle from startKeyedIdentity: its `digest` is the
 * only exposed operation, the key never leaves it, and `destroy` ends use. The
 * adapter returns hex like the current derivation, so a value is never confused
 * with `P` — the domain string differs, so every account's value differs too.
 */
export function createKeyedPseudonymAdapter({handle}={}){
  if(!handle)return DISABLED_ADAPTER;
  assert(typeof handle.digest==='function'&&handle.ready===true,'KMS_KEY_NOT_READY');
  return Object.freeze({enabled:true,generation:'v2',
    pseudonym(provider,id){
      assert(handle.ready===true,'KMS_KEY_NOT_READY');
      return Promise.resolve(handle.digest(keyedAccountMessage(provider,id))).then(hex);
    }});
}
