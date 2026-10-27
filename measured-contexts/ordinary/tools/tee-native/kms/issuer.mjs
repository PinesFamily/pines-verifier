// Measured recipient issuance for the deferred keyed-identity key. It runs the
// same measured NSM adapter as a proof offer, on the runtime's separate
// `attest-kms-recipient` lane, and returns only the signed public document.
// Nothing here verifies a quote: lifecycle.mjs still passes these exact bytes to
// the qualified signature/certificate/PCR-tuple verifier.
import assert from 'node:assert/strict';
import {execFile as nodeExecFile} from 'node:child_process';
import {inspectNitroEncoding} from '../nitro.mjs';

export const RECIPIENT_ATTEST_MODE='attest-kms-recipient';
export const RECIPIENT_BINARY='/app/bin/pines-nitro-runtime';
// A 2048-bit modulus and the 65537 exponent fix every DER length, so the whole
// SubjectPublicKeyInfo envelope is constant. Same acceptance as the measured
// runtime's spki.rs, kept here so a wrong key never reaches /dev/nsm at all.
const SPKI_PREFIX='30820122300d06092a864886f70d01010105000382010f003082010a0282010100';
const SPKI_EXPONENT='0203010001';
export const RECIPIENT_SPKI_BYTES=294;

export function inspectRecipientSpki(value){
  assert(value instanceof Uint8Array&&value.length===RECIPIENT_SPKI_BYTES,'KMS_RECIPIENT_SPKI');
  const key=Buffer.from(value);
  assert(key.subarray(0,33).toString('hex')===SPKI_PREFIX&&key.subarray(289).toString('hex')===SPKI_EXPONENT
    &&(key[33]&0x80)!==0&&(key[288]&1)===1,'KMS_RECIPIENT_SPKI');
  return key;
}
export function recipientBindingInput(binding){
  assert(binding&&typeof binding==='object'&&!Array.isArray(binding),'KMS_RECIPIENT_BINDING');
  assert.deepEqual(Object.keys(binding).sort(),['nonce','publicKey','userData'],'KMS_RECIPIENT_BINDING');
  const publicKey=inspectRecipientSpki(binding.publicKey);
  for(const field of ['nonce','userData'])
    assert(binding[field] instanceof Uint8Array&&binding[field].length===32,'KMS_RECIPIENT_BINDING');
  return {publicKey,input:JSON.stringify({public_key:publicKey.toString('base64'),
    nonce:Buffer.from(binding.nonce).toString('base64'),user_data:Buffer.from(binding.userData).toString('base64')})};
}
/**
 * `onTimestamp` receives the signed NSM timestamp so the caller feeds the same
 * clock guard the proof path uses. No raw key, document or error body is logged.
 */
export function createMeasuredRecipientIssuer({binary=RECIPIENT_BINARY,execFile=nodeExecFile,onTimestamp}={}){
  assert(typeof binary==='string'&&binary.startsWith('/')&&typeof execFile==='function','KMS_ISSUER_SCOPE');
  assert(onTimestamp===undefined||typeof onTimestamp==='function','KMS_ISSUER_SCOPE');
  return async function issueQuote(binding){
    const {publicKey,input}=recipientBindingInput(binding);
    const document=await new Promise((resolve,reject)=>{
      const child=execFile(binary,[RECIPIENT_ATTEST_MODE],{timeout:5000,maxBuffer:32768,encoding:'utf8'},
        (error,stdout)=>error?reject(Error('NSM_REFUSED')):resolve(Buffer.from(String(stdout).trim(),'base64')));
      child.stdin.end(input);
    });
    // Bounded public-document parse only. A refusal here carries no excerpt.
    const parsed=inspectNitroEncoding(new Uint8Array(document));
    onTimestamp?.(parsed.get('timestamp'));
    const pcr=parsed.get('pcrs').get(0);assert(pcr?.some(byte=>byte!==0),'DEBUG_MEASUREMENT');
    // The issued document must carry exactly the requested binding, so a
    // substituted recipient key fails before the KMS request is signed.
    for(const [field,value] of [['public_key',publicKey],['nonce',binding.nonce],['user_data',binding.userData]])
      assert(Buffer.from(parsed.get(field)??[]).equals(Buffer.from(value)),'ATTESTATION_BINDING');
    return new Uint8Array(document);
  };
}
