// Stable Sydney identity lifecycle. Native recipient-open and HMAC keep K out
// of the JavaScript service; dependency injection exercises fixed failure paths.
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {verifyNitroQuote} from '../nitro.mjs';
import {HARDWARE_PROVIDERS} from '../profile.mjs';
import {CONTEXT,HASH,canonical,rolePcr,sha256,validateKeyConfiguration} from './config.mjs';
import {createNativeRecipient} from './native-recipient.mjs';
import {strictBase64,validateWrappedRecord,wrappedRecord} from './wrapped-store.mjs';

function checkResponse(response,keyArn,bootstrap){
  assert(response&&typeof response==='object'&&!Array.isArray(response),'KMS_RESPONSE');
  assert(response.Plaintext===undefined||response.Plaintext===null||response.Plaintext==='','KMS_PLAINTEXT_RESPONSE_REFUSED');
  assert.equal(response.KeyId,keyArn,'KMS_RESPONSE_KEY_SUBSTITUTION');
  // GenerateDataKey does not return KeySpec. The request fixes AES_256 and the
  // decrypted recipient content below must be exactly 32 bytes.
  if(!bootstrap)assert.equal(response.EncryptionAlgorithm,'SYMMETRIC_DEFAULT','KMS_KEY_ALGORITHM');
  return strictBase64(response.CiphertextForRecipient,8192);
}
export async function attestedRecipient({config,operation,roleArn,wrappedSha256,now=Date.now,
  issueQuote,recipientFactory=createNativeRecipient,verifyQuote=verifyNitroQuote}){
  const c=validateKeyConfiguration(config);assert(['GenerateDataKey','Decrypt'].includes(operation),'KMS_OPERATION');
  assert(operation==='GenerateDataKey'?roleArn===c.bootstrapRoleArn:c.runtimeRoleArns.includes(roleArn),'KMS_ROLE_SCOPE');
  assert(operation==='GenerateDataKey'?wrappedSha256===null:HASH.test(wrappedSha256),'KMS_WRAPPED_PIN_REQUIRED');
  assert.equal(typeof issueQuote,'function','MEASURED_NSM_ISSUER_REQUIRED');
  const recipient=await recipientFactory();
  try{
    assert(recipient.publicKey instanceof Uint8Array&&recipient.publicKey.length===294,'KMS_RECIPIENT_SPKI');
    const binding={publicKey:recipient.publicKey,nonce:randomBytes(32),userData:Buffer.from(sha256(canonical({
      purpose:'pines/kms-recipient/v1',keyArn:c.keyArn,operation,roleArn,wrappedSha256,context:CONTEXT})), 'hex')};
    const bytes=await issueQuote(binding);assert(bytes instanceof Uint8Array&&bytes.length<=16384,'KMS_QUOTE_LIMIT');
    // This is the same signature/certificate/PCR0/1/2/freshness/binding verifier
    // as the qualified baseline. No unverified parsed PCR report is accepted.
    const quote=await verifyQuote(bytes,binding,{profile:HARDWARE_PROVIDERS[0].profile,pcrTuples:c.pcrTuples},now());
    assert(c.pcrTuples.some(t=>canonical(t)===canonical(quote.pcrTuple)),'KMS_PCR_TUPLE');
    assert.equal(quote.parentPcr3,rolePcr(roleArn),'KMS_PARENT_ROLE');
    assert(Number.isSafeInteger(quote.timestamp)&&quote.timestamp<=now()+2000&&quote.timestamp>=now()-60000,'KMS_QUOTE_STALE');
    return {recipient,request:{KeyEncryptionAlgorithm:'RSAES_OAEP_SHA_256',AttestationDocument:Buffer.from(bytes).toString('base64')},
      attestation:{sha256:sha256(bytes),pcrTuple:[...quote.pcrTuple],parentPcr3:quote.parentPcr3,issuedAt:quote.timestamp}};
  }catch(error){recipient.destroy();throw error;}
}

/** No retry: any ambiguous GenerateDataKey response leaves a durable claim. */
export async function bootstrapWrappedKey({config,store,kms,now=Date.now,...attestation}){
  const c=validateKeyConfiguration(config),at=now();assert(at>=c.bootstrapWindow.startsAt&&at<c.bootstrapWindow.endsAt,'KMS_BOOTSTRAP_WINDOW');
  const issued=await attestedRecipient({...attestation,config:c,operation:'GenerateDataKey',roleArn:c.bootstrapRoleArn,wrappedSha256:null,now});
  let key;
  try{
    await store.claimBootstrap({keyArn:c.keyArn,attemptId:randomBytes(32).toString('hex'),createdAt:at});
    assert(now()<c.bootstrapWindow.endsAt,'KMS_BOOTSTRAP_WINDOW');
    const response=await kms('GenerateDataKey',{KeyId:c.keyArn,KeySpec:'AES_256',EncryptionContext:{...CONTEXT},Recipient:issued.request});
    const encrypted=checkResponse(response,c.keyArn,true);
    key=await issued.recipient.openHandle(encrypted);assert(key.ready===true,'KMS_KEY_NOT_READY');
    const record=wrappedRecord({keyArn:c.keyArn,ciphertextBlob:response.CiphertextBlob,createdAt:now()});
    // The ciphertext is durable before success is returned. It is still only a
    // candidate: owner review/backups must pin its digest before routine boots.
    await store.persistBootstrap(record);
    return {wrapped:record,attestation:issued.attestation,identityEnabled:false,requiresOwnerPin:true,generatedNewKey:true};
  }finally{key?.destroy();issued.recipient.destroy();}
}

/** Routine boot never generates a replacement, and never exports raw key bytes. */
export async function decryptPinnedKey({config,roleArn,record,pins,kms,now=Date.now,...attestation}){
  const c=validateKeyConfiguration(config),wrapped=validateWrappedRecord(record,pins);assert.equal(wrapped.keyArn,c.keyArn,'KMS_KEY_SCOPE');
  const issued=await attestedRecipient({...attestation,config:c,operation:'Decrypt',roleArn,wrappedSha256:wrapped.ciphertextSha256,now});
  let key;
  try{
    const response=await kms('Decrypt',{KeyId:c.keyArn,EncryptionAlgorithm:'SYMMETRIC_DEFAULT',CiphertextBlob:wrapped.ciphertextBlob,
      EncryptionContext:{...CONTEXT},Recipient:issued.request});
    key=await issued.recipient.openHandle(checkResponse(response,c.keyArn,false));assert(key.ready===true,'KMS_KEY_NOT_READY');
    const held=key;key=null;
    return Object.freeze({wrappedSha256:wrapped.ciphertextSha256,keyArn:c.keyArn,attestation:issued.attestation,
      get ready(){return held.ready;},digest:bytes=>held.digest(bytes),metrics:()=>held.metrics(),destroy:()=>held.destroy()
    });
  }catch(error){key?.destroy();issued.recipient.destroy();throw error;}
}
