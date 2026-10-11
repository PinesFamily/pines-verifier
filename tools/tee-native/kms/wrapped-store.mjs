// Ciphertext-only storage. Identity recovery is the same pinned ciphertext, never
// a replacement GenerateDataKey. No cloud storage or key creation is performed.
import assert from 'node:assert/strict';
import {open,readFile,lstat,realpath} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {CONTEXT,HASH,KEY_ARN,canonical,checkedContext,exact,sha256} from './config.mjs';
export function strictBase64(value,max){
  assert(typeof value==='string'&&value.length>0&&value.length<=Math.ceil(max/3)*4&&/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value),'KMS_CIPHERTEXT_ENCODING');
  const bytes=Buffer.from(value,'base64');assert(bytes.length>0&&bytes.length<=max&&bytes.toString('base64')===value,'KMS_CIPHERTEXT_ENCODING');return bytes;
}
export function wrappedRecord({keyArn,ciphertextBlob,createdAt}){
  assert(KEY_ARN.test(keyArn)&&Number.isSafeInteger(createdAt)&&createdAt>0,'KMS_WRAPPED_SCOPE');
  const bytes=strictBase64(ciphertextBlob,6144);
  return {format:'pines-wrapped-pseudonym-key-v1',keyArn,context:{...CONTEXT},keyBytes:32,ciphertextBlob,ciphertextSha256:sha256(bytes),createdAt};
}
export function validateWrappedRecord(record,pins){
  exact(record,['format','keyArn','context','keyBytes','ciphertextBlob','ciphertextSha256','createdAt'],'KMS_WRAPPED_FIELDS');
  assert.equal(record.format,'pines-wrapped-pseudonym-key-v1');assert.equal(record.keyBytes,32);checkedContext(record.context);
  const checked=wrappedRecord(record);assert.equal(checked.ciphertextSha256,record.ciphertextSha256,'KMS_WRAPPED_CORRUPTION');
  assert(pins&&KEY_ARN.test(pins.keyArn)&&HASH.test(pins.ciphertextSha256),'KMS_WRAPPED_PIN_REQUIRED');
  assert.equal(record.keyArn,pins.keyArn,'KMS_WRAPPED_KEY_SUBSTITUTION');assert.equal(record.ciphertextSha256,pins.ciphertextSha256,'KMS_WRAPPED_SUBSTITUTION');
  return checked;
}
async function syncDirectory(path){const fd=await open(path,'r');try{await fd.sync();}finally{await fd.close();}}
async function exclusive(path,value){const fd=await open(path,'wx',0o600);try{await fd.writeFile(canonical(value)+'\n');await fd.sync();}finally{await fd.close();}}
export async function wrappedStore(directory){
  assert(resolve(directory)===directory&&await realpath(directory)===directory,'KMS_STORE_REAL_DIRECTORY');
  const stat=await lstat(directory);assert(stat.isDirectory()&&!stat.isSymbolicLink()&&(stat.mode&0o077)===0,'KMS_PRIVATE_STORE_REQUIRED');
  return Object.freeze({
    async claimBootstrap({keyArn,attemptId,createdAt}){
      assert(KEY_ARN.test(keyArn)&&/^[a-f0-9]{64}$/.test(attemptId)&&Number.isSafeInteger(createdAt),'KMS_BOOTSTRAP_CLAIM');
      // This marker is intentionally never removed automatically, even if the
      // network fails. Retrying an ambiguous generation requires owner recovery.
      await exclusive(join(directory,'bootstrap-claimed.json'),{format:'pines-kms-bootstrap-claim-v1',keyArn,attemptId,createdAt});await syncDirectory(directory);
    },
    async persistBootstrap(record){
      validateWrappedRecord(record,{keyArn:record.keyArn,ciphertextSha256:record.ciphertextSha256});
      const claim=JSON.parse(await readFile(join(directory,'bootstrap-claimed.json'),'utf8'));assert.equal(claim.keyArn,record.keyArn,'KMS_BOOTSTRAP_CLAIM');
      await exclusive(join(directory,'wrapped-key.json'),record);await syncDirectory(directory);
      return {ciphertextSha256:record.ciphertextSha256,persisted:true,identityEnabled:false};
    },
    async load(pins){
      const path=join(directory,'wrapped-key.json'),s=await lstat(path);assert(s.isFile()&&!s.isSymbolicLink()&&s.size<=12288,'KMS_WRAPPED_FILE');
      return validateWrappedRecord(JSON.parse(await readFile(path,'utf8')),pins);
    },
    async restore(record,pins){
      const checked=validateWrappedRecord(record,pins);
      // Restore into a fresh directory and fence generation there before making
      // the restored ciphertext visible. A claimed/ambiguous bootstrap directory
      // is evidence to retain, not something this helper resets or reuses.
      await exclusive(join(directory,'bootstrap-claimed.json'),{format:'pines-kms-bootstrap-claim-v1',keyArn:checked.keyArn,
        attemptId:checked.ciphertextSha256,createdAt:checked.createdAt,recovery:true});await syncDirectory(directory);
      await exclusive(join(directory,'wrapped-key.json'),checked);await syncDirectory(directory);
      return {restored:true,ciphertextSha256:checked.ciphertextSha256,generatedNewKey:false};
    }
  });
}
