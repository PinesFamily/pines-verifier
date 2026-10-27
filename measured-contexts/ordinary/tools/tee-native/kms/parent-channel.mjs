// Enclave end of the deferred keyed-identity parent handoff. An enclave has no
// durable storage and no instance role, so the parent supplies two non-secret
// things over the measured `enclave-kms-handoff` pipe: its own temporary role
// credentials, and the wrapped ciphertext. Neither is trusted: the credentials
// must be temporary, and the wrapped record is accepted only against the pin
// baked into the measured image. The hop therefore needs bounds and validation,
// not confidentiality — the parent already holds both values.
import assert from 'node:assert/strict';
import {request as httpRequest} from 'node:http';
import {HASH,KEY_ARN,KEY_REGION,canonical} from './config.mjs';
import {checkedCredentials} from './transport.mjs';
import {validateWrappedRecord} from './wrapped-store.mjs';
import {KMS_HANDOFF_BRIDGE,checkedBridge} from './vsock-agent.mjs';

export const HANDOFF_FORMAT='pines-kms-parent-handoff-v1';
export const PATHS=Object.freeze({configuration:'/kms/configuration',handoff:'/kms/handoff',claim:'/kms/bootstrap-claim',wrapped:'/kms/wrapped'});
const RESPONSE_LIMIT=32768;
const DEADLINE_MS=10000;

function fetchJson({bridge,path,method,body,request,deadline=DEADLINE_MS}){
  assert(Object.values(PATHS).includes(path)&&['GET','POST'].includes(method),'KMS_HANDOFF_ROUTE');
  const payload=body===undefined?undefined:Buffer.from(canonical(body));
  assert(payload===undefined||payload.length<=RESPONSE_LIMIT,'KMS_HANDOFF_REQUEST_LIMIT');
  return new Promise((resolve,reject)=>{
    let done=false,size=0,timer;const chunks=[];
    const finish=(error,value)=>{if(done)return;done=true;clearTimeout(timer);if(error)reject(error);else resolve(value);};
    const req=request({host:bridge.host,port:bridge.port,path,method,
      headers:{'content-type':'application/json',...(payload?{'content-length':String(payload.length)}:{})}},res=>{
      res.on('data',chunk=>{size+=chunk.length;if(size>RESPONSE_LIMIT){req.destroy();finish(Error('KMS_HANDOFF_LIMIT'));}else chunks.push(chunk);});
      res.on('error',()=>finish(Error('KMS_HANDOFF_FAILED')));
      res.on('end',()=>{
        // Never surface the parent's body: it may echo credentials or paths.
        try{
          if(res.statusCode!==200)throw Error('KMS_HANDOFF_REFUSED');
          finish(null,JSON.parse(Buffer.concat(chunks).toString('utf8')));
        }catch(error){finish(Error(/^KMS_[A-Z_]+$/.test(error.message)?error.message:'KMS_HANDOFF_ENCODING'));}
      });
    });
    timer=setTimeout(()=>{req.destroy();finish(Error('KMS_HANDOFF_TIMEOUT'));},deadline);
    req.on('error',()=>finish(Error('KMS_HANDOFF_UNAVAILABLE')));req.end(payload);
  });
}
export function validateHandoff(value,{now,pins}){
  assert(value&&typeof value==='object'&&!Array.isArray(value),'KMS_HANDOFF_DOCUMENT');
  assert.deepEqual(Object.keys(value).sort(),['credentials','format','region','wrapped'],'KMS_HANDOFF_FIELDS');
  assert.equal(value.format,HANDOFF_FORMAT,'KMS_HANDOFF_DOCUMENT');
  assert.equal(value.region,KEY_REGION,'PERMANENT_KEY_REGION');
  assert.deepEqual(Object.keys(value.credentials??{}).sort(),['accessKeyId','expiration','secretAccessKey','sessionToken'],'KMS_HANDOFF_FIELDS');
  // A long-lived IAM user key, an expired session or a missing token all refuse
  // here, before any signature is computed.
  const credentials=checkedCredentials(value.credentials,now);
  // Boot requires the pinned ciphertext; the one reviewed bootstrap has none yet.
  const wrapped=pins===null?null:validateWrappedRecord(value.wrapped,pins);
  assert(pins!==null||value.wrapped===null,'KMS_BOOTSTRAP_HAS_NO_WRAPPED_KEY');
  return {credentials,wrapped};
}
/**
 * The returned object is both the credential provider for transport.mjs and the
 * `store` shape bootstrapWrappedKey expects. Durability lives on the parent: an
 * enclave filesystem is RAM, so a fence written here would not survive a reboot.
 */
export function createParentChannel({bridge=KMS_HANDOFF_BRIDGE,request=httpRequest,now=Date.now}={}){
  const route=checkedBridge(bridge);
  assert(typeof request==='function'&&typeof now==='function','KMS_HANDOFF_SCOPE');
  const call=(path,method,body)=>fetchJson({bridge:route,path,method,body,request});
  return Object.freeze({
    bridge:route,
    async configuration(){return call(PATHS.configuration,'GET');},
    async handoff(pins){return validateHandoff(await call(PATHS.handoff,'GET'),{now:now(),pins});},
    // No retry, by design: an ambiguous claim may have been written, so only
    // operator recovery may continue. Nothing here can generate a second key.
    async claimBootstrap({keyArn,attemptId,createdAt}){
      assert(KEY_ARN.test(keyArn)&&HASH.test(attemptId)&&Number.isSafeInteger(createdAt),'KMS_BOOTSTRAP_CLAIM');
      const value=await call(PATHS.claim,'POST',{format:HANDOFF_FORMAT,keyArn,attemptId,createdAt});
      assert(value?.claimed===true&&value.keyArn===keyArn,'KMS_BOOTSTRAP_CLAIM');
      return {claimed:true};
    },
    async persistBootstrap(record){
      const checked=validateWrappedRecord(record,{keyArn:record?.keyArn,ciphertextSha256:record?.ciphertextSha256});
      const value=await call(PATHS.wrapped,'POST',checked);
      // The parent must have fsynced the ciphertext before acknowledging; the
      // digest it echoes is compared, so a rewritten record fails here.
      assert(value?.persisted===true&&value.ciphertextSha256===checked.ciphertextSha256,'KMS_WRAPPED_NOT_DURABLE');
      return {ciphertextSha256:checked.ciphertextSha256,persisted:true,identityEnabled:false};
    }
  });
}
