// Fixed-region AWS JSON/SigV4 adapter for a future measured process. No AWS
// operation runs on import and no CreateKey/CreateGrant operation is supported.
import assert from 'node:assert/strict';
import {createHmac} from 'node:crypto';
import {request as httpsRequest} from 'node:https';
import {CONTEXT,KEY_ARN,KEY_REGION,canonical,checkedContext,sha256} from './config.mjs';
import {strictBase64} from './wrapped-store.mjs';
const HOST='kms.'+KEY_REGION+'.amazonaws.com';
const hmac=(key,value)=>createHmac('sha256',key).update(value).digest();
// Instance-profile credentials must be temporary and alive for the entire
// bounded request. Long-lived IAM user credentials are not accepted here.
export function checkedCredentials(credentials,now){
  assert(credentials&&/^ASIA[A-Z0-9]{16}$/.test(credentials.accessKeyId)
    &&typeof credentials.secretAccessKey==='string'&&credentials.secretAccessKey.length===40
    &&typeof credentials.sessionToken==='string'&&credentials.sessionToken.length>=16&&credentials.sessionToken.length<=8192
    &&Number.isSafeInteger(credentials.expiration)&&credentials.expiration>now+15000
    &&credentials.expiration<=now+24*3600000,'TEMPORARY_KMS_CREDENTIALS_REQUIRED');
  return credentials;
}
export function signedKmsRequest(operation,input,credentials,now=Date.now()){
  assert(['GenerateDataKey','Decrypt'].includes(operation),'KMS_TRANSPORT_OPERATION');
  assert(input&&KEY_ARN.test(input.KeyId),'KMS_TRANSPORT_KEY');checkedContext(input.EncryptionContext);
  assert(input.Recipient?.KeyEncryptionAlgorithm==='RSAES_OAEP_SHA_256','KMS_RECIPIENT_REQUIRED');
  strictBase64(input.Recipient.AttestationDocument,16384);
  const fields=operation==='GenerateDataKey'?['KeyId','KeySpec','EncryptionContext','Recipient']:
    ['KeyId','EncryptionAlgorithm','CiphertextBlob','EncryptionContext','Recipient'];
  assert.deepEqual(Object.keys(input).sort(),fields.sort(),'KMS_REQUEST_FIELDS');
  assert.deepEqual(Object.keys(input.Recipient).sort(),['AttestationDocument','KeyEncryptionAlgorithm']);
  if(operation==='GenerateDataKey')assert.equal(input.KeySpec,'AES_256');
  else {assert.equal(input.EncryptionAlgorithm,'SYMMETRIC_DEFAULT');strictBase64(input.CiphertextBlob,6144);}
  checkedCredentials(credentials,now);
  const date=new Date(now).toISOString().replace(/[:-]|\.\d{3}/g,''),day=date.slice(0,8),body=canonical(input);
  assert(Buffer.byteLength(body)<=32768,'KMS_REQUEST_LIMIT');
  const headers={'content-type':'application/x-amz-json-1.1',host:HOST,'x-amz-date':date,
    'x-amz-security-token':credentials.sessionToken,'x-amz-target':'TrentService.'+operation};
  assert(Object.values(headers).every(v=>!/[\r\n]/.test(v)),'KMS_HEADER_ENCODING');
  const names=Object.keys(headers).sort(),canonicalHeaders=names.map(k=>k+':'+headers[k].trim().replace(/\s+/g,' ')+'\n').join('');
  const signedHeaders=names.join(';'),canonicalRequest=['POST','/','',canonicalHeaders,signedHeaders,sha256(body)].join('\n');
  const scope=day+'/'+KEY_REGION+'/kms/aws4_request',toSign=['AWS4-HMAC-SHA256',date,scope,sha256(canonicalRequest)].join('\n');
  const kDate=hmac('AWS4'+credentials.secretAccessKey,day),kRegion=hmac(kDate,KEY_REGION),kService=hmac(kRegion,'kms'),kSigning=hmac(kService,'aws4_request');
  try{headers.authorization='AWS4-HMAC-SHA256 Credential='+credentials.accessKeyId+'/'+scope+', SignedHeaders='+signedHeaders+', Signature='+hmac(kSigning,toSign).toString('hex');}
  finally{for(const key of [kDate,kRegion,kService,kSigning])key.fill(0);}
  return {hostname:HOST,port:443,path:'/',method:'POST',headers:{...headers,'content-length':String(Buffer.byteLength(body))},body};
}
export function createKmsTransport({credentials,now=Date.now,request=httpsRequest,agent}){
  assert.equal(typeof credentials,'function','KMS_CREDENTIAL_PROVIDER_REQUIRED');
  return async(operation,input)=>{
    const signed=signedKmsRequest(operation,input,await credentials(),now());
    return new Promise((resolve,reject)=>{
      let done=false,size=0,timer;const chunks=[];
      const finish=(error,value)=>{if(done)return;done=true;clearTimeout(timer);if(error)reject(error);else resolve(value);};
      // agent may bridge raw TCP through a measured vsock adapter; HTTPS still
      // authenticates this fixed AWS hostname inside the enclave process.
      const req=request({...signed,body:undefined,agent,servername:HOST,rejectUnauthorized:true,minVersion:'TLSv1.2'},res=>{
        res.on('data',chunk=>{size+=chunk.length;if(size>32768){req.destroy();finish(Error('KMS_RESPONSE_LIMIT'));}else chunks.push(chunk);});
        res.on('error',()=>finish(Error('KMS_RESPONSE_FAILED')));
        res.on('end',()=>{
          try{
            // Never surface the AWS error body, which may echo request context.
            if(res.statusCode!==200){const code=res.statusCode===403?'KMS_ACCESS_DENIED':res.statusCode===429?'KMS_THROTTLED':'KMS_REQUEST_FAILED';throw Error(code);}
            const value=JSON.parse(Buffer.concat(chunks).toString('utf8'));finish(null,value);
          }catch(error){finish(Error(/^KMS_[A-Z_]+$/.test(error.message)?error.message:'KMS_RESPONSE_ENCODING'));}
        });
      });
      timer=setTimeout(()=>{req.destroy();finish(Error('KMS_REQUEST_TIMEOUT'));},10000);
      req.on('error',()=>finish(Error('KMS_NETWORK_UNAVAILABLE')));req.end(signed.body);
    });
  };
}
export const kmsEndpoint=Object.freeze({region:KEY_REGION,hostname:HOST,port:443,context:CONTEXT});
