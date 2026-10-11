// Fixed Sydney key scope and canonical configuration for the v2 candidate.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';

export const ACCOUNT='594194277294';
export const KEY_REGION='ap-southeast-2';
export const EXISTING_KEY_ARN='arn:aws:kms:ap-southeast-2:594194277294:key/3d63a788-0acf-42c1-b20c-1c3bdd9e2375';
export const PLANNED_REGIONS=Object.freeze(['ap-southeast-2']);
export const DEFERRED_REGIONS=Object.freeze(['us-east-1','ap-southeast-1','eu-central-1']);
export const PURPOSE='pines-keyed-pseudonym-v2';
export const CONTEXT=Object.freeze({Application:'Pines',Purpose:PURPOSE,IdentityGeneration:'v2'});
export const PCR=/^[a-f0-9]{96}$/;
export const HASH=/^[a-f0-9]{64}$/;
export const KEY_ARN=new RegExp('^arn:aws:kms:'+KEY_REGION+':'+ACCOUNT+':key/[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$');
export const ROLE_ARN=new RegExp('^arn:aws:iam::'+ACCOUNT+':role/[A-Za-z0-9+=,.@_/-]{1,128}$');
export const sha256=value=>createHash('sha256').update(value).digest('hex');
export const rolePcr=role=>createHash('sha384').update(Buffer.alloc(48)).update(role).digest('hex');
export function exact(value,keys,code='KMS_CONFIGURATION_FIELDS'){
  assert(value&&typeof value==='object'&&!Array.isArray(value),code);
  assert.deepEqual(Object.keys(value).sort(),[...keys].sort(),code);
}
export function canonical(value){
  if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
  if(value&&typeof value==='object')return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
  return JSON.stringify(value);
}
export function checkedContext(value){assert.equal(canonical(value),canonical(CONTEXT),'KMS_ENCRYPTION_CONTEXT');return {...CONTEXT};}
export function validateKeyConfiguration(input,{creation=false}={}){
  exact(input,['version','purpose','account','keyRegion','keyArn','ownerRoleArn','bootstrapRoleArn','runtimeRoleArns','pcrTuples','bootstrapWindow']);
  assert.equal(input.version,1);assert.equal(input.purpose,PURPOSE);assert.equal(input.account,ACCOUNT);
  assert.equal(input.keyRegion,KEY_REGION,'PERMANENT_KEY_REGION');
  assert((creation&&input.keyArn===null)||KEY_ARN.test(input.keyArn),'EXACT_KMS_KEY_ARN_REQUIRED');
  for(const role of [input.ownerRoleArn,input.bootstrapRoleArn])assert(ROLE_ARN.test(role),'OWNER_AND_BOOTSTRAP_ROLES_REQUIRED');
  assert(Array.isArray(input.runtimeRoleArns)&&input.runtimeRoleArns.length>0&&input.runtimeRoleArns.length<=6,'RUNTIME_ROLES_REQUIRED');
  const roles=[input.ownerRoleArn,input.bootstrapRoleArn,...input.runtimeRoleArns];
  assert(roles.every(role=>ROLE_ARN.test(role))&&new Set(roles).size===roles.length,'SEPARATE_KMS_AUTHORITIES_REQUIRED');
  assert(Array.isArray(input.pcrTuples)&&input.pcrTuples.length>0&&input.pcrTuples.length<=4,'APPROVED_PCR_TUPLES_REQUIRED');
  assert(input.pcrTuples.every(tuple=>Array.isArray(tuple)&&tuple.length===3&&tuple.every(p=>PCR.test(p)&&p!=='0'.repeat(96))),'NONDEBUG_PCR_TUPLES_REQUIRED');
  // A PCR0 identifies one complete measured image. This also lets explicit Deny
  // statements reject mixed tuples even if another IAM policy tries to allow them.
  assert.equal(new Set(input.pcrTuples.map(t=>t[0])).size,input.pcrTuples.length,'AMBIGUOUS_PCR0_TUPLE');
  exact(input.bootstrapWindow,['startsAt','endsAt']);
  const {startsAt,endsAt}=input.bootstrapWindow;
  assert(Number.isSafeInteger(startsAt)&&Number.isSafeInteger(endsAt)&&startsAt>0&&endsAt>startsAt&&endsAt-startsAt<=3600000,'BOUNDED_BOOTSTRAP_WINDOW');
  return JSON.parse(canonical(input));
}
export function pendingKeyInputs(value){
  return ['keyArn','ownerRoleArn','bootstrapRoleArn','runtimeRoleArns','pcrTuples','bootstrapWindow'].filter(k=>value?.[k]===null||value?.[k]===undefined||Array.isArray(value[k])&&!value[k].length);
}
