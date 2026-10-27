// Offline validation and rendering. Measured inputs pin the existing Sydney
// key and configuration authority; signed external startup supplies final PCRs.
import assert from 'node:assert/strict';
import {KEY_REGION,EXISTING_KEY_ARN,PURPOSE,HASH,KEY_ARN,canonical,exact,pendingKeyInputs,sha256,validateKeyConfiguration} from './config.mjs';
import {sign,verify} from '../wire.mjs';
import {RECIPIENT_ATTEST_MODE,RECIPIENT_BINARY} from './issuer.mjs';
import {KMS_BRIDGE,KMS_HANDOFF_BRIDGE,checkedBridge} from './vsock-agent.mjs';
import {PATHS} from './parent-channel.mjs';

export const STARTUP_FORMAT='pines-kms-enclave-startup-v1';
export const REVIEW_FORMAT='pines-kms-enclave-startup-review-v1';
export const MODES=Object.freeze(['boot','bootstrap']);
export const TRUST_FORMAT='pines-sydney-identity-trust-v2';
export const STARTUP_DOMAIN='pines/sydney-identity-startup/v2';
// Measured BEFORE the final PCR tuple exists. No PCR, wrapped pin, role, timing
// or capacity setting is allowed here: they belong to the signed external input.
export function validateIdentityTrust(value){
  exact(value,['format','keyArn','configurationAuthority']);
  assert.equal(value.format,TRUST_FORMAT,'KMS_IDENTITY_TRUST');
  assert.equal(value.keyArn,EXISTING_KEY_ARN,'EXACT_KMS_KEY_ARN_REQUIRED');
  assert(HASH.test(value.configurationAuthority),'KMS_CONFIGURATION_AUTHORITY');
  return Object.freeze({...value});
}
export async function signStartupDocument(deployment,key,{issuedAt=Date.now(),expiresAt}={}){
  const body={deployment:validateStartupDeployment(deployment),issuedAt,expiresAt};
  checkStartupTime(body,issuedAt);
  return sign(STARTUP_DOMAIN,body,key);
}
function checkStartupTime(body,now){
  exact(body,['deployment','issuedAt','expiresAt']);
  assert(Number.isSafeInteger(body.issuedAt)&&Number.isSafeInteger(body.expiresAt)
    &&body.issuedAt<=now+2000&&now<body.expiresAt&&body.expiresAt>body.issuedAt
    &&body.expiresAt-body.issuedAt<=3*24*3600000,'KMS_STARTUP_EXPIRED');
}
export async function checkStartupDocument(document,trust,now=Date.now()){
  const pinned=validateIdentityTrust(trust);
  const body=await verify(STARTUP_DOMAIN,document,pinned.configurationAuthority);checkStartupTime(body,now);
  const deployment=validateStartupDeployment(body.deployment);
  assert.equal(deployment.keyConfiguration.keyArn,pinned.keyArn,'KMS_KEY_SCOPE');
  return deployment;
}
export function identityBinding(deployment,trust){
  const d=validateStartupDeployment(deployment),t=validateIdentityTrust(trust);
  assert.equal(d.mode,'boot','KMS_STARTUP_MODE');assert.equal(d.keyConfiguration.keyArn,t.keyArn,'KMS_KEY_SCOPE');
  const identity={generation:'v2',protocol:'pines-keyed-receipt-v2',keyArn:t.keyArn,wrappedSha256:d.pins.ciphertextSha256,
    configurationAuthority:t.configurationAuthority};
  return Object.freeze({...identity,configurationSha256:sha256(canonical(identity))});
}
const FIELDS=['version','format','mode','identityGeneration','keyConfiguration','roleArn','pins','kmsBridge','handoffBridge'];

export function validateStartupDeployment(input){
  exact(input,FIELDS,'KMS_STARTUP_FIELDS');
  assert.equal(input.version,1);assert.equal(input.format,STARTUP_FORMAT,'KMS_STARTUP_FORMAT');
  assert(MODES.includes(input.mode),'KMS_STARTUP_MODE');
  assert.equal(input.identityGeneration,'v2','KMS_IDENTITY_GENERATION');
  const key=validateKeyConfiguration(input.keyConfiguration);
  assert.equal(key.purpose,PURPOSE);assert.equal(key.keyRegion,KEY_REGION,'PERMANENT_KEY_REGION');
  // One role per deployment: a boot image may not hold bootstrap authority, and
  // the reviewed bootstrap process is not a runtime worker.
  if(input.mode==='bootstrap'){
    assert.equal(input.roleArn,key.bootstrapRoleArn,'KMS_ROLE_SCOPE');
    assert.equal(input.pins,null,'KMS_BOOTSTRAP_HAS_NO_PIN');
  }else{
    assert(key.runtimeRoleArns.includes(input.roleArn)&&input.roleArn!==key.bootstrapRoleArn,'KMS_ROLE_SCOPE');
    exact(input.pins,['keyArn','ciphertextSha256'],'KMS_WRAPPED_PIN_REQUIRED');
    assert(KEY_ARN.test(input.pins.keyArn)&&HASH.test(input.pins.ciphertextSha256),'KMS_WRAPPED_PIN_REQUIRED');
    assert.equal(input.pins.keyArn,key.keyArn,'KMS_KEY_SCOPE');
  }
  const kmsBridge=checkedBridge(input.kmsBridge),handoffBridge=checkedBridge(input.handoffBridge);
  assert.equal(kmsBridge.port,KMS_BRIDGE.port,'KMS_BRIDGE_SCOPE');
  assert.equal(handoffBridge.port,KMS_HANDOFF_BRIDGE.port,'KMS_BRIDGE_SCOPE');
  return JSON.parse(canonical({...input,keyConfiguration:key,kmsBridge,handoffBridge}));
}
export function pendingStartupInputs(value){
  const missing=['mode','roleArn','pins','keyConfiguration'].filter(field=>
    value?.[field]===null||value?.[field]===undefined);
  // `pins` is legitimately absent for the one reviewed bootstrap document.
  const resolved=value?.mode==='bootstrap'?missing.filter(field=>field!=='pins'):missing;
  return [...resolved,...pendingKeyInputs(value?.keyConfiguration).map(field=>'keyConfiguration.'+field)].sort();
}
/** Everything a future measured image must carry, and nothing it must not. */
export function renderStartupDeployment(input){
  const value=validateStartupDeployment(input),key=value.keyConfiguration;
  return {format:REVIEW_FORMAT,executed:false,identityEnabled:false,hardwareQualified:false,
    keyRegion:KEY_REGION,keyArn:key.keyArn,mode:value.mode,roleArn:value.roleArn,pins:value.pins,
    externalStartup:value,externalStartupSha256:sha256(canonical(value)),
    measuredSource:{attestMode:RECIPIENT_ATTEST_MODE,runtimeBinary:RECIPIENT_BINARY,
      kmsEgressMode:'enclave-kms-egress',handoffMode:'enclave-kms-handoff',handoffPaths:{...PATHS}},
    reviewRequired:['Validate final PCRs against both sealed builds',
      'Authorize only exact Recipient PCR and role conditions on the existing Sydney key',
      'Bootstrap once under the bounded window; preserve the exclusive fence',
      'Verify two backups of the same wrapped ciphertext before runtime boots',
      'Sign this external document with the measured configuration authority',
      'Real NSM, KMS, provider and capacity qualification remain required']};
}
