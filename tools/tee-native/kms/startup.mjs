// Measured Sydney startup requires a signed external configuration and a fresh
// NSM Recipient document. Runtime boots decrypt the one pinned wrapped key;
// bootstrap is separately fenced and never opens proof admission.
import assert from 'node:assert/strict';
import {bootstrapWrappedKey,decryptPinnedKey} from './lifecycle.mjs';
import {createKmsTransport} from './transport.mjs';
import {createKmsVsockAgent} from './vsock-agent.mjs';
import {createParentChannel} from './parent-channel.mjs';
import {createMeasuredRecipientIssuer} from './issuer.mjs';
import {validateStartupDeployment,validateIdentityTrust,checkStartupDocument,identityBinding} from './deployment.mjs';
import {sha256} from './config.mjs';

export const KEYED_IDENTITY_OFF=Object.freeze({enabled:false,ready:false,identityEnabled:false});

// The sole measured entry. The untrusted parent supplies the signed document;
// the image pins its authority. Genuine Recipient attestation below verifies
// that its external PCR/role tuple matches this actual boot before any key use.
export async function startMeasuredIdentity({trust,channel,now=Date.now,...options}){
  const pinned=validateIdentityTrust(trust),parent=channel??createParentChannel({now});
  const deployment=await checkStartupDocument(await parent.configuration(),pinned,now());
  if(deployment.mode==='bootstrap')return {bootstrap:true,result:await bootstrapKeyedIdentity({deployment,channel:parent,now,...options})};
  const started=await startKeyedIdentity({deployment,channel:parent,now,...options});
  const identity=identityBinding(deployment,pinned);
  return Object.freeze({...started,get ready(){return started.ready;},identity,health:Object.freeze({...started.health,identity})});
}

function dependencies({deployment,issueQuote,channel,agent,now,verifyQuote,recipientFactory,onTimestamp}){
  const value=validateStartupDeployment(deployment);
  const parent=channel??createParentChannel({bridge:value.handoffBridge,now});
  const owned=agent===undefined?createKmsVsockAgent({bridge:value.kmsBridge}):undefined;
  return {value,parent,owned,now,
    attestation:{issueQuote:issueQuote??createMeasuredRecipientIssuer({onTimestamp}),
      ...(verifyQuote?{verifyQuote}:{}),...(recipientFactory?{recipientFactory}:{})},
    transport:credentials=>createKmsTransport({credentials:async()=>credentials,now,agent:agent??owned})};
}
/**
 * Resolves to a frozen handle whose `digest` is the only way the key is used.
 * `health` deliberately carries no account identifier, role or key ARN.
 */
export async function startKeyedIdentity(options={}){
  const {deployment}=options;
  if(deployment===undefined||deployment===null)return KEYED_IDENTITY_OFF;
  const {value,parent,owned,now,attestation,transport}=dependencies({now:Date.now,...options,deployment});
  // A bootstrap document must never boot a worker: generation is a separate,
  // reviewed, one-time operation under its own window and role.
  assert.equal(value.mode,'boot','KMS_STARTUP_MODE');
  try{
    const {credentials,wrapped}=await parent.handoff(value.pins);
    const handle=await decryptPinnedKey({config:value.keyConfiguration,roleArn:value.roleArn,
      record:wrapped,pins:value.pins,kms:transport(credentials),now,...attestation});
    return Object.freeze({enabled:true,get ready(){return handle.ready;},identityEnabled:true,handle,
      wrappedSha256:handle.wrappedSha256,attestationSha256:handle.attestation.sha256,
      health:Object.freeze({enabled:true,ready:true,identityEnabled:true,
        wrappedSha256:handle.wrappedSha256,attestationSha256:handle.attestation.sha256}),
      destroy(){handle.destroy();}});
  }finally{owned?.destroy();}
}
/**
 * The one reviewed attested `GenerateDataKey`. It is never part of a worker boot:
 * the caller is an operator-run measured process inside the bootstrap window.
 * Durability and the once-only fence belong to the parent, because an enclave
 * filesystem does not survive a reboot.
 */
export async function bootstrapKeyedIdentity(options={}){
  const {deployment}=options;
  const {value,parent,owned,now,attestation,transport}=dependencies({now:Date.now,...options,deployment});
  assert.equal(value.mode,'bootstrap','KMS_STARTUP_MODE');
  try{
    const {credentials}=await parent.handoff(null);
    const result=await bootstrapWrappedKey({config:value.keyConfiguration,store:parent,
      kms:transport(credentials),now,...attestation});
    // A durable wrapped record is a candidate, not an approved identity key. The
    // owner selects one, verifies independent backups and pins this digest.
    return Object.freeze({...result,candidatePin:Object.freeze({keyArn:result.wrapped.keyArn,
      ciphertextSha256:result.wrapped.ciphertextSha256}),
      deploymentSha256:sha256(JSON.stringify(value)),identityEnabled:false,requiresOwnerPin:true});
  }finally{owned?.destroy();}
}
