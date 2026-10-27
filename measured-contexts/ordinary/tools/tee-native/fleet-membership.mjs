// Measured per-boot identity. Membership quotes never enter the proof/preflight slot.
import {check, exact, sign, verify, signingKey, publicKey, digest, encode, unhex} from './wire.mjs';
import {validateResourcePolicy,membershipContext} from './capacity-policy.mjs';

export const MEMBERSHIP_CHALLENGE_DOMAIN = 'pines/tee/membership-challenge/v1';
export const MEMBERSHIP_HEALTH_DOMAIN = 'pines/tee/membership-health/v1';
// A selected boot also names the digest of the controller document it froze.
const SELECTION_HASH=/^[a-f0-9]{64}$/;
export const membershipIdentity = body => ({workerId:body.workerId,bootId:body.bootId,bootKey:body.bootKey,contextHash:body.contextHash,
  ...(body.resourcePolicy?{resourcePolicy:validateResourcePolicy(body.resourcePolicy)}:{}),
  ...(body.capacitySelectionHash!==undefined?{capacitySelectionHash:body.capacitySelectionHash}:{})});
export async function membershipQuoteBinding(challenge, identity) {
  return {publicKey:unhex(identity.bootKey,32),nonce:unhex(await digest(encode(challenge)),32),userData:unhex(await digest(encode(identity)),32)};
}

export async function createFleetMembership({workerId,bootId,context,resourcePolicy,capacitySelectionHash,controllerKey,issueQuote,clockCheck=async()=>{},now=Date.now}) {
  unhex(controllerKey,32);unhex(bootId,32);
  check(capacitySelectionHash===undefined||resourcePolicy&&SELECTION_HASH.test(capacitySelectionHash),'MEMBERSHIP_IDENTITY');
  const key=await signingKey(),identity=Object.freeze({workerId,bootId,bootKey:await publicKey(key.publicKey),contextHash:await digest(encode(membershipContext(context,resourcePolicy))),
    ...(resourcePolicy?{resourcePolicy:validateResourcePolicy(resourcePolicy)}:{}),...(capacitySelectionHash?{capacitySelectionHash}:{})});
  const seen=new Map();let pending=false;
  return async (challenge,health) => {
    check(!pending,'MEMBERSHIP_BUSY');pending=true;
    try {
      const body=await verify(MEMBERSHIP_CHALLENGE_DOMAIN,challenge,controllerKey);
      exact(body,['kind','nodeId','nonce','issuedAt','expiresAt']);
      check(['enroll','heartbeat'].includes(body.kind) && typeof body.nodeId==='string' && /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(body.nodeId),'MEMBERSHIP_CHALLENGE');
      unhex(body.nonce,32);
      const at=now();check(Number.isSafeInteger(body.issuedAt)&&Number.isSafeInteger(body.expiresAt)&&body.issuedAt<=at+2000
        &&body.issuedAt>=at-10000&&body.expiresAt>at&&body.expiresAt<=body.issuedAt+10000,'MEMBERSHIP_STALE');
      for(const [nonce,expiry] of seen)if(expiry<=at)seen.delete(nonce);
      check(!seen.has(body.nonce)&&seen.size<256,'MEMBERSHIP_REPLAY');seen.set(body.nonce,body.expiresAt);
      await clockCheck();
      const quote=body.kind==='enroll'?await issueQuote(await membershipQuoteBinding(challenge,identity)):null;
      const heartbeat=await sign(MEMBERSHIP_HEALTH_DOMAIN,{...identity,challengeHash:await digest(encode(challenge)),issuedAt:now(),
        sessions:health.sessions,preflights:health.preflights,outbox:health.outbox,draining:health.draining},key.privateKey);
      return {heartbeat,quote};
    } finally {pending=false;}
  };
}

/** Checks an attested-key heartbeat. AWS membership and quote trust are controller responsibilities. */
export async function checkMembershipHeartbeat(reply,challenge,expected,now=Date.now()) {
  exact(reply,['heartbeat','quote']);
  const body=reply.heartbeat?.body;
  exact(body,['workerId','bootId','bootKey','contextHash','challengeHash','issuedAt','sessions','preflights','outbox','draining',
    ...(Object.hasOwn(body,'resourcePolicy')?['resourcePolicy']:[]),...(Object.hasOwn(body,'capacitySelectionHash')?['capacitySelectionHash']:[])]);
  if(Object.hasOwn(body,'resourcePolicy'))validateResourcePolicy(body.resourcePolicy);
  if(Object.hasOwn(body,'capacitySelectionHash'))check(Object.hasOwn(body,'resourcePolicy')&&typeof body.capacitySelectionHash==='string'
    &&SELECTION_HASH.test(body.capacitySelectionHash),'MEMBERSHIP_IDENTITY');
  check(typeof body.workerId==='string'&&/^[a-z0-9][a-z0-9-]{1,63}$/.test(body.workerId),'MEMBERSHIP_IDENTITY');
  unhex(body.bootId,32);unhex(body.bootKey,32);unhex(body.contextHash,32);
  await verify(MEMBERSHIP_HEALTH_DOMAIN,reply.heartbeat,body.bootKey);
  check(body.challengeHash===await digest(encode(challenge))&&Number.isSafeInteger(body.issuedAt)
    &&body.issuedAt>=challenge.body.issuedAt-2000&&body.issuedAt<=now+2000&&now<challenge.body.expiresAt,'MEMBERSHIP_STALE');
  check(['sessions','preflights','outbox'].every(k=>Number.isSafeInteger(body[k])&&body[k]>=0&&body[k]<=128)
    &&typeof body.draining==='boolean','MEMBERSHIP_HEALTH');
  if(expected)check(Object.entries(expected).every(([k,v])=>Buffer.from(encode(body[k])).equals(Buffer.from(encode(v)))),'MEMBERSHIP_BOOT_CHANGED');
  return body;
}
