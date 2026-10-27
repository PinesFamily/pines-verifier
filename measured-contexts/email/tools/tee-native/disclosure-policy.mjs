// Resource/disclosure policy is signed in the admission ticket. It is separate
// from identity/schema versions: changing it must never rotate a subject key.
import {check, exact} from './wire.mjs';

export const REDACTED_RESPONSE = Object.freeze({version:1,id:'redacted-response-v1',
  response:'selective',resourceClass:'redacted-max-v1',maxSentBytes:8192,maxRecvBytes:65536,
  maxSentRecords:1024,maxRecvRecords:1024,maxSentRanges:64});
export const FULL_RESPONSE = Object.freeze({version:1,id:'full-response-v1',
  response:'complete',resourceClass:'full-response-v1',maxSentBytes:8192,maxRecvBytes:65536,
  maxSentRecords:32,maxRecvRecords:1024,maxSentRanges:64});
// Every response header value except the framing is hidden, and the body is requested
// as gzip, so the revealed bytes that need zero-knowledge authentication stay small.
// maxRecvRecords 64 is deliberate and not yet measured at these sizes: the total
// relayed records (handshake, application and close) are what fixture174 showed matter.
export const PRIVATE_HEADERS = Object.freeze({version:1,id:'private-headers-gzip-v1',
  response:'private-headers',resourceClass:'private-headers-gzip-v1',maxSentBytes:8192,maxRecvBytes:8192,
  maxSentRecords:32,maxRecvRecords:64,maxSentRanges:64});
// A separate opt-in class keeps the live provider set and its pins immutable.
// Same native resource limits; the new schema hides exact UA and clearance.
export const GROK_CLEARANCE = Object.freeze({...PRIVATE_HEADERS,
  id:'grok-clearance-private-v1',resourceClass:'grok-clearance-private-v1'});
// The sybil-facts generation's class (multi-exchange protocol §2.6, owner D4 2026-10-20): every response byte is revealed
// to the measured enclave, as under full-response-v1 (TLSNotary's reveal-all path, ~85 MiB flat measured 2026-10-05;
// no response value is hidden, so no revealed byte needs a circuit), and the request keeps hiding its credential
// headers exactly as today. The receipt still carries only the schema's fields. Sized for the captured sessions
// (qualified provider captures): ChatGPT usage 1,101 + history 7,289 raw, Claude per-org ~3.5 KB + account
// 35,926 raw, Grok 1,134 + 820 raw, plus response headers; the session-measured 65,536-byte bound is a 1.5x margin
// over the largest and the per-message schema caps bound each response.
export const FACTS_COMPLETE = Object.freeze({version:1,id:'facts-complete-v1',
  response:'complete',resourceClass:'facts-complete-v1',maxSentBytes:8192,maxRecvBytes:65536,
  maxSentRecords:32,maxRecvRecords:1024,maxSentRanges:64});
// Grok's two-exchange email companion keeps its own measured admission class.
export const GROK_EMAIL = Object.freeze({...FACTS_COMPLETE,
  id:'grok-email-complete-v1',resourceClass:'grok-email-complete-v1'});
export const DISCLOSURE_POLICIES = Object.freeze([REDACTED_RESPONSE,FULL_RESPONSE,PRIVATE_HEADERS,FACTS_COMPLETE,GROK_CLEARANCE,GROK_EMAIL]);
// A boot is frozen on ONE resource class (capacity-policy.mjs). This names the single
// disclosure policy that class serves, so the tooling that prepares a boot, builds its
// extension and judges its tickets all derive the policy from the class and never guess.
export function disclosurePolicyForClass(resourceClass) {
  const policy=DISCLOSURE_POLICIES.find(policy=>policy.resourceClass===resourceClass);
  check(policy,'RESOURCE_CLASS');return policy;
}

// Per-class caps that are not part of the signed wire shape, because the two existing
// policy objects must stay byte-identical. Mirrored in apps/tlsn-verifier/src/
// disclosure_policy.rs, which enforces them before accept() allocates any circuit;
// a test asserts the two tables agree. Revealed bytes, not total bytes, are the cost.
export const REVEAL_CAPS = Object.freeze({
  'grok-clearance-private-v1': Object.freeze({maxRevealedRecvBytes:4096,maxRevealedSentBytes:1024,
    maxRecvRanges:33,maxHiddenRecvRanges:32}),
  'private-headers-gzip-v1': Object.freeze({maxRevealedRecvBytes:4096,maxRevealedSentBytes:1024,
    // At most 32 hidden header values, so at most 33 revealed runs around them.
    maxRecvRanges:33,maxHiddenRecvRanges:32}),
});

export function disclosurePolicy(value=REDACTED_RESPONSE) {
  if (typeof value==='string') value=DISCLOSURE_POLICIES.find(policy=>policy.id===value);
  check(value && typeof value==='object','DISCLOSURE_POLICY');
  exact(value,Object.keys(REDACTED_RESPONSE));
  const policy=DISCLOSURE_POLICIES.find(policy=>Object.keys(policy).every(key=>policy[key]===value[key]));
  check(policy,'DISCLOSURE_POLICY');return policy;
}

export function disclosurePolicyFromEnv(env) {
  // This candidate reveals complete responses unless the private-headers policy is
  // named explicitly. Legacy redacted policy remains explicit in rollback/test
  // tooling; it cannot start a serving API.
  const policy=disclosurePolicy(env.TLSN_TEE_DISCLOSURE_POLICY??FULL_RESPONSE.id);
  check(policy===FULL_RESPONSE||policy===PRIVATE_HEADERS||policy===FACTS_COMPLETE||policy===GROK_CLEARANCE||policy===GROK_EMAIL,'FULL_RESPONSE_REQUIRED');
  return policy;
}

const revealedBytes=ranges=>ranges.reduce((total,range)=>total+range.end-range.start,0);

export function checkDisclosureRanges(policy,sent,recv,sentRanges,recvRanges) {
  policy=disclosurePolicy(policy);
  check(sent>0&&sent<=policy.maxSentBytes&&recv>0&&recv<=policy.maxRecvBytes,'DISCLOSURE_LIMIT');
  const ordered=(ranges,length,maximum)=>Array.isArray(ranges)&&ranges.length>0&&ranges.length<=maximum&&ranges.every((range,index)=>
    range&&Number.isSafeInteger(range.start)&&Number.isSafeInteger(range.end)&&range.start>=0&&range.start<range.end&&range.end<=length&&(!index||ranges[index-1].end<range.start));
  check(ordered(sentRanges,sent,policy.maxSentRanges),'DISCLOSURE_REQUEST_RANGES');
  if(policy.response==='complete')check(Array.isArray(recvRanges)&&recvRanges.length===1&&recvRanges[0]?.start===0&&recvRanges[0]?.end===recv,'FULL_RESPONSE_REQUIRED');
  const caps=REVEAL_CAPS[policy.resourceClass];
  if(caps){
    // The same bound apps/tlsn-verifier enforces before accept(). This mirror is for
    // the browser's planner and the enclave's evaluator; it is never the only check.
    check(ordered(recvRanges,recv,caps.maxRecvRanges),'DISCLOSURE_RESPONSE_RANGES');
    check(revealedBytes(recvRanges)<=caps.maxRevealedRecvBytes,'DISCLOSURE_REVEAL_LIMIT');
    check(revealedBytes(sentRanges)<=caps.maxRevealedSentBytes,'DISCLOSURE_REVEAL_LIMIT');
  }
}
