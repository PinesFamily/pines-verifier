import {check, decode, digest, encode, exact, lp, publicKey, random, sign, signingKey, unhex, verify} from './wire.mjs';
import {channelKey, exportChannelKey, SUITE} from './channel.mjs';
import {CONTEXT, TIMES} from './hardware/context.mjs';
import {verifyNitroQuote, quoteBinding} from './nitro.mjs';
// Every provider lookup below resolves under the policy that was SIGNED, never a module
// default: `providerForTicket` reads it from the ticket body it is given, and the two
// lookups that have no ticket yet are passed the attempt's or the configuration's.
// The profile strings are shared between the disclosure classes, so only the schema
// digest distinguishes them, and a lookup that ignored the policy would silently answer
// with the other class's schema and inventory.
import {LIMITS, schema, SIMULATION, providersFor, isHardwareProfile, providerForSchema, providerForTicket, validatePublicPlan} from './profile.mjs';
import {SESSION_POLICY_FIELDS, validateSessionPolicySnapshot} from './session-policy.mjs';
import {disclosurePolicy} from './disclosure-policy.mjs';
import {checkIdentityBinding} from './identity-binding.mjs';

export const DOMAIN = Object.freeze({ticket: 'pines/tee/ticket/v1', grant: 'pines/tee/grant/v1', receipt: 'pines/tee/receipt/v1', lifecycle: 'pines/tee/lifecycle/v1', simulation: 'pines/tee/SIMULATION-NOT-ATTESTATION/v1'});
export const schemaDigest = (profile = SIMULATION, selectedPolicy) => {
  const provider = providersFor(selectedPolicy).find(p => p.profile === profile);
  check(provider || profile === SIMULATION, 'PROFILE');
  return digest(encode(provider?.schema ?? schema));
};
export const envelopeDigest = envelope => digest(encode(envelope));

const PARENT_FIELDS = ['nodeId', 'parentPcr3', 'parentPcr4'];
function parentBinding(value) {
  if (PARENT_FIELDS.every(key => !Object.hasOwn(value, key))) return {};
  check(typeof value.nodeId === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(value.nodeId), 'PARENT_MEMBERSHIP');
  for (const key of ['parentPcr3', 'parentPcr4']) {
    const pcr = unhex(value[key], 48); check(pcr.some(byte => byte !== 0), 'PARENT_MEMBERSHIP');
  }
  return Object.fromEntries(PARENT_FIELDS.map(key => [key, value[key]]));
}

export async function issueTicket(clientKey, browserNonce, key, now = Date.now()) {
  const body = {profile: SIMULATION, mode: 'Proxy', attempt: random(), wallet: '0x' + '12'.repeat(20),
    application: 'pines-local-nonclaimable', chain: 4663, schemaDigest: await schemaDigest(), clientKey,
    browserNonce, apiNonce: random(), issuedAt: now, expiresAt: now + 60000, resultExpiresAt: now + 180000, limits: LIMITS};
  return sign(DOMAIN.ticket, body, key);
}

export async function issueHardwareTicket(attempt, clientKey, browserNonce, key, now = Date.now()) {
  const provider = providerForSchema(attempt.schema, attempt.disclosurePolicy); check(provider, 'SCHEMA_UNAVAILABLE');
  const timing = validateSessionPolicySnapshot(attempt, attempt.issuedAt);
  const body = {profile: provider.profile, mode: 'Proxy', attempt: attempt.attemptId, wallet: attempt.recipient,
    ...CONTEXT, workerId: attempt.workerId, bootId: attempt.bootId, schemaDigest: await schemaDigest(provider.profile, attempt.disclosurePolicy), clientKey, browserNonce, apiNonce: random(),
    issuedAt: attempt.issuedAt, expiresAt: attempt.expiresAt, resultExpiresAt: attempt.issuedAt + TIMES.deliveryMs, limits: LIMITS, ...timing, ...parentBinding(attempt),
    // Signed exact policy object; an attempt without one keeps the legacy redacted ticket.
    ...(attempt.disclosurePolicy===undefined?{}:{disclosurePolicy:disclosurePolicy(attempt.disclosurePolicy)})};
  check(body.expiresAt > now, 'TICKET_EXPIRED');
  return sign(DOMAIN.ticket, body, key);
}

export async function checkTicket(ticket, key, profile, now = Date.now(), {allowLegacy = false} = {}) {
  const t = await verify(DOMAIN.ticket, ticket, key);
  const hardware = isHardwareProfile(profile);
  const timing = validateSessionPolicySnapshot(t, t.issuedAt, {allowLegacy: allowLegacy || !hardware});
  const parent = hardware ? parentBinding(t) : {};
  const disclosure = Object.hasOwn(t, 'disclosurePolicy');
  // Object form only: the API signs the policy object, and a bare id would widen what a signed ticket may carry (review R-PH-5).
  if (disclosure) {check(hardware && typeof t.disclosurePolicy === 'object' && t.disclosurePolicy !== null, 'DISCLOSURE_POLICY'); disclosurePolicy(t.disclosurePolicy);}
  exact(t, ['profile', 'mode', 'attempt', 'wallet', 'application', 'chain', 'schemaDigest', 'clientKey', 'browserNonce', 'apiNonce', 'issuedAt', 'expiresAt', 'resultExpiresAt', 'limits', ...(timing ? SESSION_POLICY_FIELDS : []), ...Object.keys(parent), ...(hardware ? [...Object.keys(CONTEXT).filter(k => !['application','chain'].includes(k)), 'workerId', 'bootId'] : []), ...(disclosure ? ['disclosurePolicy'] : [])]);
  check((hardware || profile === SIMULATION) && t.profile === profile && t.mode === 'Proxy', 'PROFILE');
  check(t.application === (hardware ? CONTEXT.application : 'pines-local-nonclaimable') && t.chain === 4663 && /^0x[0-9a-f]{40}$/.test(t.wallet), 'TICKET_SCOPE');
  if (hardware) check(/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(t.attempt), 'ATTEMPT');
  else unhex(t.attempt, 32);
  for (const key of ['browserNonce', 'apiNonce', 'schemaDigest']) unhex(t[key], 32);
  unhex(t.clientKey, 65);
  // `t.disclosurePolicy` was validated above, so both of these resolve under the signed
  // class: the digest must be that class's schema, not the other class's for the same profile.
  check((!hardware || providerForTicket(t)) && t.schemaDigest === await schemaDigest(profile, t.disclosurePolicy) && digestEqual(t.limits, LIMITS), 'LIMITS');
  for (const key of ['issuedAt', 'expiresAt', 'resultExpiresAt']) check(Number.isSafeInteger(t[key]), 'TIME');
  check(t.issuedAt <= now + 2000 && t.issuedAt <= t.expiresAt && t.expiresAt - t.issuedAt <= TIMES.admissionMs
    && now < t.expiresAt && t.resultExpiresAt >= t.expiresAt && t.resultExpiresAt - t.issuedAt <= (hardware ? TIMES.deliveryMs : 180000), 'TICKET_EXPIRED');
  if (timing) check(now < timing.sessionExpiresAt && timing.sessionExpiresAt <= t.resultExpiresAt, 'SESSION_DEADLINE');
  if (hardware) {
    check(Object.entries(CONTEXT).every(([k,v]) => t[k] === v), 'DEPLOYMENT_CONTEXT');
    check(typeof t.workerId === 'string' && /^[a-z0-9][a-z0-9-]{1,63}$/.test(t.workerId), 'WORKER_CONTEXT');
    unhex(t.bootId, 32);
  }
  return t;
}
const digestEqual = (a, b) => new TextDecoder().decode(encode(a)) === new TextDecoder().decode(encode(b));

// Simulation issuer is deliberately separate from the Nitro validator. It cannot
// create an AWS quote and is never admitted by a hardware profile.
export async function simulationOffer(ticket, apiKey, simulationKey, measurement, now = Date.now()) {
  await checkTicket(ticket, apiKey, SIMULATION, now);
  const channel = await channelKey(), receipt = await signingKey();
  const body = {profile: SIMULATION, ticketHash: await envelopeDigest(ticket), session: random(),
    channelKey: await exportChannelKey(channel.publicKey), receiptKey: await publicKey(receipt.publicKey),
    suite: SUITE, measurement, issuedAt: now};
  return {offer: {body, evidence: await sign(DOMAIN.simulation, body, simulationKey)}, channel, receipt};
}
export async function checkOffer(offer, ticket, policy, now = Date.now()) {
  exact(offer, ['body', 'evidence']);
  const body = offer.body;
  exact(body, ['profile', 'ticketHash', 'session', 'channelKey', 'receiptKey', 'suite', 'measurement', 'issuedAt', ...(isHardwareProfile(policy.profile) ? ['workerId','bootId'] : []),...(policy.identity?['identity']:[])]);
  if(policy.identity){await checkIdentityBinding(policy.identity);await checkIdentityBinding(body.identity);
    check(digestEqual(body.identity,policy.identity),'IDENTITY_CONFIGURATION');}
  check(policy.profile === ticket.body.profile && body.profile === policy.profile, 'PROFILE');
  check(body.ticketHash === await envelopeDigest(ticket) && body.suite === SUITE, 'OFFER_CONTEXT');
  unhex(body.session, 32); unhex(body.channelKey, 65); unhex(body.receiptKey, 32);
  check(Number.isSafeInteger(body.issuedAt) && body.issuedAt >= ticket.body.issuedAt - 2000
    && body.issuedAt <= now + 2000 && now - body.issuedAt <= 180000, 'QUOTE_STALE');
  check(Array.isArray(policy.measurements) && policy.measurements.includes(body.measurement)
    && body.measurement !== '0'.repeat(96), 'MEASUREMENT');
  if (policy.profile === SIMULATION) {
    check(policy.syntheticOnly === true, 'SIMULATION_REFUSED');
    const verified = await verify(DOMAIN.simulation, offer.evidence, policy.rootKey);
    check(digestEqual(verified, body), 'KEY_BINDING');
  } else {
    check(body.workerId === ticket.body.workerId && body.bootId === ticket.body.bootId, 'WORKER_CONTEXT');
    check(!policy.revokedBootIds?.includes(body.bootId) && !policy.revokedWorkerIds?.includes(body.workerId) && !policy.revokedMeasurements?.includes(body.measurement), 'REVOKED');
    check(isHardwareProfile(policy.profile) && providerForTicket(ticket.body) && policy.admissionEnabled === true && policy.providerQualified === true
      && policy.clockQualified === true && policy.lifecycleQualified === true, 'HARDWARE_PROFILE_UNQUALIFIED');
    exact(offer.evidence, ['cose']);
    const quote = await verifyNitroQuote(unhex(offer.evidence.cose), await quoteBinding(ticket, body), policy, now);
    check(quote.pcrTuple[0] === body.measurement && Math.abs(quote.timestamp - body.issuedAt) <= 2000, 'ATTESTATION_BINDING');
    const parent = parentBinding(ticket.body);
    if (parent.nodeId) check(quote.parentPcr3 === parent.parentPcr3 && quote.parentPcr4 === parent.parentPcr4, 'PARENT_MEMBERSHIP');
  }
  return body;
}

export async function grantBody(ticket, offer, now = Date.now(), {allowLegacy = false} = {}) {
  const timing = validateSessionPolicySnapshot(ticket.body, ticket.body.issuedAt, {allowLegacy: allowLegacy || !isHardwareProfile(ticket.body.profile)});
  return {profile: ticket.body.profile, ticketHash: await envelopeDigest(ticket), offerHash: await envelopeDigest(offer),
    attempt: ticket.body.attempt, session: offer.body.session, issuedAt: now,
    deadline: timing ? timing.sessionExpiresAt : Math.min(now + LIMITS.sessionTimeoutMs, ticket.body.resultExpiresAt), ...(timing ?? {})};
}
export async function checkGrant(grant, ticket, offer, apiKey, now = Date.now(), {allowLegacy = false} = {}) {
  const g = await verify(DOMAIN.grant, grant, apiKey);
  const expected = await grantBody(ticket, offer, g.issuedAt, {allowLegacy});
  exact(g, Object.keys(expected));
  check(digestEqual(g, expected) && Number.isSafeInteger(g.issuedAt) && Number.isSafeInteger(g.deadline)
    && g.issuedAt >= ticket.body.issuedAt && g.issuedAt < ticket.body.expiresAt && g.issuedAt <= now + 2000
    && now < g.deadline, 'GRANT_CONTEXT');
  return g;
}
export const channelBinding = async (ticket, offer, grant) => digest(lp([SUITE, await envelopeDigest(ticket), await envelopeDigest(offer), await envelopeDigest(grant)]));

export async function makeTerminal(ticket, offer, grant, outcome, receipt, key, now = Date.now(), {nativeStarted} = {}) {
  check(['completed', 'cancelled', 'failed'].includes(outcome), 'LIFECYCLE');
  check(nativeStarted === undefined || nativeStarted === false && outcome !== 'completed' && !receipt, 'LIFECYCLE');
  return sign(DOMAIN.lifecycle, {profile: ticket.body.profile, attempt: ticket.body.attempt,
    session: offer.body.session, ticketHash: await envelopeDigest(ticket), grantHash: await envelopeDigest(grant),
    binding: await channelBinding(ticket, offer, grant), outcome, receiptHash: receipt ? await envelopeDigest(receipt) : null, endedAt: now,
    ...(nativeStarted === false ? {nativeStarted: false} : {})}, key);
}
export async function checkTerminal(terminal, ticket, offer, grant, apiKey, policy, now = Date.now()) {
  await checkTicket(ticket, apiKey, policy.profile, Math.min(now, ticket.body.expiresAt - 1), {allowLegacy: true});
  await checkGrant(grant, ticket, offer, apiKey, Math.min(now, grant.body.deadline - 1), {allowLegacy: true});
  await checkOffer(offer, ticket, policy, isHardwareProfile(policy.profile) ? grant.body.issuedAt : now);
  const body = await verify(DOMAIN.lifecycle, terminal, offer.body.receiptKey);
  const unstarted = Object.hasOwn(body, 'nativeStarted');
  exact(body, ['profile','attempt','session','ticketHash','grantHash','binding','outcome','receiptHash','endedAt', ...(unstarted ? ['nativeStarted'] : [])]);
  if (unstarted) check(body.nativeStarted === false && body.outcome !== 'completed' && body.receiptHash === null, 'LIFECYCLE_CONTEXT');
  check(body.profile === ticket.body.profile && body.attempt === ticket.body.attempt && body.session === offer.body.session
    && body.ticketHash === await envelopeDigest(ticket) && body.grantHash === await envelopeDigest(grant)
    && body.binding === await channelBinding(ticket, offer, grant) && ['completed','cancelled','failed'].includes(body.outcome)
    && Number.isSafeInteger(body.endedAt) && body.endedAt >= grant.body.issuedAt && body.endedAt <= now + 2000
    && body.endedAt <= (unstarted ? ticket.body.resultExpiresAt : grant.body.deadline + 5000), 'LIFECYCLE_CONTEXT');
  if (body.outcome === 'completed') unhex(body.receiptHash, 32); else check(body.receiptHash === null, 'LIFECYCLE_CONTEXT');
  return body;
}

export async function makeReceipt(ticket, offer, grant, facts, key, now = Date.now()) {
  return sign(DOMAIN.receipt, (await makeReceiptShape(ticket, offer, grant, {...facts, issuedAt: now})).body, key);
}

export async function checkReceipt(receipt, ticket, offer, grant, apiKey, policy, expectedFacts, now = Date.now()) {
  // Revalidate quote/policy on acceptance, including API acceptance. Never trust a
  // cached boolean or the host's completed response.
  // The signed grant fixes the time when this quote was freshly admitted. Receipt
  // delivery has its own deadline; a 120-second proof need not reuse a fresh offer.
  await checkGrant(grant, ticket, offer, apiKey, Math.min(now, grant.body.deadline - 1), {allowLegacy: true});
  await checkOffer(offer, ticket, policy, isHardwareProfile(policy.profile) ? grant.body.issuedAt : now);
  // A completed, signed receipt may arrive after physical execution ended.
  // Its own signed issuedAt must precede the grant deadline; delivery instead
  // observes resultExpiresAt. This does not authorize new work on an old grant.
  // Ticket signature remains required after the admission expiry; no new admission.
  await checkTicket(ticket, apiKey, policy.profile, Math.min(now, ticket.body.expiresAt - 1), {allowLegacy: true});
  const r = await verify(DOMAIN.receipt, receipt, offer.body.receiptKey);
  exact(r, ['profile', 'mode', 'attempt', 'wallet', 'application', 'chain', 'schemaDigest', 'session', 'binding',
    'ticketHash', 'grantHash', 'measurement', 'issuedAt', 'expiresAt', 'host', 'endpoint', 'pseudonym', 'plan', 'sentBytes', 'recvBytes',...(offer.body.identity?['identity']:[])]);
  const expected = (await makeReceiptShape(ticket, offer, grant, r)).body;
  check(digestEqual(r, expected), 'RECEIPT_CONTEXT');
  unhex(r.pseudonym, 32);
  const provider = isHardwareProfile(policy.profile) ? providerForTicket(ticket.body) : null;
  check(provider ? validatePublicPlan(provider, r.plan) : schema.checks.find(rule => rule.field === 'plan_type').values.includes(r.plan), 'PLAN');
  check(Number.isSafeInteger(r.issuedAt) && r.issuedAt >= grant.body.issuedAt && r.issuedAt <= now + 2000
    && r.issuedAt < grant.body.deadline && now < r.expiresAt, 'RECEIPT_EXPIRED');
  check(Number.isSafeInteger(r.sentBytes) && r.sentBytes > 0 && r.sentBytes <= LIMITS.maxSentBytes
    && Number.isSafeInteger(r.recvBytes) && r.recvBytes > 0 && r.recvBytes <= LIMITS.maxRecvBytes, 'RECEIPT_LIMIT');
  if (expectedFacts) for (const k of [...(offer.body.identity?[]:['pseudonym']), 'plan', 'sentBytes', 'recvBytes']) check(r[k] === expectedFacts[k], 'LOCAL_FACTS');
  return {namespace: offer.body.identity?`${provider.id}-private-keyed-v2`:provider?.identityNamespace ?? 'chatgpt-private-account-v1', subjectKey: r.pseudonym, plan: r.plan};
}
async function makeReceiptShape(ticket, offer, grant, facts) {
  // Construct the exact public binding without an arbitrary-message signing API.
  const provider = providerForTicket(ticket.body);
  check(provider || ticket.body.profile === SIMULATION, 'PROFILE');
  return {body: {profile: ticket.body.profile, mode: 'Proxy', attempt: ticket.body.attempt,
    wallet: ticket.body.wallet, application: ticket.body.application, chain: ticket.body.chain,
    schemaDigest: ticket.body.schemaDigest, session: offer.body.session, binding: await channelBinding(ticket, offer, grant),
    ticketHash: await envelopeDigest(ticket), grantHash: await envelopeDigest(grant), measurement: offer.body.measurement,
    issuedAt: facts.issuedAt, expiresAt: ticket.body.resultExpiresAt, host: provider?.host ?? 'chatgpt.com', endpoint: provider?.endpoint ?? '/backend-api/wham/usage',
    pseudonym: facts.pseudonym, plan: facts.plan, sentBytes: facts.sentBytes, recvBytes: facts.recvBytes,
    ...(offer.body.identity?{identity:offer.body.identity}:{})}};
}
