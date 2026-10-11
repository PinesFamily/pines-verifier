// Measured provider profiles: the fixed ChatGPT, Claude and Grok sources the enclave evaluates.
import legacy from '../../packages/verification-schemas/schemas/chatgpt-plan.v3.json' with {type: 'json'};
import claudeLegacy from '../../packages/verification-schemas/schemas/claude-plan.v1.json' with {type: 'json'};
import grokLegacy from '../../packages/verification-schemas/schemas/grok-plan.v1.json' with {type: 'json'};
import chatgptInventory from './hardware/provider-inventory.json' with {type: 'json'};
import claudeInventory from './hardware/claude-inventory.json' with {type: 'json'};
import grokInventory from './hardware/grok-inventory.json' with {type: 'json'};
// The private-headers candidate's own schemas and inventories. Separate files: the
// three above are measured, pinned and part of the current candidate's image.
import chatgptPrivatePlan from '../../packages/verification-schemas/schemas/chatgpt-plan.v4.json' with {type: 'json'};
import claudeOrgPlan from '../../packages/verification-schemas/schemas/claude-plan.v2.json' with {type: 'json'};
import grokActivePlan from '../../packages/verification-schemas/schemas/grok-plan.v2.json' with {type: 'json'};
import chatgptPrivateInventory from './hardware/chatgpt-private-inventory.json' with {type: 'json'};
import claudeOrgInventory from './hardware/claude-org-inventory.json' with {type: 'json'};
import grokActiveInventory from './hardware/grok-active-inventory.json' with {type: 'json'};
import {CONTEXT} from './hardware/context.mjs';
import {planDisclosure as nativePlan} from '../../packages/verification-schemas/src/disclosure.ts';
import {parseHttp, headerValue, utf8} from '../../packages/verification-schemas/src/http.ts';
import {parseJson} from '../../packages/verification-schemas/src/json.ts';
import {inspectDisclosedRequest} from '../../packages/verification-schemas/src/redacted-request.ts';
import {inspectDisclosedResponse} from '../../packages/verification-schemas/src/redacted-response.ts';
import {evaluateVerifiedExchange} from '../../packages/verification-schemas/src/evaluate.ts';
import {check, digest, lp, encode} from './wire.mjs';
import {inspectProvider, inspectProviderShape} from './inventory.mjs';
import {disclosurePolicy, checkDisclosureRanges, REDACTED_RESPONSE, PRIVATE_HEADERS} from './disclosure-policy.mjs';

export const SIMULATION = 'pines.chatgpt.tee.native.simulation.v1';
export const NITRO = 'pines.chatgpt.tee.native.nitro.v1';
export const LIMITS = Object.freeze({...legacy.limits, protocolBytes: 64 * 1024 * 1024});
export const stagingSchema = legacy;
export const schema = structuredClone(legacy);
schema.schemaId = 'pines.chatgpt.tee.synthetic';
schema.version = 1;
schema.claims.enabled = false;
schema.capture.headers.find(h => h.name === 'user-agent').secret = false;
const freeze = value => {for (const child of Object.values(value)) if (child && typeof child === 'object') freeze(child);return Object.freeze(value);};
const prior = structuredClone(schema);
prior.schemaId = 'pines.chatgpt.tee.native';
prior.version = 3;
prior.lifecycle = 'qualified';
prior.claims.enabled = true;
prior.claims.templateIds = ['CHATGPT-SUBSCRIPTION'];
prior.identity.version = 'chatgpt-private-account-v1';
prior.response.secretHeaders = ['x-oai-is-update'];
// Read-only historical resolution. New admission never selects this schema.
export const priorHardwareSchema = freeze(prior);
export const PRIOR_SCHEMA_REF = Object.freeze({schemaId: prior.schemaId, version: prior.version, digest: 'sha256:3b3aedbbb49af48a072c7c3de44f0fc1f76360b1c5c57236d19aae2456925eb1'});
export const hardwareSchema = structuredClone(priorHardwareSchema);
hardwareSchema.version = 5;
hardwareSchema.identity.version = 'chatgpt-private-keyed-v2';
hardwareSchema.checks.find(rule => rule.field === 'plan_type').values = ['plus', 'pro', 'prolite', 'promax'];
freeze(hardwareSchema);
export const SCHEMA_REF = Object.freeze({schemaId: hardwareSchema.schemaId, version: hardwareSchema.version, digest: 'sha256:e54276775c668f67a1aeac9e7f5470896904314b5211a2a83066f6e6a3ec27c9'});
export const schemaReference = async () => Object.freeze({schemaId: hardwareSchema.schemaId, version: hardwareSchema.version, digest: 'sha256:' + await digest(encode(hardwareSchema))});

export const CLAUDE_NITRO = 'pines.claude.tee.native.nitro.v1';
export const GROK_NITRO = 'pines.grok.tee.native.nitro.v1';
const nativeSchema = (legacy, id, namespace) => {
  const result = structuredClone(legacy);
  result.schemaId = `pines.${id}.tee.native`;
  result.version = 2;
  result.identity.version = namespace;
  result.capture.headers.find(rule=>rule.name==='user-agent').secret=false;
  return freeze(result);
};
export const claudeHardwareSchema = nativeSchema(claudeLegacy, 'claude', 'claude-private-keyed-v2');
export const grokHardwareSchema = nativeSchema(grokLegacy, 'grok', 'grok-private-keyed-v2');
export const CLAUDE_SCHEMA_REF = Object.freeze({schemaId: claudeHardwareSchema.schemaId, version: 2, digest: 'sha256:2371d46a8836cd8b5baaf749c85cb9c7e873fb7311e8755ab8485a50c97979dd'});
export const GROK_SCHEMA_REF = Object.freeze({schemaId: grokHardwareSchema.schemaId, version: 2, digest: 'sha256:d07ebe1bdee5775fb513666cd612b78c466b103972cd4ac3c34fe39e575f7e81'});
// One derivation for the private-headers candidate, the same shape as `prior` and
// `nativeSchema`: qualified, claims enabled, and the capture's user-agent public. The
// identity namespace and identitySourceVersion are deliberately UNCHANGED from the
// qualified versions above, so existing bindings and keyed pseudonyms carry over.
const privateHeadersSchema = (candidate, id, namespace, version, templateIds) => {
  const result = structuredClone(candidate);
  result.schemaId = `pines.${id}.tee.native`;
  result.version = version;
  result.lifecycle = 'qualified';
  result.identity.version = namespace;
  result.claims.enabled = true;
  result.claims.templateIds = templateIds;
  result.capture.headers.find(rule => rule.name === 'user-agent').secret = false;
  if (id === 'chatgpt') result.checks.find(rule => rule.field === 'plan_type').values = ['plus', 'pro', 'prolite', 'promax'];
  return freeze(result);
};
export const chatgptPrivateHeadersSchema = privateHeadersSchema(chatgptPrivatePlan, 'chatgpt', 'chatgpt-private-keyed-v2', 6, ['CHATGPT-SUBSCRIPTION']);
export const claudePrivateHeadersSchema = privateHeadersSchema(claudeOrgPlan, 'claude', 'claude-private-keyed-v2', 3, ['CLAUDE-PLAN']);
export const grokPrivateHeadersSchema = privateHeadersSchema(grokActivePlan, 'grok', 'grok-private-keyed-v2', 3, ['GROK-PAGE']);
// Pinned like every reference above, and asserted against the derivation by a test.
export const CHATGPT_PRIVATE_SCHEMA_REF = Object.freeze({schemaId: chatgptPrivateHeadersSchema.schemaId, version: 6, digest: 'sha256:cd5e6039d98ecc181ca5f965515cf6eaa5a8dbc621ecd7673c492143f5fe223d'});
export const CLAUDE_PRIVATE_SCHEMA_REF = Object.freeze({schemaId: claudePrivateHeadersSchema.schemaId, version: 3, digest: 'sha256:b8209443cbf6aa759e9bef8b808de111e0de7837773612facb7387f4726738e2'});
export const GROK_PRIVATE_SCHEMA_REF = Object.freeze({schemaId: grokPrivateHeadersSchema.schemaId, version: 3, digest: 'sha256:72127c492d778072c103b374177cc6d71f60e0a49ccac7aa1b23fb6da80aff75'});

const makeProvider = (id, profile, schema, reference, savedSchemaDefinitions, savedSchemas, inventory, identitySourceVersion, planField, publicPlanValues, egressPort) => freeze({
  id, profile, schema, reference, savedSchemas, savedSchemaDefinitions, inventory,
  host: new URL(schema.request.origin).hostname, endpoint: schema.request.path,
  identityNamespace: schema.identity.version, identitySourceVersion, planField,
  publicPlanValues, templateIds: schema.claims.templateIds, egressPort,
});
export const HARDWARE_PROVIDERS = freeze([
  makeProvider('chatgpt', NITRO, hardwareSchema, SCHEMA_REF, [hardwareSchema], [SCHEMA_REF], chatgptInventory,
    'chatgpt-user-v1', 'plan_type', ['plus', 'pro', 'prolite', 'promax'], 8001),
  makeProvider('claude', CLAUDE_NITRO, claudeHardwareSchema, CLAUDE_SCHEMA_REF, [claudeHardwareSchema], [CLAUDE_SCHEMA_REF], claudeInventory,
    'claude-org-v1', 'rate_limit_tier', ['pro', 'max'], 8002),
  makeProvider('grok', GROK_NITRO, grokHardwareSchema, GROK_SCHEMA_REF, [grokHardwareSchema], [GROK_SCHEMA_REF], grokInventory,
    'grok-user-v1', 'tier', ['SUBSCRIPTION_TIER_X_PREMIUM_PLUS', 'SUBSCRIPTION_TIER_SUPER_GROK_LITE', 'SUBSCRIPTION_TIER_GROK_PRO', 'SUBSCRIPTION_TIER_SUPER_GROK_PLUS', 'SUBSCRIPTION_TIER_SUPER_GROK_PRO'], 8003),
]);
// The private-headers candidate's providers. The profile ids are the same measured
// enclave profiles: what changes is the schema version, the inventory and the policy.
// They are resolvable ONLY when the boot's disclosure policy is the private-headers
// one, so with it unselected every lookup below behaves exactly as it did before.
export const PRIVATE_HEADERS_PROVIDERS = freeze([
  makeProvider('chatgpt', NITRO, chatgptPrivateHeadersSchema, CHATGPT_PRIVATE_SCHEMA_REF, [chatgptPrivateHeadersSchema], [CHATGPT_PRIVATE_SCHEMA_REF], chatgptPrivateInventory,
    'chatgpt-user-v1', 'plan_type', ['plus', 'pro', 'prolite', 'promax'], 8001),
  makeProvider('claude', CLAUDE_NITRO, claudePrivateHeadersSchema, CLAUDE_PRIVATE_SCHEMA_REF, [claudePrivateHeadersSchema], [CLAUDE_PRIVATE_SCHEMA_REF], claudeOrgInventory,
    'claude-org-v1', 'rate_limit_tier', ['pro', 'max'], 8002),
  makeProvider('grok', GROK_NITRO, grokPrivateHeadersSchema, GROK_PRIVATE_SCHEMA_REF, [grokPrivateHeadersSchema], [GROK_PRIVATE_SCHEMA_REF], grokActiveInventory,
    'grok-user-v1', 'tier', ['SUBSCRIPTION_TIER_X_PREMIUM_PLUS', 'SUBSCRIPTION_TIER_SUPER_GROK_LITE', 'SUBSCRIPTION_TIER_GROK_PRO', 'SUBSCRIPTION_TIER_SUPER_GROK_PLUS', 'SUBSCRIPTION_TIER_SUPER_GROK_PRO'], 8003),
]);
// Membership for the per-provider helpers below. A provider is never usable under a
// policy that is not its own: `providersFor` is what decides, not this union.
export const ALL_PROVIDERS = freeze([...HARDWARE_PROVIDERS, ...PRIVATE_HEADERS_PROVIDERS]);
/**
 * The providers one disclosure policy ADMITS. An omitted policy keeps today's answer,
 * so every existing caller is unchanged. `'any'` is for RECOGNISING a schema already
 * written to storage, never for admitting a new attempt: a receipt saved under one
 * candidate must stay readable after the other is selected.
 */
export const providersFor = selectedPolicy => selectedPolicy === undefined ? HARDWARE_PROVIDERS
  : selectedPolicy === 'any' ? ALL_PROVIDERS
  : disclosurePolicy(selectedPolicy) === PRIVATE_HEADERS ? PRIVATE_HEADERS_PROVIDERS : HARDWARE_PROVIDERS;
const sameReference = (a, b) => a && typeof a === 'object' && Object.keys(a).length === 3 && ['schemaId', 'version', 'digest'].every(k => a[k] === b[k]);
export const providerForSchema = (ref, policy) => providersFor(policy).find(p => sameReference(ref, p.reference)) ?? null;
export const providerForSavedSchema = (ref, policy) => providersFor(policy).find(p => p.savedSchemas.some(saved => sameReference(ref, saved))) ?? null;
// A ticket body carries the policy it was SIGNED with, so this reads it from the body
// rather than trusting a caller to remember it: the profile strings are shared between
// the classes, and only the schema digest tells them apart. A body without the field is
// the legacy redacted path and still resolves against the qualified providers alone.
export const providerForTicket = (ticket, policy = ticket?.disclosurePolicy) =>
  providersFor(policy).find(p => p.profile === ticket?.profile && p.reference.digest === 'sha256:' + ticket?.schemaDigest) ?? null;
export const isHardwareProfile = profile => ALL_PROVIDERS.some(p => p.profile === profile);
export const publicPlansForSchema = (ref, policy) => {
  const provider = providerForSavedSchema(ref, policy);
  if (!provider) return null;
  return sameReference(ref, PRIOR_SCHEMA_REF) ? priorHardwareSchema.checks.find(rule => rule.field === 'plan_type').values : provider.publicPlanValues;
};
export const validatePublicPlan = (provider, value) => ALL_PROVIDERS.includes(provider) && provider.publicPlanValues.includes(value);
export function normalizePlan(provider, value) {
  check(ALL_PROVIDERS.includes(provider), 'PROVIDER_SCOPE');
  if (provider.id === 'claude') {
    check(typeof value === 'string' && value.length <= 64, 'INELIGIBLE_PLAN');
    const match = /^default_claude_(max|pro)(?:_[a-z0-9]+){0,4}$/.exec(value);
    check(match, 'INELIGIBLE_PLAN'); return match[1];
  }
  check(validatePublicPlan(provider, value), 'INELIGIBLE_PLAN'); return value;
}
export const providerPseudonym = (provider, id) => {
  check(ALL_PROVIDERS.includes(provider), 'PROVIDER_SCOPE');
  check(typeof id === 'string' && (provider.id === 'chatgpt' ? /^user-[A-Za-z\d]{24}$/ : /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/).test(id), 'ACCOUNT_ID');
  return digest(lp(['pines/private-account/v1', provider.host, provider.identitySourceVersion, id]));
};
// The capability one boot/API/extension advertises is the provider set of ONE class.
// Omitted keeps today's answer (the qualified full-response providers), so every
// existing caller and the pinned config/tee-capability.json are unchanged; the
// private-headers class has its own pin (config/tee-capability-private-headers.json).
// 'any' is a storage-recognition scope, never a capability.
export const hardwareCapability = selectedPolicy => {
  check(selectedPolicy !== 'any', 'CAPABILITY_POLICY');
  return freeze({...CONTEXT, protocol: CONTEXT.protocolVersion, capabilityVersion: 2,
    claimSigningAvailable: false, providers: providersFor(selectedPolicy).map(p => ({id: p.id, profile: p.profile, schema: p.reference, savedSchemas: p.savedSchemas}))});
};

// Full provider JSON is authenticated only inside the measured evaluator. The
// browser sees it locally, but the only public consent/receipt fact is a closed plan.
const privateFacts = (provider, facts) => ({id: facts.subjectKey, plan: normalizePlan(provider, facts.values[provider.planField])});
export function planDisclosureForProvider(provider, sent, recv, wallet, selectedPolicy = REDACTED_RESPONSE) {
  const policy = disclosurePolicy(selectedPolicy);
  // A provider belongs to exactly one policy's set. There is no fallback between them:
  // the private-headers schemas and inventories are only ever evaluated under the
  // class whose memory budget and pre-ZK caps were chosen for them.
  check(providersFor(policy).includes(provider), 'PROVIDER_SCOPE');
  if (provider.schema.capture.cookies.length) check(headerValue(parseHttp(sent, provider.schema, 'sent'), 'cookie') !== undefined, 'PROVIDER_REQUEST_CREDENTIAL');
  inspectProviderShape(parseHttp(recv, provider.schema, 'recv'), provider.inventory, policy.response);
  const plan = nativePlan(provider.schema, sent, recv, wallet, policy.response);
  // Every authenticated response byte is revealed inside the encrypted channel;
  // only credential-bearing request header values are hidden. No fallback.
  checkDisclosureRanges(policy, sent.length, recv.length, plan.sent, plan.recv);
  return {reveal: {sent: plan.sent, recv: plan.recv, server_identity: true}, facts: privateFacts(provider, plan.preview)};
}
export async function evaluateAuthenticatedForProvider(provider, output, wallet, selectedPolicy = REDACTED_RESPONSE, identityAdapter) {
  const policy = disclosurePolicy(selectedPolicy);
  check(providersFor(policy).includes(provider), 'PROVIDER_SCOPE');
  check(output.mode === 'Proxy' && output.host === provider.host, 'VERIFIER_CONTEXT');
  check(output.extraCommitments === 0, 'UNEXPECTED_COMMITMENTS');
  checkDisclosureRanges(policy, output.sent.length, output.recv.length, output.sentAuthed, output.recvAuthed);
  const verified = (bytes, authenticated) => ({bytes, authenticated, originalLength: bytes.length});
  const sent = verified(output.sent, output.sentAuthed), recv = verified(output.recv, output.recvAuthed);
  inspectDisclosedRequest(provider.schema, sent);
  inspectProviderShape(inspectDisclosedResponse(provider.schema, recv, policy.response), provider.inventory, policy.response);
  const facts = privateFacts(provider, evaluateVerifiedExchange(provider.schema, {mode:'Proxy',serverName:provider.host,sent,recv}, wallet, policy.response));
  if(identityAdapter)check(identityAdapter.enabled===true&&(policy.response==='complete'||policy.response==='private-headers'),'KEYED_IDENTITY_REQUIRED');
  return {pseudonym: identityAdapter?await identityAdapter.pseudonym(provider,facts.id):await providerPseudonym(provider, facts.id),
    ...(identityAdapter?{accountId:facts.id}:{}),plan: facts.plan, sentBytes: output.sent.length, recvBytes: output.recv.length};
}

// Owned fixture inventory only. Unknown fields refuse, rather than being hidden.
// This does not qualify real ChatGPT response compatibility.
export function inspectInventory(message) {
  check(message.startLine === 'HTTP/1.1 200 OK', 'RESPONSE_STATUS');
  check(['application/json', 'application/json; charset=utf-8', 'application/json;charset=utf-8']
    .includes(headerValue(message, 'content-type')?.toLowerCase()), 'CONTENT_TYPE');
  check(headerValue(message, 'content-encoding') === undefined, 'CONTENT_ENCODING');
  const allowed = new Set(['content-type', 'content-length', 'transfer-encoding', 'connection', 'date', 'server', 'set-cookie']);
  for (const h of message.headers) check(allowed.has(h.name), 'UNQUALIFIED_HEADER');
  const root = parseJson(utf8(message.body), LIMITS.maxJsonDepth);
  check(root && typeof root === 'object' && !Array.isArray(root), 'BODY_SHAPE');
  for (const key of Object.keys(root)) check(['user_id', 'plan_type', 'email', 'padding'].includes(key), 'UNQUALIFIED_FIELD');
  check(typeof root.user_id === 'string' && /^user-[A-Za-z\d]{24}$/.test(root.user_id), 'ACCOUNT_ID');
  check(['plus', 'pro', 'prolite'].includes(root.plan_type), 'INELIGIBLE_PLAN');
  for (const key of ['email', 'padding']) check(!Object.hasOwn(root, key) || typeof root[key] === 'string', 'BODY_SHAPE');
  return {id: root.user_id, plan: root.plan_type};
}

export function planDisclosure(sent, recv, wallet, baseline = false, inventory) {
  // Same planner as staging. Only the explicit candidate profile exposes UA.
  const selected = inventory ? hardwareSchema : baseline ? stagingSchema : schema;
  const message = parseHttp(recv, selected, 'recv');
  const facts = inventory ? inspectProvider(message, inventory) : inspectInventory(message);
  const plan = nativePlan(selected, sent, recv, wallet);
  return {reveal: {sent: plan.sent, recv: plan.recv, server_identity: true}, facts};
}

export async function evaluateAuthenticated(output, baseline = false, inventory) {
  check(output.mode === 'Proxy' && output.host === 'chatgpt.com', 'VERIFIER_CONTEXT');
  // There are no application commitments in this profile, including unsolicited ones.
  check(output.extraCommitments === 0, 'UNEXPECTED_COMMITMENTS');
  const selected = inventory ? hardwareSchema : baseline ? stagingSchema : schema;
  const verified = (bytes, authenticated) => ({bytes, authenticated, originalLength: bytes.length});
  inspectDisclosedRequest(selected, verified(output.sent, output.sentAuthed));
  const message = inspectDisclosedResponse(selected, verified(output.recv, output.recvAuthed));
  const facts = inventory ? inspectProvider(message, inventory) : inspectInventory(message);
  return {pseudonym: await pseudonym(facts.id), plan: facts.plan, sentBytes: output.sent.length, recvBytes: output.recv.length};
}

export const pseudonym = id => digest(lp(['pines/private-account/v1', 'chatgpt.com', 'chatgpt-user-v1', id]));
