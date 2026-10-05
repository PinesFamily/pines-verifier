// Measured provider profiles: the fixed ChatGPT, Claude and Grok sources the enclave evaluates.
import legacy from '../../packages/verification-schemas/schemas/chatgpt-plan.v3.json' with {type: 'json'};
import claudeLegacy from '../../packages/verification-schemas/schemas/claude-plan.v1.json' with {type: 'json'};
import grokLegacy from '../../packages/verification-schemas/schemas/grok-plan.v1.json' with {type: 'json'};
import chatgptInventory from './hardware/provider-inventory.json' with {type: 'json'};
import claudeInventory from './hardware/claude-inventory.json' with {type: 'json'};
import grokInventory from './hardware/grok-inventory.json' with {type: 'json'};
import {CONTEXT} from './hardware/context.mjs';
import {planDisclosure as nativePlan} from '../../packages/verification-schemas/src/disclosure.ts';
import {parseHttp, headerValue, utf8} from '../../packages/verification-schemas/src/http.ts';
import {parseJson} from '../../packages/verification-schemas/src/json.ts';
import {inspectDisclosedRequest} from '../../packages/verification-schemas/src/redacted-request.ts';
import {inspectDisclosedResponse} from '../../packages/verification-schemas/src/redacted-response.ts';
import {evaluateVerifiedExchange} from '../../packages/verification-schemas/src/evaluate.ts';
import {check, digest, lp, encode} from './wire.mjs';
import {inspectProvider, inspectProviderShape} from './inventory.mjs';

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
hardwareSchema.version = 4;
hardwareSchema.checks.find(rule => rule.field === 'plan_type').values = ['plus', 'pro', 'prolite', 'promax'];
freeze(hardwareSchema);
export const SCHEMA_REF = Object.freeze({schemaId: hardwareSchema.schemaId, version: hardwareSchema.version, digest: 'sha256:21d9bee1bbd37da79dc6afc9b6664b53a7cf520d0ee2007696bc655212318a47'});
export const schemaReference = async () => Object.freeze({schemaId: hardwareSchema.schemaId, version: hardwareSchema.version, digest: 'sha256:' + await digest(encode(hardwareSchema))});

export const CLAUDE_NITRO = 'pines.claude.tee.native.nitro.v1';
export const GROK_NITRO = 'pines.grok.tee.native.nitro.v1';
const nativeSchema = (legacy, id, namespace) => {
  const result = structuredClone(legacy);
  result.schemaId = `pines.${id}.tee.native`;
  result.version = 1;
  result.identity.version = namespace;
  return freeze(result);
};
export const claudeHardwareSchema = nativeSchema(claudeLegacy, 'claude', 'claude-private-org-v1');
export const grokHardwareSchema = nativeSchema(grokLegacy, 'grok', 'grok-private-account-v1');
export const CLAUDE_SCHEMA_REF = Object.freeze({schemaId: claudeHardwareSchema.schemaId, version: 1, digest: 'sha256:853b4e26195f81837da924292b51b9ce9e1e8feec1380174f25281fb4fb51699'});
export const GROK_SCHEMA_REF = Object.freeze({schemaId: grokHardwareSchema.schemaId, version: 1, digest: 'sha256:69870e59cf44ecd76114f3f35c93de33991edfab6674702381754d920b2adb8b'});
const makeProvider = (id, profile, schema, reference, savedSchemaDefinitions, savedSchemas, inventory, identitySourceVersion, planField, publicPlanValues, egressPort) => freeze({
  id, profile, schema, reference, savedSchemas, savedSchemaDefinitions, inventory,
  host: new URL(schema.request.origin).hostname, endpoint: schema.request.path,
  identityNamespace: schema.identity.version, identitySourceVersion, planField,
  publicPlanValues, templateIds: schema.claims.templateIds, egressPort,
});
export const HARDWARE_PROVIDERS = freeze([
  makeProvider('chatgpt', NITRO, hardwareSchema, SCHEMA_REF, [priorHardwareSchema, hardwareSchema], [PRIOR_SCHEMA_REF, SCHEMA_REF], chatgptInventory,
    'chatgpt-user-v1', 'plan_type', ['plus', 'pro', 'prolite', 'promax'], 8001),
  makeProvider('claude', CLAUDE_NITRO, claudeHardwareSchema, CLAUDE_SCHEMA_REF, [claudeHardwareSchema], [CLAUDE_SCHEMA_REF], claudeInventory,
    'claude-org-v1', 'rate_limit_tier', ['pro', 'max'], 8002),
  makeProvider('grok', GROK_NITRO, grokHardwareSchema, GROK_SCHEMA_REF, [grokHardwareSchema], [GROK_SCHEMA_REF], grokInventory,
    'grok-user-v1', 'tier', ['SUBSCRIPTION_TIER_X_PREMIUM_PLUS', 'SUBSCRIPTION_TIER_SUPER_GROK_LITE', 'SUBSCRIPTION_TIER_GROK_PRO', 'SUBSCRIPTION_TIER_SUPER_GROK_PLUS', 'SUBSCRIPTION_TIER_SUPER_GROK_PRO'], 8003),
]);
const sameReference = (a, b) => a && typeof a === 'object' && Object.keys(a).length === 3 && ['schemaId', 'version', 'digest'].every(k => a[k] === b[k]);
export const providerForSchema = ref => HARDWARE_PROVIDERS.find(p => sameReference(ref, p.reference)) ?? null;
export const providerForSavedSchema = ref => HARDWARE_PROVIDERS.find(p => p.savedSchemas.some(saved => sameReference(ref, saved))) ?? null;
export const providerForTicket = ticket => HARDWARE_PROVIDERS.find(p => p.profile === ticket?.profile && p.reference.digest === 'sha256:' + ticket?.schemaDigest) ?? null;
export const isHardwareProfile = profile => HARDWARE_PROVIDERS.some(p => p.profile === profile);
export const publicPlansForSchema = ref => {
  const provider = providerForSavedSchema(ref);
  if (!provider) return null;
  return sameReference(ref, PRIOR_SCHEMA_REF) ? priorHardwareSchema.checks.find(rule => rule.field === 'plan_type').values : provider.publicPlanValues;
};
export const validatePublicPlan = (provider, value) => HARDWARE_PROVIDERS.includes(provider) && provider.publicPlanValues.includes(value);
export function normalizePlan(provider, value) {
  check(HARDWARE_PROVIDERS.includes(provider), 'PROVIDER_SCOPE');
  if (provider.id === 'claude') {
    check(typeof value === 'string' && value.length <= 64, 'INELIGIBLE_PLAN');
    const match = /^default_claude_(max|pro)(?:_[a-z0-9]+){0,4}$/.exec(value);
    check(match, 'INELIGIBLE_PLAN'); return match[1];
  }
  check(validatePublicPlan(provider, value), 'INELIGIBLE_PLAN'); return value;
}
export const providerPseudonym = (provider, id) => {
  check(HARDWARE_PROVIDERS.includes(provider), 'PROVIDER_SCOPE');
  check(typeof id === 'string' && (provider.id === 'chatgpt' ? /^user-[A-Za-z\d]{24}$/ : /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/).test(id), 'ACCOUNT_ID');
  return digest(lp(['pines/private-account/v1', provider.host, provider.identitySourceVersion, id]));
};
export const hardwareCapability = () => freeze({...CONTEXT, protocol: CONTEXT.protocolVersion, capabilityVersion: 2,
  claimSigningAvailable: false, providers: HARDWARE_PROVIDERS.map(p => ({id: p.id, profile: p.profile, schema: p.reference, savedSchemas: p.savedSchemas}))});

// Full provider JSON is authenticated only inside the measured evaluator. The
// browser sees it locally, but the only public consent/receipt fact is a closed plan.
const privateFacts = (provider, facts) => ({id: facts.subjectKey, plan: normalizePlan(provider, facts.values[provider.planField])});
export function planDisclosureForProvider(provider, sent, recv, wallet) {
  check(HARDWARE_PROVIDERS.includes(provider), 'PROVIDER_SCOPE');
  if (provider.schema.capture.cookies.length) check(headerValue(parseHttp(sent, provider.schema, 'sent'), 'cookie') !== undefined, 'PROVIDER_REQUEST_CREDENTIAL');
  inspectProviderShape(parseHttp(recv, provider.schema, 'recv'), provider.inventory);
  const plan = nativePlan(provider.schema, sent, recv, wallet);
  return {reveal: {sent: plan.sent, recv: plan.recv, server_identity: true}, facts: privateFacts(provider, plan.preview)};
}
export async function evaluateAuthenticatedForProvider(provider, output, wallet) {
  check(HARDWARE_PROVIDERS.includes(provider), 'PROVIDER_SCOPE');
  check(output.mode === 'Proxy' && output.host === provider.host, 'VERIFIER_CONTEXT');
  check(output.extraCommitments === 0, 'UNEXPECTED_COMMITMENTS');
  const verified = (bytes, authenticated) => ({bytes, authenticated, originalLength: bytes.length});
  const sent = verified(output.sent, output.sentAuthed), recv = verified(output.recv, output.recvAuthed);
  inspectDisclosedRequest(provider.schema, sent);
  inspectProviderShape(inspectDisclosedResponse(provider.schema, recv), provider.inventory);
  const facts = privateFacts(provider, evaluateVerifiedExchange(provider.schema, {mode:'Proxy',serverName:provider.host,sent,recv}, wallet));
  return {pseudonym: await providerPseudonym(provider, facts.id), plan: facts.plan, sentBytes: output.sent.length, recvBytes: output.recv.length};
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
