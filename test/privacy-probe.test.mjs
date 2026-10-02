import test from 'node:test';
import assert from 'node:assert/strict';
import {privacyPageProbe, privacyProbeReport} from '../capture/privacy-probe.mjs';

const secret = 'synthetic-token-never-a-real-credential';
const email = 'private-canary@example.test', uuid = '11111111-2222-4333-8444-555555555555';
function harness(body, {status = 200, contentType = 'application/json', token = secret} = {}) {
  const calls = [];
  const env = {AbortController, TextDecoder, setTimeout, clearTimeout, fetch: async (path, options) => {
    calls.push({path, options});
    const session = path === '/api/auth/session';
    return new Response(session ? JSON.stringify({accessToken: token, email}) : typeof body === 'string' ? body : JSON.stringify(body),
      {status: session ? 200 : status, headers: {'content-type': contentType}});
  }};
  return {env, calls};
}
test('ChatGPT uses only its auth prerequisite and usage GET; the report cannot export values', async () => {
  const h = harness({user_id: 'user-ABCDEFGHIJKLMNOPQRSTUVWX', plan_type: 'plus', email,
    name: 'Private Canary', account_id: uuid, [email]: secret, extras: {invoiceId: 'in_CANARY'}});
  const result = await privacyPageProbe('chatgpt', h.env), text = privacyProbeReport(result, 'chatgpt');
  for (const value of [secret, email, uuid, 'Private Canary', 'in_CANARY', 'user-ABCDEFGHIJKLMNOPQRSTUVWX', 'plus']) assert(!text.includes(value));
  assert.deepEqual(h.calls.map(c => c.path), ['/api/auth/session', '/backend-api/wham/usage']);
  assert.equal(h.calls[1].options.headers.authorization, `Bearer ${secret}`);
  for (const {options} of h.calls) {
    assert.equal(options.method, 'GET'); assert.equal(options.credentials, 'same-origin'); assert.equal(options.redirect, 'error');
  }
  assert.equal(result.selectorFieldsComplete, true); assert.equal(result.privateStringValues, 5);
  assert.equal(result.emailFieldPresent, true); assert.equal(result.nameFieldPresent, true);
  assert.equal(result.billingIdFieldPresent, true); assert.equal(result.rawAsciiStrings, result.stringValues);
});
test('Claude inspects every organization and distinguishes capability strings from private values', async () => {
  const org = {uuid, name: email, capabilities: ['chat', 'claude_max'], rate_limit_tier: 'default_claude_max_20x',
    raven_type: null, parent_organization_uuid: null};
  const h = harness([org, {...org, rate_limit_tier: undefined, name: 'Other Canary'}]);
  const result = await privacyPageProbe('claude', h.env);
  assert.equal(result.itemCount, 2); assert.equal(result.selectorFieldsComplete, false);
  assert.equal(result.privateStringValues, 2); assert.equal(result.identityFieldsPresent, true);
  assert.deepEqual(h.calls.map(c => c.path), ['/api/organizations']);
  assert(!privacyProbeReport(result, 'claude').includes(email));
});
test('Grok inspects all entries and reports billing markers as booleans only', async () => {
  const sub = {xaiUserId: uuid, tier: 'SUBSCRIPTION_TIER_GROK_PRO', status: 'SUBSCRIPTION_STATUS_ACTIVE'};
  const h = harness({subscriptions: [{...sub, billingSystem: 'BILLING_SYSTEM_COMMERCE', stripe: {subscriptionId: secret}},
    {...sub, billingSystem: 'BILLING_SYSTEM_LEGACY'}]});
  const result = await privacyPageProbe('grok', h.env);
  assert.equal(result.selectorFieldsComplete, true); assert.equal(result.billingIdFieldPresent, true);
  assert.equal(result.commerceBillingMarkerPresent, true); assert.equal(result.legacyBillingMarkerPresent, true);
  assert.deepEqual(h.calls.map(c => c.path), ['/rest/subscriptions']);
  assert(!privacyProbeReport(result, 'grok').includes(secret));
  const noBilling = await privacyPageProbe('grok', harness({subscriptions: [sub]}).env);
  assert.equal(noBilling.billingIdFieldPresent, false, 'xaiUserId under subscriptions is identity, not a billing ID');
});
test('raw serialization metrics distinguish actual Unicode escapes, escaped slashes and empty values', async () => {
  const h = harness('{"user_id":"id","plan_type":"plus","a":"\\u0041\\u0042","b":"\\\\u0041","c":"","d":"é","e":"\\\""}');
  const result = await privacyPageProbe('chatgpt', h.env);
  assert.equal(result.stringValues, 7); assert.equal(result.fullyU00EscapedStrings, 1);
  assert.equal(result.rawAsciiStrings, 3); assert.equal(result.stringsWithEscapes, 3);
});
test('failures, redirects, missing auth, excessive size and deep shapes never echo error text', async () => {
  const cases = [
    [harness({}, {token: null}), 'chatgpt', 'AUTH_REQUIRED'],
    [harness(email, {status: 401}), 'claude', 'AUTH_REQUIRED'],
    [harness(email), 'claude', 'INVALID_JSON'],
    [harness(email, {contentType: 'text/html'}), 'claude', 'UNEXPECTED_CONTENT_TYPE'],
    [harness('x'.repeat(65537)), 'claude', 'BODY_TOO_LARGE'],
    [harness({subscriptions: new Array(65).fill({})}), 'grok', 'UNEXPECTED_SHAPE'],
    [harness({subscriptions: [{nested: JSON.parse('['.repeat(33) + '0' + ']'.repeat(33))}]}), 'grok', 'SHAPE_LIMIT'],
  ];
  for (const [h, provider, code] of cases) {
    const result = await privacyPageProbe(provider, h.env);
    assert.equal(result.error, code); assert(!privacyProbeReport(result, provider).includes(email));
  }
  const h = harness({}); h.env.fetch = async () => {throw Error(email + secret);};
  assert.equal((await privacyPageProbe('claude', h.env)).error, 'REQUEST_FAILED');
  await assert.rejects(privacyPageProbe('other', h.env), /INVALID_PROVIDER/);
});
test('the report writer rejects extra keys, values in counts, forged flags and arbitrary error strings', async () => {
  const good = await privacyPageProbe('grok', harness({subscriptions: []}).env);
  for (const bad of [{...good, raw: email}, {...good, responseBytes: email}, {...good, emailFieldPresent: email},
    {...good, error: email}, {...good, itemCount: 65}, {...good, provider: email}]) {
    assert.throws(() => privacyProbeReport(bad, 'grok'), /INVALID_PRIVACY_REPORT/);
  }
});
