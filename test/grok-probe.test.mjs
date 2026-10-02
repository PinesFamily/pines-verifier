import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto, createHash} from 'node:crypto';
import {pageProbe, grokProbeReport, identityTags, cookieVariants, CANDIDATE_ROUTES, READ_WORTHY, NEVER_READ} from '../capture/grok-probe.mjs';

const USER = '0f0e0d0c-0b0a-4908-8706-050403020100', X_USER = '1790000000000000001';
const EMAIL = 'canary-person@example.com', SSO = 'eyJhbGciOiJIUzI1NiJ9.' + 'x'.repeat(120);
const subscriptions = {subscriptions: [{id: 'sub_canary_0001', xaiUserId: USER, tier: 'SUBSCRIPTION_TIER_GROK_PRO',
  status: 'SUBSCRIPTION_STATUS_ACTIVE', billingPeriod: 'monthly', createTime: '2026-09-01T00:00:00Z'}]};
const bodies = {
  '/rest/subscriptions': subscriptions,
  '/rest/auth/get-user': {userId: USER, xUserId: X_USER, email: EMAIL, givenName: 'Canary', isPremium: true},
  '/rest/user-profile': {userId: USER, displayName: 'Canary Person'},
  'https://assets.example/app.js': [
    'a("/rest/subscriptions");b("/rest/user-profile");c("/rest/app-chat/conversations/delete-all")',
    'd(`/rest/app-chat/conversations/${id}`);e("SUBSCRIPTION_TIER_SUPER_GROK_PRO");f("SUBSCRIPTION_STATUS_ACTIVE")',
    'g("SuperGrok");h("/rest/media/upload")'].join(';'),
};
const requested = [];
function env() {
  return {crypto: webcrypto, TextEncoder, navigator: {userAgent: 'Probe-Test'}, location: {origin: 'https://grok.com'},
    document: {scripts: [{src: 'https://assets.example/app.js'}]},
    performance: {getEntriesByType: () => [{name: `https://grok.com/rest/app-chat/conversations/${USER}/responses`, initiatorType: 'fetch'},
      {name: 'https://grok.com/rest/rate-limits', initiatorType: 'fetch'}]},
    fetch: async path => {
      requested.push(path);
      const body = bodies[path];
      return {ok: body !== undefined, status: body === undefined ? 404 : 200,
        headers: {get: () => 'application/json'}, text: async () => typeof body === 'string' ? body : JSON.stringify(body ?? {})};
    }};
}
const run = () => pageProbe({salt: 'test-salt', candidates: CANDIDATE_ROUTES, readWorthy: READ_WORTHY.source, neverRead: NEVER_READ.source}, env());

test('the page probe keeps tier enums and replaces identities with salted tags', async () => {
  const report = await run(); delete report.userAgent;
  const text = JSON.stringify(report);
  for (const canary of [USER, X_USER, EMAIL, 'Canary', 'sub_canary']) assert.equal(text.includes(canary), false, canary);
  const sub = report.routes['/rest/subscriptions'].shape.subscriptions.items[0];
  assert.deepEqual(sub.tier, {enum: 'SUBSCRIPTION_TIER_GROK_PRO'});
  assert.deepEqual(sub.status, {enum: 'SUBSCRIPTION_STATUS_ACTIVE'});
  assert.deepEqual(sub.billingPeriod, {enum: 'monthly'});
  const user = report.routes['/rest/auth/get-user'].shape;
  assert.equal(sub.xaiUserId.tag, user.userId.tag, 'the same account is visible across routes');
  assert.equal(user.xUserId.id, 'digits');
  assert.deepEqual(user.isPremium, {bool: true});
  assert.deepEqual(report.client.subscriptionTiers, ['SUBSCRIPTION_TIER_SUPER_GROK_PRO']);
  assert.deepEqual(report.client.planWords, ['SuperGrok']);
  assert.deepEqual(report.client.templatedRoutes, ['/rest/app-chat/conversations/${id}']);
  assert.deepEqual(report.observedRequests, ['fetch:/rest/app-chat/conversations/<id>/responses', 'fetch:/rest/rate-limits']);
});

test('only read-worthy discovered routes are read, and nothing that sounds like a write', async () => {
  requested.length = 0;
  const report = await run();
  assert.ok('/rest/user-profile' in report.routes, 'a discovered profile route is read');
  for (const path of ['/rest/app-chat/conversations/delete-all', '/rest/media/upload'])
    assert.equal(requested.includes(path), false, path);
});

test('the report writer refuses anything identity- or credential-shaped', async () => {
  const report = await run(); delete report.userAgent;
  const cookies = [{name: 'sso', value: SSO, httpOnly: true}];
  const text = grokProbeReport(report, cookies, {}, 'Chrome/154.0');
  assert.equal(text.includes(SSO), false);
  assert.deepEqual(JSON.parse(text).cookies, [{name: 'sso', httpOnly: true, bytes: SSO.length}]);
  for (const leak of [USER, EMAIL, SSO, X_USER])
    assert.throws(() => grokProbeReport({...report, routes: {leak}}, [], {}, 'Chrome/154.0'), /PROBE_REPORT_LEAK/);
});

test('replay identities are tags, and cookie variants isolate the session cookies', () => {
  const tag = v => createHash('sha256').update('s:' + v).digest('hex').slice(0, 12);
  const tags = identityTags(bodies['/rest/auth/get-user'], tag);
  assert.deepEqual(tags, [`userId:${tag(USER)}`, `xUserId:${tag(X_USER)}`].sort());
  const variants = cookieVariants(['sso', 'sso-rw', 'cf_clearance', '__cf_bm', 'i18nextLng'].map(name => ({name})));
  assert.deepEqual(variants.withoutCloudflare, ['sso', 'sso-rw', 'i18nextLng']);
  assert.deepEqual(variants['only:sso'], ['sso']);
  assert.deepEqual(variants.sessionCookies, ['sso', 'sso-rw']);
  assert.deepEqual(variants.none, []);
  assert.equal(variants.all, null);
  assert.deepEqual(variants['cf_clearance+sso'], ['cf_clearance', 'sso']);
  assert.deepEqual(variants['cf_clearance+sessionCookies'], ['cf_clearance', 'sso', 'sso-rw']);
  assert.deepEqual(variants.withoutCfBm, ['sso', 'sso-rw', 'cf_clearance', 'i18nextLng']);
});
