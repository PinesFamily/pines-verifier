import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {pageProbe, claudeProbeReport, FIXED_ROUTES} from '../capture/claude-probe.mjs';

const ORG = '0f0e0d0c-0b0a-4908-8706-050403020100', ACCOUNT = '11111111-2222-4333-8444-555555555555';
const EMAIL = 'canary-person@example.com', SESSION = 'sk-ant-sid01-' + 'x'.repeat(80);
const org = {uuid: ORG, name: 'Canary Person’s Organization', rate_limit_tier: 'default_claude_max_20x',
  capabilities: ['chat', 'claude_max'], billing_type: 'stripe_subscription', settings: {[ORG]: true}};
const bodies = {
  '/api/organizations': [org],
  [`/api/organizations/${ORG}`]: org,
  '/api/account': {uuid: ACCOUNT, email_address: EMAIL, memberships: [{role: 'admin', organization: org}]},
  '/api/bootstrap': {account: {uuid: ACCOUNT}},
  'https://assets.example/app.js': 'x("default_claude_ai");y("default_claude_max_5x");z("claude_pro","raven");f("/api/account")',
};
function env() {
  return {crypto: webcrypto, TextEncoder, navigator: {userAgent: 'Probe-Test'},
    document: {scripts: [{src: 'https://assets.example/app.js'}]}, performance: {getEntriesByType: () => []},
    fetch: async path => {
      const body = bodies[path];
      return {ok: body !== undefined, status: body === undefined ? 404 : 200,
        headers: {get: () => 'application/json'}, text: async () => typeof body === 'string' ? body : JSON.stringify(body ?? {})};
    }};
}
const run = () => pageProbe({salt: 'test-salt', routes: FIXED_ROUTES, statusOnly: ['/api/bootstrap']}, env());

test('the page probe keeps plan enums and replaces identities with salted tags', async () => {
  const {report, targets} = await run();
  const text = JSON.stringify({...report, userAgent: undefined});
  for (const canary of [ORG, ACCOUNT, EMAIL, 'Canary Person']) assert.equal(text.includes(canary), false, canary);
  assert.deepEqual(targets, [`/api/organizations/${ORG}`]);
  const detail = report.organizations[0].detail.shape;
  assert.deepEqual(detail.rate_limit_tier, {enum: 'default_claude_max_20x'});
  assert.deepEqual(detail.capabilities, {enums: ['chat', 'claude_max']});
  assert.equal(detail.uuid.tag, report.organizations[0].tag, 'the org detail and the list entry are the same identity');
  assert.deepEqual(Object.keys(detail.settings), ['<key>'], 'a UUID used as a key is not a key name');
  assert.equal(report.routes['/api/bootstrap'].shape, undefined, 'bootstrap is sized, not read');
  assert.deepEqual(report.client.rateLimitTiers, ['default_claude_ai', 'default_claude_max_5x']);
  assert.deepEqual(report.client.capabilityNames, ['claude_pro', 'raven']);
});

test('the report writer refuses anything identity- or credential-shaped', async () => {
  const {report} = await run(); delete report.userAgent;
  const cookies = [{name: 'sessionKey', value: SESSION, httpOnly: true}];
  const text = claudeProbeReport(report, cookies, {}, 'Chrome/154.0');
  assert.equal(text.includes(SESSION), false);
  assert.deepEqual(JSON.parse(text).cookies, [{name: 'sessionKey', httpOnly: true, bytes: SESSION.length}]);
  for (const leak of [ORG, EMAIL, SESSION]) {
    assert.throws(() => claudeProbeReport({...report, routes: {leak}}, [], {}, 'Chrome/154.0'), /PROBE_REPORT_LEAK/);
  }
});
