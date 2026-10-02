import test from 'node:test';
import assert from 'node:assert/strict';
import {checkProviderPermission, providerPermission} from '../src/provider-permission.js';
import {publicState} from '../src/policy.js';
import {progressOf} from '../src/progress.js';

test('each provider asks for exactly its own origin, and existing grants skip the wait', async () => {
  for (const [provider, host] of [['chatgpt', 'chatgpt.com'], ['claude', 'claude.ai'], ['grok', 'grok.com']]) {
    const job = {schema: {schemaId: `pines.${provider}.plan`}, phase: 'awaiting-capture'};
    const browser = {permissions: {contains: async request => {
      assert.deepEqual(request, {origins: [`https://${host}/*`]}); return true;
    }}};
    assert.equal(await checkProviderPermission(browser, job), true);
    assert.equal(job.permissionPending, false);
    assert.equal(publicState(job).phase, 'awaiting-capture');
    browser.permissions.contains = async () => false;
    await assert.rejects(checkProviderPermission(browser, job), /PERMISSION_REVOKED/);
  }
});

test('missing permission waits without pretending to open a tab; grant resumes, revocation fails closed', async () => {
  const job = {schema: {schemaId: 'pines.grok.plan'}, phase: 'awaiting-capture'};
  let allowed = false;
  const browser = {permissions: {contains: async () => allowed}};
  assert.equal(await checkProviderPermission(browser, job), false);
  assert.equal(publicState(job).phase, 'awaiting-permission');
  assert.match(progressOf(publicState(job)).detail, /Allow access to grok.com/);
  allowed = true;
  assert.equal(await checkProviderPermission(browser, job), true);
  assert.equal(publicState(job).phase, 'awaiting-capture');
  allowed = false;
  await assert.rejects(checkProviderPermission(browser, job), /PERMISSION_REVOKED/);
  job.phase = 'failed'; job.error = 'PERMISSION_REVOKED';
  assert.equal(publicState(job).phase, 'failed');
});

test('denial remains a clear terminal cancellation even with a pending permission flag', () => {
  const state = publicState({schema: {schemaId: 'pines.claude.plan'}, permissionPending: true,
    phase: 'cancelled', error: 'PROVIDER_PERMISSION_DENIED'});
  assert.equal(state.phase, 'cancelled');
  assert.match(progressOf(state).description, /Access to claude.ai was declined/);
});

test('untrusted schema names cannot request arbitrary hosts; fixtures need no optional grant', async () => {
  for (const id of ['https://evil.test/*', 'toString', '__proto__', 'pines.fixture.httpbingo']) {
    assert.equal(providerPermission(id), null);
    assert.equal(await checkProviderPermission({}, {schema: {schemaId: id}}), true);
  }
});
