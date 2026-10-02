// Exercise the production controller with an isolated Chrome API double. No provider traffic.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {loadRegistry} from '../verification-schemas/src/index.ts';
const schema = (await loadRegistry()).list().find(e => e.reference.schemaId === 'pines.grok.plan').reference;
const config = {chatgptIdentity: true, captureProvider: true, schemas: [schema], origins: ['https://app.pines.family']};
const event = () => {const listeners = []; return {listeners, addListener: fn => listeners.push(fn), removeListener: fn => {const i = listeners.indexOf(fn); if (i >= 0) listeners.splice(i, 1);}};};
async function fixture({granted = false, phase = 'awaiting-capture', previouslyGranted = false, restored} = {}) {
  const job = restored ?? {runId: randomUUID(), recipient: '0x' + '1'.repeat(40), schema, phase, permissionPending: !granted, permissionGranted: previouslyGranted,
    automaticCapture: true, deadline: Date.now() + 60000, captureExpiresAt: Date.now() + 60000,
    owner: {windowId: 1, tabId: 1, origin: 'https://app.pines.family', documentId: 'owner'}};
  let saved = structuredClone(job), openCount = 0;
  const messages = [];
  const browser = {
    storage: {session: {get: async () => ({job: restored || ['proving', 'completed', 'failed', 'cancelled'].includes(phase) ? structuredClone(job) : null}), set: async value => {saved = value.job;}}},
    runtime: {id: 'test', getURL: path => `chrome-extension://test/${path}`, onMessage: event(), onMessageExternal: event(), onConnectExternal: event(),
      getContexts: async () => [{}], sendMessage: async message => {
        messages.push(message); return message.type === 'status' ? {ok: true, state: {runId: job.runId, phase}} : {ok: true};
      }},
    permissions: {contains: async () => granted, onRemoved: event()},
    tabs: {onRemoved: event(), onUpdated: event(), onDetached: event(), create: async () => {openCount++; throw Error('synthetic tab failure');}},
    alarms: {onAlarm: event(), create: async () => {}}, sidePanel: {setPanelBehavior: async () => {}, open: async () => {}},
  };
  globalThis.chrome = browser;
  let source = await readFile(new URL('../src/background.js', import.meta.url), 'utf8');
  source = source.replace("import config from './config.js';", `const config = ${JSON.stringify(config)};`)
    .replaceAll("'./schemas/src/index.js'", JSON.stringify(new URL('../verification-schemas/src/index.ts', import.meta.url).href))
    .replace(/from '(\.\/[^']+)'/g, (_, path) => `from ${JSON.stringify(new URL('../src/' + path.slice(2), import.meta.url).href)}`);
  await import('data:text/javascript;base64,' + Buffer.from(source + `\n// ${randomUUID()}`).toString('base64'));
  const sender = {origin: job.owner.origin, url: job.owner.origin, frameId: 0, documentId: 'owner', tab: {id: 1, windowId: 1, incognito: false}};
  const external = (type, fields = {}) => new Promise(resolve => browser.runtime.onMessageExternal.listeners[0](
    {protocol: 'pines-tlsn-bridge-v1', type, ...fields}, sender, resolve));
  const port = {name: 'pines-tlsn-owner-v1', sender, onMessage: event(), onDisconnect: event(), disconnect() {},
    postMessage(message) {for (const fn of this.onMessage.listeners) fn(message);}};
  browser.runtime.onConnectExternal.listeners[0](port);
  if (!restored && !['proving', 'completed', 'failed', 'cancelled'].includes(phase)) {
    await external('bridge-open-panel');
    const prepared = await external('prepare-provider', {recipient: job.recipient, schema});
    assert.equal(prepared.ok, true); job.runId = prepared.runId;
    if (phase === 'awaiting-disclosure') {
      // The worker state path is independent of restart restoration.
      await new Promise(resolve => browser.runtime.onMessage.listeners[0]({target: 'background', type: 'worker-state',
        state: {runId: job.runId, phase}}, {id: 'test', url: browser.runtime.getURL('offscreen.html')}, resolve));
      granted = false;
    }
  }
  const send = (type, extra = {}) => new Promise(resolve => browser.runtime.onMessage.listeners[0](
    {target: 'background', type, windowId: 1, runId: job.runId, ...extra}, {id: 'test', url: browser.runtime.getURL('panel.html')}, resolve));
  const externalStatus = () => new Promise(resolve => browser.runtime.onMessageExternal.listeners[0](
    {protocol: 'pines-tlsn-bridge-v1', type: 'verification-status', runId: job.runId, recipient: job.recipient},
    {origin: job.owner.origin, url: job.owner.origin, frameId: 0, documentId: 'owner', tab: {id: 1, windowId: 1, url: job.owner.origin, incognito: false}}, resolve));
  return {send, external, externalStatus, browser, messages, saved: () => saved, openCount: () => openCount, grant: () => {granted = true;}, revoke: () => {granted = false;}};
}
test('missing access blocks opening and denial cancels both controller and proof worker', async () => {
  const f = await fixture();
  assert.equal((await f.send('panel-status')).state.phase, 'awaiting-permission');
  assert.equal(f.openCount(), 0);
  assert.equal((await f.send('panel-permission', {granted: false})).ok, true);
  assert.equal(f.saved().phase, 'cancelled'); assert.equal(f.saved().error, 'PROVIDER_PERMISSION_DENIED');
  assert(f.messages.some(m => m.type === 'cancel')); assert.equal(f.openCount(), 0);
});
test('a forged grant and a stale run cannot open a provider', async () => {
  const f = await fixture();
  assert.equal((await f.send('panel-permission', {granted: true, runId: randomUUID()})).error, 'STALE_RUN');
  assert.equal((await f.send('panel-permission', {granted: true})).error, 'PERMISSION_REVOKED');
  assert.equal(f.openCount(), 0); assert(!f.messages.some(m => m.type === 'approve'));
});
test('an actual grant finishes preparation without opening a provider or consuming a ticket', async () => {
  const f = await fixture(); f.grant();
  assert.equal((await f.send('panel-permission', {granted: true})).ok, true);
  assert.equal(f.openCount(), 0); assert.equal(f.saved().permissionGranted, true);
  assert.equal(f.saved().preparing, true); assert.equal(f.messages.length, 0);
  assert.equal((await f.send('panel-status')).state.preparationReady, true);
});
test('lost permission blocks Share even if onRemoved has not arrived yet', async () => {
  const f = await fixture({phase: 'awaiting-disclosure', granted: true, previouslyGranted: true});
  assert.equal((await f.send('panel-approve')).error, 'PERMISSION_REVOKED');
  assert.equal(f.saved().phase, 'failed'); assert(!f.messages.some(m => m.type === 'approve'));
});
test('revocation during proving aborts the worker and fails the run', async () => {
  const f = await fixture({phase: 'proving', previouslyGranted: true});
  f.browser.permissions.onRemoved.listeners[0]({origins: ['https://grok.com/*']});
  for (let i = 0; i < 100 && !f.messages.some(m => m.type === 'cancel'); i++) await new Promise(resolve => setTimeout(resolve, 5));
  assert.equal(f.saved().phase, 'failed'); assert.equal(f.saved().error, 'PERMISSION_REVOKED');
  assert(f.messages.some(m => m.type === 'cancel'));
});

test('a saved Chrome grant skips the permission stage before API admission', async () => {
  const f = await fixture({granted: true});
  assert.equal((await f.send('panel-status')).state.phase, 'awaiting-capture');
  assert.equal(f.openCount(), 0); assert.equal(f.saved().permissionPending, false);
});


test('return persists panel home while preserving terminal status for the owner page', async () => {
  for (const phase of ['failed', 'cancelled', 'completed']) {
    const f = await fixture({phase});
    f.browser.tabs.get = async () => ({id: 1, windowId: 1, url: 'https://app.pines.family/'});
    f.browser.tabs.update = async () => {};
    f.browser.windows = {update: async () => {}};
    f.browser.sidePanel.close = async () => {
      assert.equal(f.saved().panelDismissed, true);
      throw Error('synthetic close refusal');
    };
    // completed recovery is eligible after its confirmation wait has elapsed.
    if (phase === 'completed') {
      await f.send('panel-cancel'); // persists receiptWaitStopped without cancelling the completed proof
    }
    assert.equal((await f.send('panel-recover')).ok, true);
    assert.equal((await f.send('panel-status')).state, null);
    assert.equal((await f.externalStatus()).phase, phase);
    assert.equal((await f.send('panel-recover')).error, 'STALE_RUN');
    assert.equal(f.saved().receiptVerified, undefined);
    assert(!f.messages.some(m => m.type === 'approve'));
    const restarted = await fixture({phase, restored: f.saved()});
    assert.equal((await restarted.send('panel-status')).state, null);
    assert.equal((await restarted.externalStatus()).phase, phase);
  }
});

test('refused admission requires a fresh owner gesture, survives restart, and cannot replace an active proof', async () => {
  for (const phase of ['failed', 'proving']) {
    const f = await fixture({phase});
    f.browser.sidePanel.open = async () => {};
    const owner = {origin: 'https://app.pines.family', url: 'https://app.pines.family/', frameId: 0, documentId: 'owner',
      tab: {id: 1, windowId: 1, url: 'https://app.pines.family/', incognito: false}};
    const external = (type, fields = {}, sender = owner) => new Promise(resolve => f.browser.runtime.onMessageExternal.listeners[0](
      {protocol: 'pines-tlsn-bridge-v1', type, ...fields}, sender, resolve));
    const fields = {recipient: f.saved().recipient, schema, error: 'RATE_LIMITED', retryAt: Date.now() + 60000};
    assert.equal((await external('verification-refused', fields)).error, 'PANEL_GESTURE_REQUIRED');
    assert.equal((await external('bridge-open-panel')).ok, true);
    assert.equal((await external('verification-refused', fields, {...owner, documentId: 'other'})).error, 'PANEL_GESTURE_REQUIRED');
    const result = await external('verification-refused', fields);
    if (phase === 'proving') {assert.equal(result.error, 'BUSY'); assert.equal(f.saved().phase, phase); continue;}
    assert.equal(result.ok, true);
    assert.equal(f.saved().retryAt, fields.retryAt);
    assert.equal(f.saved().attemptId, undefined);
    assert.equal(f.openCount(), 0); assert.equal(f.messages.length, 0);
    assert.equal((await external('verification-refused', fields)).error, 'PANEL_GESTURE_REQUIRED');
    const restarted = await fixture({phase: 'failed', restored: f.saved()});
    assert.equal((await restarted.send('panel-status')).state.retryAt, fields.retryAt);
    restarted.browser.tabs.get = async () => ({id: 1, windowId: 1, url: owner.url});
    restarted.browser.tabs.update = async () => {};
    restarted.browser.windows = {update: async () => {}};
    restarted.browser.sidePanel.close = async () => {};
    assert.equal((await restarted.send('panel-recover')).ok, true);
    assert.equal((await restarted.send('panel-status')).state, null);
  }
});

test('worker restart invalidates an automatic pre-reveal run instead of restoring its capture lease', async () => {
  const prepared = await fixture({granted: true});
  const restarted = await fixture({restored: prepared.saved()});
  assert.equal((await restarted.send('panel-status')).state.error, 'WORKER_RESTARTED');
  assert.equal(restarted.openCount(), 0);
});

test('cancel or revoke while API admission is pending cannot restart a prepared run', async () => {
  for (const revoke of [false, true]) {
    const f = await fixture({granted: true}); const prepared = f.saved();
    if (revoke) f.revoke(); else await f.send('panel-cancel');
    const response = await f.external('verify-provider', {preparationId: prepared.runId, recipient: prepared.recipient, attempt: {}});
    assert.equal(response.error, revoke ? 'PERMISSION_REVOKED' : 'CANCELLED');
    assert.equal(f.openCount(), 0); assert(!f.messages.some(m => m.type === 'start'));
  }
});
test('an older page gets an explicit update error before starting the new guided flow', async () => {
  const f = await fixture({phase: 'failed'});
  const response = await f.external('verify-provider', {recipient: f.saved().recipient, attempt: {}});
  assert.equal(response.error, 'EXTENSION_UPDATE_REQUIRED'); assert.equal(f.openCount(), 0);
});
