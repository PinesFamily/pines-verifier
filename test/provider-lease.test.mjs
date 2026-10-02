import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {loadRegistry} from '../verification-schemas/src/index.ts';
import {ProviderCapture} from '../src/provider-capture.js';
import {providerUrl} from '../src/provider-flow.js';
const schemas = (await loadRegistry()).list();
const event = () => {const listeners = new Set(); return {listeners, addListener: fn => listeners.add(fn), removeListener: fn => listeners.delete(fn), emit: (...args) => {for (const fn of [...listeners]) fn(...args);}};};
const settle = () => new Promise(resolve => setImmediate(resolve));
function fixture(provider = 'chatgpt') {
  const schema = schemas.find(e => e.reference.schemaId === `pines.${provider}.plan` && e.reference.version === (provider === 'chatgpt' ? 3 : 1)).schema;
  const job = {runId: randomUUID(), phase: 'awaiting-capture', captureExpiresAt: Date.now()+30000, ownedProviderTabId: 2,
    owner: {tabId: 1, windowId: 1, documentId: 'pines'}};
  const tab = {id: 2, windowId: 1, incognito: false, url: 'about:blank', status: 'complete'};
  let granted = true, alive = true, current = job;
  const browser = {permissions: {contains: async () => granted, onRemoved: event()},
    tabs: {get: async () => ({...tab}), update: async (_, {url}) => {
      tab.url = url; browser.webRequest.onBeforeRequest.emit({tabId: 2, frameId: 0, type: 'main_frame', url, requestId: 'navigation'});
      browser.tabs.onUpdated.emit(2, {status: 'loading'});
    }, onUpdated: event(), onRemoved: event(), onDetached: event(), onReplaced: event()},
    webRequest: {onBeforeRequest: event(), onBeforeSendHeaders: event(), onBeforeRedirect: event()}};
  const delivered = [], failures = [];
  const controller = new ProviderCapture({browser, current: () => current, ownerReady: async () => alive,
    owner: async (_, owner) => {job.providerOwner = owner;},
    deliver: async (runId, replay) => {delivered.push({runId, replay}); job.phase = 'requesting';},
    fail: async code => {failures.push(code); job.phase = 'failed';}});
  const request = {tabId: 2, frameId: 0, type: 'xmlhttprequest', documentId: 'provider', documentLifecycle: 'active',
    initiator: schema.request.origin, url: schema.request.origin + (provider === 'chatgpt' ? '/backend-api/wham/usage' : provider === 'claude' ? '/api/account_profile' : '/rest/subscriptions'), method: 'GET',
    requestHeaders: [{name: 'Authorization', value: 'Bearer synthetic-secret'}, {name: 'User-Agent', value: 'Pines-Test'},
      {name: 'Cookie', value: 'sessionKey=synthetic-secret; sso=synthetic-secret; ignored=unselected'}]};
  const emit = (changes = {}) => {const d = {...request, ...changes}; browser.webRequest.onBeforeRequest.emit(d); browser.webRequest.onBeforeSendHeaders.emit(d);};
  return {job, schema, tab, browser, controller, delivered, failures, request, emit,
    start: () => controller.start(job, schema, {tabId: 2, navigateTo: providerUrl(schema)}),
    revoke: () => {granted = false;}, leave: () => {alive = false;}, replace: () => {current = {...job};},
    listeners: () => Object.values(browser).flatMap(group => Object.values(group)).reduce((n, value) => n + (value?.listeners?.size ?? 0), 0)};
}
for (const provider of ['chatgpt', 'claude', 'grok']) test(`${provider}: fresh owned document delivers one filtered replay without privileged navigation APIs`, async () => {
  const f = fixture(provider); await f.start(); f.emit(); await settle();
  assert.equal(f.delivered.length, 1); assert.equal(f.delivered[0].runId, f.job.runId);
  assert.equal(JSON.stringify(f.job).includes('synthetic-secret'), false);
  assert.equal(JSON.stringify(f.delivered).includes('unselected'), false);
  f.emit(); await settle(); assert.equal(f.delivered.length, 1);
  assert.equal(f.browser.webRequest.onBeforeSendHeaders.listeners.size, 0);
  await f.controller.validate(f.job);
  f.controller.cancel(); assert.equal(f.listeners(), 0);
});
test('incorrect tab/frame/initiator/lifecycle or absent document cannot bind or capture', async () => {
  const f = fixture(); await f.start();
  for (const change of [{tabId: 99}, {frameId: 1}, {initiator: 'https://evil.test'}, {documentLifecycle: 'cached'}, {documentLifecycle: 'prerender'}, {documentId: undefined}]) f.emit(change);
  await settle(); assert.equal(f.delivered.length, 0); assert.equal(f.job.providerOwner, null);
  f.emit(); await settle(); assert.equal(f.delivered.length, 1); f.controller.cancel();
});
test('old header callbacks cannot supply credentials to the newly bound document', async () => {
  const f = fixture(); await f.start(); f.browser.webRequest.onBeforeRequest.emit(f.request);
  f.browser.webRequest.onBeforeSendHeaders.emit({...f.request, documentId: 'old-document'}); await settle();
  assert.equal(f.delivered.length, 0); f.emit(); await settle(); assert.equal(f.delivered.length, 1); f.controller.cancel();
});
test('navigation, redirects, hidden routes, blank pages, replacement, detach and closure invalidate capture and Share', async () => {
  const changes = [
    f => f.browser.webRequest.onBeforeRequest.emit({tabId: 2, frameId: 0, type: 'main_frame', url: f.tab.url, requestId: 'reload'}),
    f => f.browser.webRequest.onBeforeRedirect.emit({tabId: 2, type: 'main_frame'}),
    f => f.browser.tabs.onUpdated.emit(2, {status: 'loading'}, {id: 2, status: 'loading'}),
    f => f.browser.tabs.onUpdated.emit(2, {url: 'about:blank'}),
    f => f.browser.tabs.onUpdated.emit(2, {url: 'https://example.test'}),
    f => f.browser.tabs.onRemoved.emit(2), f => f.browser.tabs.onDetached.emit(2), f => f.browser.tabs.onReplaced.emit(3, 2),
    f => f.browser.permissions.onRemoved.emit({origins: ['https://chatgpt.com/*']}),
    f => f.browser.webRequest.onBeforeRequest.emit({...f.request, documentId: 'new-document'}),
  ];
  for (const share of [false, true]) for (const change of changes) {
    const f = fixture(); await f.start(); f.browser.webRequest.onBeforeRequest.emit(f.request);
    if (share) {f.emit(); await settle(); assert.equal(f.delivered.length, 1);}
    change(f); f.emit(); await settle();
    assert.equal(f.delivered.length, share ? 1 : 0); assert.equal(f.listeners(), 0);
    await assert.rejects(f.controller.validate(f.job));
  }
});
test('permission and current tab are rechecked without relying on notification delivery', async () => {
  for (const change of [f => f.revoke(), f => {f.tab.url = 'https://other.test';}, f => {f.tab.windowId = 7;},
    f => {f.tab.pendingUrl = 'https://elsewhere.test';}, f => f.leave(), f => {f.job.captureExpiresAt = Date.now()-1;}]) {
    const f = fixture(); await f.start(); change(f); f.emit(); await settle();
    assert.equal(f.delivered.length, 0); assert.equal(f.listeners(), 0);
  }
});
test('capture and cancellation during asynchronous setup never leak a listener or replay twice', async () => {
  for (const cancel of [false, true]) {
    const f = fixture(), navigate = f.browser.tabs.update;
    f.browser.tabs.update = async (...args) => {await navigate(...args); f.emit(); if (cancel) f.controller.cancel();};
    if (cancel) await assert.rejects(f.start(), /STALE_RUN/); else await f.start();
    await settle(); assert.equal(f.delivered.length, cancel ? 0 : 1);
    f.controller.cancel(); assert.equal(f.listeners(), 0);
  }
});
test('navigation failures are bounded and grants precede any webRequest registration', async () => {
  const f = fixture(); f.revoke(); await assert.rejects(f.start(), /CAPTURE_PERMISSION_LOST/); assert.equal(f.listeners(), 0);
  const g = fixture(); g.browser.tabs.update = async () => {throw Error('private browser detail');};
  await assert.rejects(g.start(), {message: 'PROVIDER_OPEN_FAILED'}); assert.equal(g.listeners(), 0);
});

for (const provider of ['chatgpt', 'claude', 'grok']) test(`${provider}: same-document URL loading updates preserve capture before and after replay`, async () => {
  const f = fixture(provider); await f.start();
  const update = suffix => {f.tab.url = providerUrl(f.schema) + suffix;
    f.browser.tabs.onUpdated.emit(2, {status: 'loading', url: f.tab.url});
    f.browser.tabs.onUpdated.emit(2, {status: 'complete'});};
  update('?boot=1'); f.emit(); await settle(); assert.equal(f.delivered.length, 1);
  // Identical-URL history updates omit change.url entirely in Chrome.
  f.browser.tabs.onUpdated.emit(2, {status: 'loading'}, {...f.tab});
  f.browser.tabs.onUpdated.emit(2, {status: 'complete'}, {...f.tab});
  await f.controller.validate(f.job);
  for (const suffix of ['?review=1', '#review', '']) {update(suffix); await f.controller.validate(f.job);}
  assert.equal(f.job.providerOwner.documentId, 'provider'); assert.deepEqual(f.failures, []);
  // A real navigation to another query is a new document even though its route still matches.
  f.browser.webRequest.onBeforeRequest.emit({tabId: 2, frameId: 0, type: 'main_frame', url: f.tab.url+'?new-document=1', requestId: 'new-navigation'});
  assert.equal(f.failures.at(-1), 'CAPTURE_NAVIGATED'); assert.equal(f.listeners(), 0);
  await assert.rejects(f.controller.validate(f.job));
});
