import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {loadRegistry, requestUrl} from '../verification-schemas/src/index.ts';
import {CaptureSession, captureProvider} from '../capture/session.mjs';
import {captureReport} from '../capture/measure.mjs';

const registry = await loadRegistry();
const schema = registry.list().find(entry => entry.reference.schemaId === 'pines.chatgpt.plan').schema;
const canary = 'Bearer capture-test-credential-canary';
function fixture(overrides = {}) {
  const owner = {runId: randomUUID(), tabId: 7, windowId: 8, documentId: randomUUID()};
  const states = []; let now = Date.now();
  const session = new CaptureSession({schema, owner, deadline: now + 1000, now: () => now, onChange: state => states.push(state), ...overrides});
  const event = {tabId: owner.tabId, frameId: 0, documentId: owner.documentId, documentLifecycle: 'active',
    type: 'xmlhttprequest', initiator: schema.request.origin, url: requestUrl(schema), method: 'GET',
    requestHeaders: [{name: ':authority', value: 'chatgpt.com'}, {name: 'Authorization', value: canary},
      {name: 'User-Agent', value: 'Pines-Capture-Test'}, {name: 'Cookie', value: 'unselected-cookie-canary'},
      {name: 'X-Extra-Secret', value: 'unselected-secret-canary'}]};
  return {owner, session, event, states, advance: ms => {now += ms;}};
}
test('native capture selects only schema headers and hands off fixed replay once', () => {
  const f = fixture(); assert.equal(f.session.observe(f.event), true);
  assert.equal(f.session.status().phase, 'captured');
  assert.equal(JSON.stringify(f.states).includes(canary), false);
  assert.equal(JSON.stringify(f.session.status()).includes('unselected'), false);
  assert.throws(() => f.session.take(randomUUID()), /CAPTURE_UNAVAILABLE/);
  const replay = f.session.take(f.owner.runId);
  assert.equal(replay.headers.authorization, canary); assert.equal(replay.headers['user-agent'], 'Pines-Capture-Test');
  assert.equal(replay.headers.cookie, undefined); assert.equal(replay.headers['x-extra-secret'], undefined);
  assert.equal(replay.headers.accept, 'application/json'); assert.equal(replay.headers['accept-encoding'], 'identity');
  assert.equal(replay.url, requestUrl(schema)); assert.equal(replay.body, '');
  assert.equal(f.session.status().phase, 'consumed');
  assert.throws(() => f.session.take(f.owner.runId), /CAPTURE_UNAVAILABLE/);
  assert.equal(f.session.observe(f.event), false);
});
test('other tabs, frames, documents, initiators, routes and methods cannot supply a capture', () => {
  const f = fixture();
  for (const change of [{tabId: 99}, {frameId: 1}, {documentId: randomUUID()}, {documentLifecycle: 'prerender'},
    {documentId: undefined}, {initiator: 'https://example.test'}, {initiator: undefined}, {url: requestUrl(schema) + '?extra=1'},
    {url: schema.request.origin + '/backend-api/other'}, {method: 'POST'}, {type: 'main_frame'}]) {
    assert.equal(f.session.observe({...f.event, ...change}), false);
    assert.equal(f.session.status().phase, 'waiting');
  }
});
test('missing, binary, duplicate, injected and oversized captured headers fail without leaking values', () => {
  const base = fixture().event.requestHeaders;
  for (const headers of [[], base.filter(header => header.name !== 'Authorization'),
    [...base, {name: 'authorization', value: canary}],
    base.map(header => header.name === 'Authorization' ? {...header, value: 'Bearer a\r\nX-Evil: canary'} : header),
    base.map(header => header.name === 'Authorization' ? {name: header.name, binaryValue: [1, 2]} : header),
    base.map(header => header.name === 'Authorization' ? {...header, value: 'Bearer ' + 'a'.repeat(8192)} : header)]) {
    const f = fixture(); f.session.observe({...f.event, requestHeaders: headers});
    assert.equal(f.session.status().error, 'INVALID_CAPTURE');
    assert.equal(JSON.stringify(f.states).includes('canary'), false);
    assert.throws(() => f.session.take(f.owner.runId), /CAPTURE_UNAVAILABLE/);
  }
});
test('a provider-sized value fits the schema and can be consumed once', () => {
  const f = fixture();
  f.event.requestHeaders.find(header => header.name === 'Authorization').value = 'Bearer '.padEnd(2189, 'a');
  f.session.observe(f.event);
  assert.equal(f.session.status().phase, 'captured');
  assert.deepEqual(f.session.status().headers, [{name: 'authorization', bytes: 2189, secret: true}, {name: 'user-agent', bytes: 18, secret: true}]);
  assert.equal(f.session.take(f.owner.runId).headers.authorization.length, 2189);
  assert.equal(f.session.status().phase, 'consumed');
});
test('cancellation and wall-clock expiry erase captured replay even if timers are throttled', () => {
  for (const reason of ['CAPTURE_CANCELLED', 'CAPTURE_NAVIGATED', 'CAPTURE_TAB_CLOSED', 'CAPTURE_OWNER_CHANGED', 'CAPTURE_PERMISSION_LOST']) {
    const f = fixture(); f.session.observe(f.event); f.session.cancel(reason);
    assert.equal(f.session.status().error, reason); assert.throws(() => f.session.take(f.owner.runId), /CAPTURE_UNAVAILABLE/);
  }
  for (const captured of [false, true]) {
    const f = fixture(); if (captured) f.session.observe(f.event); f.advance(1000);
    assert.throws(() => f.session.take(f.owner.runId), /CAPTURE_UNAVAILABLE/);
    assert.equal(f.session.status().error, 'CAPTURE_TIMEOUT'); assert.equal(f.session.observe(f.event), false);
  }
});
test('unsupported body/cookie policies and unbounded owner/deadline configuration are rejected', () => {
  for (const overrides of [{schema: {...schema, request: {...schema.request, method: 'POST'}}},
    {schema: {...schema, capture: {...schema.capture, cookies: ['session']}}}, {owner: {}},
    {deadline: Date.now() + 180000}]) assert.throws(() => fixture(overrides));
});

function browserFixture(f = fixture(), captureSchema = schema) {
  const event = () => ({listeners: new Set(), options: [], addListener(fn, ...options) {this.listeners.add(fn); this.options.push(options);}, removeListener(fn) {this.listeners.delete(fn);}, emit(...args) {for (const fn of [...this.listeners]) fn(...args);}});
  const frame = {url: captureSchema.request.origin + '/', documentId: f.owner.documentId, documentLifecycle: 'active'};
  const browser = {
    tabs: {get: async () => ({id: f.owner.tabId, windowId: f.owner.windowId, incognito: false, url: frame.url}), onRemoved: event(), onDetached: event(), onReplaced: event()},
    webNavigation: {getFrame: async () => frame, onBeforeNavigate: event(), onCommitted: event()},
    webRequest: {onBeforeSendHeaders: event()}, permissions: {onRemoved: event()},
  };
  const listeners = () => Object.values(browser).flatMap(group => Object.values(group)).reduce((sum, value) => sum + (value.listeners?.size ?? 0), 0);
  const start = () => captureProvider({browser, schema: captureSchema, owner: f.owner, deadline: Date.now() + 5000});
  return {...f, browser, frame, listeners, start};
}
test('browser adapter stops interception after capture and retains navigation cancellation until handoff', async () => {
  const f = browserFixture(); const session = await f.start();
  assert.equal(f.listeners(), 7);
  // The untriggered schema listens only to its exact request URL.
  assert.deepEqual(f.browser.webRequest.onBeforeSendHeaders.options, [[{urls: [requestUrl(schema)], tabId: f.owner.tabId, types: ['xmlhttprequest']}, ['requestHeaders', 'extraHeaders']]]);
  f.browser.webRequest.onBeforeSendHeaders.emit(f.event);
  assert.equal(f.browser.webRequest.onBeforeSendHeaders.listeners.size, 0);
  assert.equal(session.status().phase, 'captured');
  f.browser.webNavigation.onBeforeNavigate.emit({tabId: f.owner.tabId, frameId: 0});
  assert.equal(session.status().error, 'CAPTURE_NAVIGATED'); assert.equal(f.listeners(), 0);
  await assert.rejects(session.take(f.owner.runId), /CAPTURE_UNAVAILABLE/);
});
test('browser adapter validates actual window/document and closes asynchronous setup races', async () => {
  const wrong = browserFixture(); wrong.frame.documentId = randomUUID();
  await assert.rejects(wrong.start(), /INVALID_CAPTURE_OWNER/); assert.equal(wrong.listeners(), 0);
  const raced = browserFixture(); let reads = 0;
  raced.browser.webNavigation.getFrame = async () => {
    if (++reads === 2) raced.browser.webNavigation.onBeforeNavigate.emit({tabId: raced.owner.tabId, frameId: 0});
    return raced.frame;
  };
  await assert.rejects(raced.start(), /CAPTURE_UNAVAILABLE/); assert.equal(raced.listeners(), 0);
});
test('browser lifecycle and permission removal erase pending credentials and detach every listener', async () => {
  for (const invalidate of [f => f.browser.tabs.onRemoved.emit(f.owner.tabId),
    f => f.browser.tabs.onDetached.emit(f.owner.tabId), f => f.browser.tabs.onReplaced.emit(100, f.owner.tabId),
    f => f.browser.permissions.onRemoved.emit({origins: ['https://chatgpt.com/*']})]) {
    const f = browserFixture(); const session = await f.start();
    f.browser.webRequest.onBeforeSendHeaders.emit(f.event); invalidate(f);
    assert.equal(session.status().phase, 'cancelled'); assert.equal(f.listeners(), 0);
    await assert.rejects(session.take(f.owner.runId), /CAPTURE_UNAVAILABLE/);
  }
});

test('handoff rechecks browser ownership even before a queued navigation event arrives', async () => {
  const f = browserFixture(); const session = await f.start();
  f.browser.webRequest.onBeforeSendHeaders.emit(f.event);
  f.frame.documentId = randomUUID();
  await assert.rejects(session.take(f.owner.runId), /CAPTURE_UNAVAILABLE/);
  assert.equal(session.status().error, 'CAPTURE_OWNER_CHANGED'); assert.equal(f.listeners(), 0);
});

test('measurement reports project bounded public metadata and reject secret-bearing string substitutions', () => {
  const f = fixture(); f.session.observe(f.event); f.session.take(f.owner.runId);
  const reference = registry.list().find(entry => entry.reference.schemaId === schema.schemaId).reference;
  const value = {ok: true, claimable: false, schema: reference, capture: f.session.status(), extra: canary};
  const report = captureReport(value, {reference, schema}, '154.0.8037.57');
  assert.equal(JSON.stringify(report).includes(canary), false);
  assert.equal(report.headers.length, 2);
  for (const change of [{phase: canary}, {error: canary}, {headers: [{name: canary, bytes: 20, secret: true}]},
    {headers: [{name: 'authorization', bytes: canary, secret: true}]}, {maxHeaderBytes: 1e9}, {claimable: true}]) {
    assert.throws(() => captureReport({...value, capture: {...value.capture, ...change}}, {reference, schema}, '154.0.8037.57'), /INVALID_CAPTURE_REPORT/);
  }
});

// Claude (pines.claude.plan@1): the credential is the origin-wide sessionKey cookie,
// taken from any same-origin GET the owned document makes under /api/.
const claude = registry.list().find(entry => entry.reference.schemaId === 'pines.claude.plan' && entry.reference.version === 1).schema;
const sessionKey = 'sk-ant-sid01-capture-test-session-secret';
function claudeFixture() {
  const owner = {runId: randomUUID(), tabId: 7, windowId: 8, documentId: randomUUID()};
  const states = []; const now = Date.now();
  const session = new CaptureSession({schema: claude, owner, deadline: now + 1000, now: () => now, onChange: state => states.push(state)});
  const event = {tabId: owner.tabId, frameId: 0, documentId: owner.documentId, documentLifecycle: 'active',
    type: 'xmlhttprequest', initiator: 'https://claude.ai', url: 'https://claude.ai/api/account_profile', method: 'GET',
    requestHeaders: [{name: ':authority', value: 'claude.ai'},
      {name: 'Cookie', value: `anthropic-device-id=device-canary; sessionKey=${sessionKey}; cf_clearance=clearance-canary; lastActiveOrg=org-canary`},
      {name: 'User-Agent', value: 'Pines-Capture-Test'}, {name: 'anthropic-client-sha', value: 'unselected-canary'},
      {name: 'Authorization', value: 'Bearer unselected-canary'}]};
  return {owner, session, event, states};
}
const leaks = value => ['canary', sessionKey].some(secret => JSON.stringify(value).includes(secret));
test('triggered capture takes sessionKey from the page API traffic and replays only the fixed request', () => {
  const f = claudeFixture(); assert.equal(f.session.observe(f.event), true);
  assert.equal(f.session.status().phase, 'captured');
  assert.deepEqual(f.session.status().headers, [{name: 'user-agent', bytes: 18, secret: true},
    {name: 'cookie', bytes: `sessionKey=${sessionKey}`.length, secret: true}]);
  assert.equal(leaks(f.states) || leaks(f.session.status()), false, 'status carries sizes, never cookie values');
  const replay = f.session.take(f.owner.runId);
  assert.equal(replay.url, 'https://claude.ai/api/organizations', 'captured from /api/account_profile, proven at the fixed route');
  assert.deepEqual({...replay.headers}, {accept: 'application/json', 'user-agent': 'Pines-Capture-Test', cookie: `sessionKey=${sessionKey}`,
    host: 'claude.ai', 'accept-encoding': 'identity', connection: 'close'});
  assert.equal(JSON.stringify(replay).includes('canary'), false, 'other cookies and unselected headers are dropped');
  assert.equal(f.session.observe(f.event), false);
});
test('triggered capture ignores other origins, paths, methods, initiators, documents and resource types', () => {
  const f = claudeFixture();
  for (const change of [{url: 'https://evil.example/api/account'}, {url: 'https://claude.ai.evil.example/api/x'}, {url: 'https://claude.ai/new'},
    {url: 'https://claude.ai/settings/billing'}, {url: 'https://claude.ai/apix'}, {url: 'https://claude.ai/api/x#f'}, {url: 'http://claude.ai/api/x'},
    {url: undefined}, {method: 'POST'}, {initiator: 'https://evil.example'}, {initiator: undefined}, {type: 'main_frame'}, {type: 'script'},
    {tabId: 99}, {frameId: 1}, {documentId: randomUUID()}, {documentLifecycle: 'prerender'}]) {
    assert.equal(f.session.observe({...f.event, ...change}), false, JSON.stringify(change));
    assert.equal(f.session.status().phase, 'waiting');
  }
  assert.equal(f.session.observe({...f.event, url: 'https://claude.ai/api/organizations/x/chat_conversations?limit=1'}), true);
  assert.equal(f.session.status().phase, 'captured');
});
test('a jar without exactly one valid sessionKey, or without the user agent, fails closed without leaking', () => {
  const base = claudeFixture().event.requestHeaders, jar = value => base.map(header => header.name === 'Cookie' ? {...header, value} : header);
  for (const headers of [base.filter(header => header.name !== 'Cookie'), jar('cf_clearance=clearance-canary; lastActiveOrg=org-canary'),
    jar(`sessionKey=${sessionKey}; sessionKey=other-canary`), jar('sessionKey='), jar(`sessionkey=${sessionKey}`),
    [...base, {name: 'cookie', value: `sessionKey=${sessionKey}`}], base.filter(header => header.name !== 'User-Agent'),
    jar(`sessionKey=${sessionKey}; filler=${'x'.repeat(32768)}`), jar(`sessionKey=${'a'.repeat(8192)}`)]) {
    const f = claudeFixture(); assert.equal(f.session.observe({...f.event, requestHeaders: headers}), true);
    assert.equal(f.session.status().error, 'INVALID_CAPTURE');
    assert.equal(leaks(f.states), false);
    assert.throws(() => f.session.take(f.owner.runId), /CAPTURE_UNAVAILABLE/);
  }
  // A real jar carries unrelated cookies well past the request limit; only the kept cookie counts.
  const f = claudeFixture(); f.session.observe({...f.event, requestHeaders: jar(`sessionKey=${sessionKey}; filler=${'x'.repeat(20000)}`)});
  assert.equal(f.session.status().phase, 'captured');
});
test('cookie schemas need a trigger; the browser adapter listens under the trigger prefix with extraHeaders', async () => {
  const {trigger: _trigger, ...capture} = claude.capture;
  assert.throws(() => new CaptureSession({schema: {...claude, capture}, owner: claudeFixture().owner, deadline: Date.now() + 1000}), /UNSUPPORTED_CAPTURE/);
  const f = browserFixture(claudeFixture(), claude); const session = await f.start();
  assert.deepEqual(f.browser.webRequest.onBeforeSendHeaders.options, [[{urls: ['https://claude.ai/api/*'], tabId: f.owner.tabId, types: ['xmlhttprequest']}, ['requestHeaders', 'extraHeaders']]]);
  f.browser.webRequest.onBeforeSendHeaders.emit({...f.event, url: 'https://claude.ai/new'});
  assert.equal(session.status().phase, 'waiting');
  f.browser.webRequest.onBeforeSendHeaders.emit(f.event);
  assert.equal(session.status().phase, 'captured'); assert.equal(f.browser.webRequest.onBeforeSendHeaders.listeners.size, 0);
  assert.equal((await session.take(f.owner.runId)).headers.cookie, `sessionKey=${sessionKey}`);
});
