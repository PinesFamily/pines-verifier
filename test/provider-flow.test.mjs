import test from 'node:test';
import assert from 'node:assert/strict';
import {ProviderFlow, providerRoute, providerUrl, CHATGPT_USAGE_URL} from '../src/provider-flow.js';
import {progressOf, receiptProgressOf, failureHelp, steps, stepsFor, reviewRowsOf} from '../src/progress.js';
import {loadRegistry, planDisclosure} from '../verification-schemas/src/index.ts';

const registry = (await loadRegistry()).list();
const chatgpt = registry.find(entry => entry.reference.schemaId === 'pines.chatgpt.plan' && entry.reference.version === 3).schema;
const claude = registry.find(entry => entry.reference.schemaId === 'pines.claude.plan' && entry.reference.version === 1).schema;
const grok = registry.find(entry => entry.reference.schemaId === 'pines.grok.plan' && entry.reference.version === 1).schema;

function fixture() {
  const job = {phase: 'awaiting-capture', owner: {tabId: 1, windowId: 4, origin: 'http://localhost:5202', documentId: 'pines-doc'}};
  let current = job;
  const tabs = new Map([[1, {id: 1, windowId: 4, url: 'http://localhost:5202/tokens/test'}], [2, {id: 2, windowId: 4, url: 'https://chatgpt.com/settings/usage'}]]);
  const frames = new Map([[1, {documentId: 'pines-doc', documentLifecycle: 'active'}]]);
  const closed = [], captures = [], actions = [];
  const browser = {
    tabs: {create: async options => {const tab = {id: Math.max(...tabs.keys()) + 1, ...options}; tabs.set(tab.id, tab); return tab;},
      get: async id => {if (!tabs.has(id)) throw Error('No tab'); return tabs.get(id);},
      update: async (id, options) => {actions.push(['tab', id]); Object.assign(tabs.get(id), options);},
      remove: async id => {closed.push(id); tabs.delete(id);}},
    windows: {update: async id => {actions.push(['window', id]);}},
    sidePanel: {close: async ({windowId}) => {actions.push(['panel-closed', windowId]);}},
  };
  const capture = {start: async (job, _schema, options) => {
    captures.push(options); tabs.get(options.tabId).url = options.navigateTo;
    frames.set(options.tabId, {documentId: 'provider-doc', documentLifecycle: 'active'});
    job.providerOwner = {tabId: options.tabId, documentId: 'provider-doc'};
  }};
  const flow = new ProviderFlow({browser, current: () => current, ownerReady: async owner => frames.get(owner.tabId)?.documentId === owner.documentId && tabs.get(owner.tabId)?.url?.startsWith(owner.origin), capture, persist: async () => {}, returned: async job => {job.panelDismissed = true;}});
  const verified = () => {job.phase = 'completed'; job.receiptVerified = true;};
  return {flow, job, browser, tabs, frames, captures, capture, closed, actions, verified, replace: () => {current = {...job};}};
}
test('automatic capture opens one owned tab and leaves existing ChatGPT tabs alone', async () => {
  const f = fixture(); await Promise.all([f.flow.start(f.job, chatgpt), f.flow.start(f.job, chatgpt)]);
  assert.equal(f.captures.length, 1); assert.equal(f.captures[0].tabId, 3);
  assert.equal(f.tabs.get(2).url, 'https://chatgpt.com/settings/usage');
  assert.equal(f.job.providerOpening, false);
  f.job.phase = 'requesting'; await f.flow.start(f.job, chatgpt);
  assert.equal(f.captures.length, 1);
});
test('Continue requires both proof completion and the API receipt, then focuses Pines and retains provider tabs', async () => {
  const f = fixture(); await f.flow.start(f.job, chatgpt);
  f.job.phase = 'completed'; await assert.rejects(f.flow.continue(f.job), /RECEIPT_PENDING/);
  f.verified(); await f.flow.continue(f.job);
  assert.deepEqual(f.closed, []); assert(f.tabs.has(2));
  assert.deepEqual(f.actions, [['tab', 1], ['window', 4], ['panel-closed', 4]]);
});
test('Continue never closes a reused, moved or navigated tab, and opens Pines afresh for a different owner document', async () => {
  for (const change of [f => {f.tabs.get(3).url = 'https://example.com';}, f => {f.tabs.get(3).windowId = 8;}, f => {f.frames.get(3).documentId = 'new-doc';}, f => {f.tabs.delete(3);}, f => {f.job.ownedProviderTabId = 1;}]) {
    const f = fixture(); await f.flow.start(f.job, chatgpt); f.verified(); change(f); await f.flow.continue(f.job);
    assert.deepEqual(f.closed, []); assert.deepEqual(f.actions.at(-1), ['panel-closed', 4]);
  }
  const f = fixture(); await f.flow.start(f.job, chatgpt); f.verified(); f.frames.get(1).documentId = 'another-pines-document';
  await f.flow.continue(f.job); assert.equal(f.tabs.get(4).url, f.job.owner.origin);
});
test('ChatGPT history parameters keep the owned Usage route without retaining their values', async () => {
  const f = fixture(); await f.flow.start(f.job, chatgpt); f.verified();
  f.tabs.get(3).url = CHATGPT_USAGE_URL + '?ui=loaded#usage';
  assert.equal(providerRoute(f.tabs.get(3).url), CHATGPT_USAGE_URL);
  assert.notEqual(providerRoute('https://chatgpt.com/settings/security'), CHATGPT_USAGE_URL);
  assert.notEqual(providerRoute('https://example.com/settings/usage'), CHATGPT_USAGE_URL);
  assert.equal(providerRoute(undefined), null);
  await f.flow.continue(f.job); assert.deepEqual(f.closed, []);
});
test('cancelling while tab creation is pending never starts capture', async () => {
  const f = fixture(); const create = f.browser.tabs.create;
  f.browser.tabs.create = async options => {const tab = await create(options); f.job.phase = 'cancelled'; return tab;};
  await assert.rejects(f.flow.start(f.job, chatgpt), /CANCELLED/);
  assert.deepEqual(f.closed, [3]); assert.equal(f.captures.length, 0);
});
test('failed navigation removes only its own untouched blank tab', async () => {
  for (const changed of [false, true]) {
    const f = fixture();
    f.capture.start = async () => {
      if (changed) f.tabs.get(3).pendingUrl = 'https://example.test/';
      else Object.assign(f.tabs.get(3), {url: 'about:blank', pendingUrl: 'about:blank'});
      throw Error('PROVIDER_OPEN_FAILED');
    };
    await assert.rejects(f.flow.start(f.job, chatgpt), /PROVIDER_OPEN_FAILED/);
    assert.deepEqual(f.closed, changed ? [] : [3]); assert(f.tabs.has(2));
    assert.equal(f.job.providerOpening, false);
  }
});
test('tab creation failure produces a bounded, actionable error', async () => {
  const f = fixture(); f.browser.tabs.create = async () => {throw Error('Browser error containing private metadata');};
  await assert.rejects(f.flow.start(f.job, chatgpt), {message: 'PROVIDER_OPEN_FAILED'});
  assert.equal(f.captures.length, 0); assert.equal(f.job.providerOpening, false);
  assert.match(progressOf({phase: 'failed', error: 'PROVIDER_OPEN_FAILED'}).description, /could not open ChatGPT/);
});
test('interrupted progress always has recovery instructions and never displays raw errors', () => {
  for (const error of ['EXTENSION_UNAVAILABLE', 'CAPTURE_UNAVAILABLE', undefined, 'private-secret-canary', 'toString']) {
    const progress = progressOf({phase: 'failed', error});
    assert.equal(progress.complete, false); assert.equal(progress.stopped, true);
    assert.match(progress.description, /[Rr]etry|[Tt]ry/);
    assert(!progress.description.includes('private-secret-canary'));
    assert.equal(typeof failureHelp(error), 'string');
  }
});
test('progress does not announce success for a pending callback, cancelled run or early acknowledgment', () => {
  assert.equal(progressOf({phase: 'completed'}).complete, false);
  assert.equal(progressOf({phase: 'completed'}).step, 2);
  assert.equal(progressOf({phase: 'proving', receiptVerified: true}).complete, false);
  assert.equal(progressOf({phase: 'failed', receiptVerified: true}).complete, false);
  assert.equal(progressOf({phase: 'cancelled'}).stopped, true);
  assert.equal(progressOf({phase: 'completed', receiptVerified: true}).complete, true);
});

test('save progress measures the confirmation wait and finishes only after both proof and receipt', () => {
  const state = {phase: 'completed', phaseStartedAt: 1000};
  assert.deepEqual(receiptProgressOf(state, 6000), {visible: true, complete: false, seconds: 5, recovery: false,
    label: 'Waiting for Pines confirmation', detail: '5s waiting · Checking your saved verification…'});
  assert.match(receiptProgressOf(state, 61000).detail, /Return to Pines/);
  const saved = receiptProgressOf({...state, receiptVerified: true, receiptVerifiedAt: 7500}, 100000);
  assert.equal(saved.complete, true); assert.equal(saved.seconds, 6);
  assert.equal(receiptProgressOf({...state, phase: 'proving', receiptVerified: true}).visible, false);
  assert.equal(receiptProgressOf({...state, phase: 'failed'}).visible, false);
  assert.equal(receiptProgressOf({phase: 'completed'}, 6000).seconds, 0);
});

test('a stopped or overdue confirmation offers recovery without announcing verification success', () => {
  for (const state of [{phase: 'completed', phaseStartedAt: 1000}, {phase: 'completed', receiptWaitStopped: true}]) {
    const progress = progressOf(state, 145000);
    assert.equal(progress.complete, false); assert.equal(progress.recovery, true);
    assert.match(progress.description, /hasn’t confirmed/);
  }
  const saved = {phase: 'completed', phaseStartedAt: 1000, receiptVerified: true, receiptVerifiedAt: 145000, receiptWaitStopped: true};
  assert.equal(progressOf(saved, 146000).complete, true);
  assert.equal(receiptProgressOf(saved, 146000).recovery, false);
});

test('recovery returns to the owning Pines document without setting a verified flag', async () => {
  const f = fixture(); await f.flow.start(f.job, chatgpt);
  await assert.rejects(f.flow.recover(f.job), /RECEIPT_PENDING/);
  f.job.phase = 'completed'; f.job.phaseStartedAt = Date.now();
  await assert.rejects(f.flow.recover(f.job), /RECEIPT_PENDING/);
  f.job.receiptWaitStopped = true;
  await assert.rejects(f.flow.continue(f.job), /RECEIPT_PENDING/);
  await f.flow.recover(f.job);
  assert.equal(f.job.receiptVerified, undefined);
  assert.deepEqual(f.closed, []); assert(f.tabs.has(2));
  assert.deepEqual(f.actions, [['tab', 1], ['window', 4], ['panel-closed', 4]]);
});

test('a cancelled or failed run returns to Pines at once, still without a verified flag', async () => {
  for (const phase of ['cancelled', 'failed']) {
    const f = fixture(); await f.flow.start(f.job, chatgpt);
    Object.assign(f.job, {phase, error: phase === 'failed' ? 'CAPTURE_TIMEOUT' : null});
    await f.flow.recover(f.job);
    assert.equal(f.job.receiptVerified, undefined);
    assert.deepEqual(f.actions, [['tab', 1], ['window', 4], ['panel-closed', 4]]);
  }
});

test('recovery returns to a reloaded Pines page and preserves a navigated provider tab', async () => {
  const f = fixture(); await f.flow.start(f.job, chatgpt);
  f.job.phase = 'completed'; f.job.phaseStartedAt = Date.now() - 31000;
  f.frames.get(1).documentId = 'changed';
  f.tabs.get(3).url = 'https://example.com';
  await f.flow.recover(f.job); assert.deepEqual(f.closed, []);
});

test('a rejected binding names the wallet and offers immediate return without claiming success', async () => {
  const f = fixture(); await f.flow.start(f.job, chatgpt);
  const linkedWallet = '0x' + 'a'.repeat(40);
  Object.assign(f.job, {phase: 'failed', error: 'PROVIDER_ACCOUNT_BOUND', receiptRejected: true, linkedWallet});
  const progress = progressOf(f.job);
  assert.equal(progress.complete, false); assert.equal(progress.recovery, true);
  assert.equal(progress.title, 'Account already linked');
  assert.equal(progress.description, `This ChatGPT account is linked to ${linkedWallet.slice(0, 6)}…${linkedWallet.slice(-4)}. Connect that wallet to continue.`);
  // The panel reads the full address aloud in its status line.
  assert.equal(failureHelp(f.job.error, f.job.linkedWallet), `This account is already linked to wallet ${linkedWallet}. Connect that wallet to continue.`);
  await assert.rejects(f.flow.continue(f.job), /RECEIPT_PENDING/);
  await f.flow.recover(f.job);
  assert.deepEqual(f.closed, []); assert(f.tabs.has(2));
  assert.deepEqual(f.actions.at(-1), ['panel-closed', 4]);
  assert.equal(f.job.receiptVerified, undefined);
  assert(!failureHelp('CHECK_FAILED', linkedWallet).includes(linkedWallet));
  assert(!failureHelp('PROVIDER_ACCOUNT_BOUND', '<private-data>').includes('<private-data>'));
});

test('each provider schema opens its own route; unknown schemas open nothing', async () => {
  assert.equal(providerUrl(chatgpt), CHATGPT_USAGE_URL, 'ChatGPT keeps its pinned Usage route, not the schema hint');
  assert.equal(providerUrl(claude), 'https://claude.ai/new');
  assert.equal(providerUrl(grok), 'https://grok.com/');
  for (const schema of [{}, undefined, {schemaId: 'pines.fixture.httpbingo'}, {schemaId: 'toString'},
    {...claude, capture: {...claude.capture, navigationUrl: 'https://claude.ai/new?x=1'}}]) assert.throws(() => providerUrl(schema), /SCHEMA_UNAVAILABLE/);
  const f = fixture(); await assert.rejects(f.flow.start(f.job, {schemaId: 'pines.fixture.httpbingo'}), /SCHEMA_UNAVAILABLE/);
  assert.equal(f.captures.length, 0); assert.equal(f.tabs.has(3), false); assert.equal(f.job.providerOpening, undefined);
});
test('Claude runs navigate to the schema route and Continue retains the provider tab', async () => {
  const f = fixture(); f.tabs.set(2, {id: 2, windowId: 4, url: 'https://claude.ai/chat/existing'});
  await f.flow.start(f.job, claude);
  assert.deepEqual(f.captures.map(options => options.navigateTo), ['https://claude.ai/new']); assert.equal(f.captures[0].tabId, 3);
  f.verified(); f.tabs.get(3).url = 'https://claude.ai/new?model=x'; await f.flow.continue(f.job);
  assert.deepEqual(f.closed, []); assert(f.tabs.has(2));
  // A ChatGPT Usage URL in the Claude run's tab is not this run's route.
  for (const url of [CHATGPT_USAGE_URL, 'https://claude.ai/chat/123']) {
    const g = fixture(); await g.flow.start(g.job, claude); g.verified(); g.tabs.get(3).url = url;
    await g.flow.continue(g.job); assert.deepEqual(g.closed, []);
  }
});
test('provider copy follows the run schema and keeps ChatGPT wording unchanged', () => {
  assert.equal(steps[0], 'Open ChatGPT'); assert.deepEqual(stepsFor('pines.chatgpt.plan'), steps);
  assert.equal(stepsFor('pines.grok.plan')[0], 'Open Grok');
  assert.match(failureHelp('CAPTURE_UNAVAILABLE', undefined, 'pines.grok.plan'), /the Grok tab.*access to grok\.com/);
  assert.equal(stepsFor('pines.claude.plan')[0], 'Open Claude'); assert.deepEqual(stepsFor('pines.claude.plan').slice(1), steps.slice(1));
  const schema = {schemaId: 'pines.claude.plan', version: 1, digest: 'sha256:' + '0'.repeat(64)};
  assert.equal(progressOf({phase: 'awaiting-capture', schema}).title, 'Claude verification');
  assert.match(progressOf({phase: 'awaiting-capture', schema, providerStarted: true}).detail, /Sign in if Claude asks\. Keep its tab open/);
  assert.match(progressOf({phase: 'initializing', schema}).detail, /Opening Claude in a new tab/);
  assert.match(progressOf({phase: 'failed', error: 'PROVIDER_OPEN_FAILED', schema}).description, /could not open Claude/);
  assert.match(failureHelp('CAPTURE_UNAVAILABLE', undefined, 'pines.claude.plan'), /the Claude tab.*access to claude\.ai/);
  assert.equal(failureHelp('CAPTURE_BUSY', undefined, 'pines.chatgpt.plan'), 'Capture is already waiting for a usage request. Keep the ChatGPT tab open.');
  assert.equal(failureHelp('PROVIDER_HTTP_429'), 'ChatGPT is limiting requests. Try again later.');
  assert.equal(failureHelp('PROVIDER_HTTP_429', undefined, 'toString'), 'ChatGPT is limiting requests. Try again later.');
  for (const code of ['PROVIDER_SIGN_IN_REQUIRED', 'PROVIDER_HTTP_401', 'PROVIDER_HTTP_403', 'CAPTURE_TIMEOUT', 'PERMISSION_REVOKED'])
    assert(!/ChatGPT|chatgpt/.test(failureHelp(code, undefined, 'pines.claude.plan')), code);
});

// grok.com's response shape with synthetic identifiers: an inactive SuperGrok Lite listed before an active Grok Pro.
// The review must show what the verifier judges, not the list's first entry.
test('review rows show the subscription the verifier selects, not the first one listed', () => {
  const user = '0f0e0d0c-0b0a-4908-8706-050403020100';
  const sub = (tier, status) => ({stripe: {subscriptionId: 'sub_synthetic'}, xaiUserId: user, tier, status, billingSystem: 'BILLING_SYSTEM_LEGACY'});
  const body = JSON.stringify({subscriptions: [sub('SUBSCRIPTION_TIER_SUPER_GROK_LITE', 'SUBSCRIPTION_STATUS_INACTIVE'), sub('SUBSCRIPTION_TIER_GROK_PRO', 'SUBSCRIPTION_STATUS_ACTIVE')], dominantPlan: {plan: 'supergrok'}});
  const encode = text => new TextEncoder().encode(text);
  const sent = encode('GET /rest/subscriptions HTTP/1.1\r\naccept: application/json\r\nuser-agent: synthetic\r\ncookie: sso=synthetic\r\nhost: grok.com\r\naccept-encoding: identity\r\nconnection: close\r\n\r\n');
  const recv = encode(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${encode(body).length}\r\n\r\n${body}`);
  const fields = {...planDisclosure(grok, sent, recv, '0x' + 'a'.repeat(40)).preview.values};
  assert.deepEqual(reviewRowsOf('pines.grok.plan', fields), [{label: 'Plan', value: 'SuperGrok'}, {label: 'Status', value: 'Active'}, {label: 'xAI user ID', value: user}]);
  assert.deepEqual(reviewRowsOf('pines.grok.plan', {tier: 'SUBSCRIPTION_TIER_SUPER_GROK_LITE', status: 'SUBSCRIPTION_STATUS_ACTIVE'}), [{label: 'Plan', value: 'SuperGrok Lite'}, {label: 'Status', value: 'Active'}]);
  assert.deepEqual(reviewRowsOf('pines.grok.plan', {tier: 'SUBSCRIPTION_TIER_X_PREMIUM_PLUS'}), [{label: 'Plan', value: 'X Premium+'}]);
  assert.deepEqual(reviewRowsOf('pines.claude.plan', {organization_uuid: user, rate_limit_tier: 'default_claude_max_20x', capabilities: ['chat', 'claude_max']}),
    [{label: 'Plan', value: 'Max 20x'}, {label: 'Claude organization ID', value: user}]);
  assert.deepEqual(reviewRowsOf('pines.chatgpt.plan', {plan_type: 'prolite', user_id: 'user-' + 'a'.repeat(24)}), [{label: 'Plan', value: 'Pro Lite'}, {label: 'Account identifier', value: 'user-' + 'a'.repeat(24)}]);
  assert.deepEqual(reviewRowsOf('pines.grok.plan', undefined), []);
});


test('return dismisses every terminal screen, even when Chrome refuses to close the panel', async () => {
  for (const phase of ['failed', 'cancelled', 'completed']) {
    const f = fixture(); Object.assign(f.job, {phase, receiptWaitStopped: true});
    f.browser.sidePanel.close = async () => {assert.equal(f.job.panelDismissed, true); throw Error('panel already closed');};
    await f.flow.recover(f.job);
    assert.equal(f.job.panelDismissed, true); assert.equal(f.job.phase, phase);
    assert.equal(f.job.receiptVerified, undefined);
  }
});
test('return after owner closure or cross-origin navigation opens Pines without reusing an unrelated tab', async () => {
  for (const gone of [false, true]) {
    const f = fixture(); await f.flow.start(f.job, grok); f.job.phase = 'cancelled';
    if (gone) f.tabs.delete(1); else f.tabs.get(1).url = 'https://elsewhere.test/';
    await f.flow.recover(f.job);
    assert.equal(f.tabs.get(4).url, f.job.owner.origin); assert.equal(f.job.panelDismissed, true);
    assert.deepEqual(f.closed, []); assert(f.tabs.has(2));
    if (!gone) assert.equal(f.tabs.get(1).url, 'https://elsewhere.test/');
  }
});
test('an old return cannot dismiss a replacement run or close its panel', async () => {
  const f = fixture(); f.job.phase = 'failed';
  f.browser.windows.update = async () => {f.replace();};
  await assert.rejects(f.flow.recover(f.job), /STALE_RUN/);
  assert.equal(f.job.panelDismissed, undefined);
  assert(!f.actions.some(([action]) => action === 'panel-closed'));
});

test('navigation failures explain recovery instead of hiding behind the generic fallback', () => {
  for (const provider of ['chatgpt', 'claude', 'grok']) {
    const message = failureHelp('CAPTURE_NAVIGATED', undefined, `pines.${provider}.plan`);
    assert.match(message, /page reloaded or changed/); assert.match(message, /return to Pines/);
    assert(!message.includes('Something went wrong'));
  }
});
