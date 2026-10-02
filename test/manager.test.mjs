import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {ProveManager} from '../src/prove-manager.js';

function harness(t) {
  const workers = [], states = [];
  const old = globalThis.Worker;
  globalThis.Worker = class {
    constructor() { workers.push(this); }
    postMessage(value) { this.lastMessage = value; }
    terminate() { this.terminated = true; }
    phase(phase, extra = {}) { this.onmessage({data: {runId: this.lastMessage.runId, phase, ...extra}}); }
  };
  t.after(() => {globalThis.Worker = old;});
  const job = {runId: randomUUID(), attempt: {resultExpiresAt: Date.now() + 60_000}, recipient: '0x'+'a'.repeat(40), deadline: Date.now()+30_000};
  const manager = new ProveManager(state => states.push(state)); manager.start(job);
  t.after(() => manager.cancel(manager.status().runId));
  const review = () => workers[0].phase('awaiting-disclosure', {preview: {request: 'authorization: [hidden]', response: 'public fixture'}});
  return {manager, workers, states, job, review};
}
test('native completion releases WASM and review data without an additional proof phase', t => {
  const f = harness(t); f.review();
  assert.equal(f.manager.status().preview, undefined);
  assert.match(f.manager.status(true).preview.request, /\[hidden\]/);
  f.manager.approve(f.job.runId);
  assert.equal(f.manager.status(true).preview, undefined);
  assert.equal(f.workers[0].lastMessage.type, 'approve');
  f.workers[0].phase('completed');
  assert.equal(f.manager.status().phase, 'completed');
  assert.equal(f.workers[0].terminated, true);
  f.workers[0].onerror(); assert.equal(f.manager.status().phase, 'completed');
});
test('cancellation and late worker messages cannot affect a subsequent run', t => {
  const f = harness(t); f.review(); f.manager.cancel(f.job.runId);
  assert.equal(f.manager.status(true).preview, undefined);
  assert.equal(f.workers[0].terminated, true);
  const fresh = {...f.job, runId: randomUUID()}; f.manager.start(fresh);
  f.workers[0].phase('completed'); f.workers[0].onerror();
  assert.equal(f.manager.status().runId, fresh.runId); assert.equal(f.manager.status().phase, 'initializing');
  assert.throws(() => f.manager.approve(f.job.runId), /STALE_RUN/);
});
test('throttled timers cannot extend an expired native proof or disclosure approval', t => {
  const f = harness(t); f.review();
  const now = Date.now(); t.mock.method(Date, 'now', () => now + 60_000);
  assert.throws(() => f.manager.approve(f.job.runId), /STALE_RUN/);
  f.workers[0].phase('completed');
  assert.equal(f.manager.status().error, 'PROOF_TIMEOUT');
  assert.equal(f.manager.status(true).preview, undefined); assert.equal(f.workers[0].terminated, true);
});
test('private replay is handed off once to its waiting worker and never exposed in state', t => {
  const f = harness(t), replay = {headers: {authorization: 'Bearer synthetic-private-canary'}};
  assert.throws(() => f.manager.replay(f.job.runId, replay), /STALE_RUN/);
  f.workers[0].phase('awaiting-capture');
  assert.throws(() => f.manager.replay(randomUUID(), replay), /STALE_RUN/);
  f.manager.replay(f.job.runId, replay);
  assert.deepEqual(f.workers[0].lastMessage, {type: 'replay', runId: f.job.runId, replay});
  assert.equal(JSON.stringify([f.manager.status(true), f.states]).includes('synthetic-private-canary'), false);
  assert.throws(() => f.manager.replay(f.job.runId, replay), /STALE_RUN/);
  f.workers[0].phase('failed', {error: 'PROVIDER_HTTP_403'});
  assert.equal(f.manager.status().error, 'PROVIDER_HTTP_403');
  assert.equal(f.workers[0].terminated, true);
});
test('cancellation and deadline expiry reject a late captured credential', t => {
  const f = harness(t);
  f.workers[0].phase('awaiting-capture'); f.manager.cancel(f.job.runId);
  assert.throws(() => f.manager.replay(f.job.runId, {}), /STALE_RUN/);
  const fresh = {...f.job, runId: randomUUID()}; f.manager.start(fresh);
  f.workers[1].phase('awaiting-capture');
  const now = Date.now(); t.mock.method(Date, 'now', () => now + 60_000);
  assert.throws(() => f.manager.replay(fresh.runId, {}), /STALE_RUN/);
  assert.equal(f.manager.status().error, 'PROOF_TIMEOUT');
  assert.equal(f.workers[1].lastMessage.type, 'start');
  assert.equal(f.workers[1].terminated, true);
});

test('review fields pass through only as short strings or string lists', t => {
  const f = harness(t), preview = {request: 'r', response: 'b'};
  f.workers[0].phase('awaiting-disclosure', {preview: {...preview, fields: {tier: 'SUBSCRIPTION_TIER_GROK_PRO', capabilities: ['chat']}}});
  assert.deepEqual(f.manager.status(true).preview.fields, {tier: 'SUBSCRIPTION_TIER_GROK_PRO', capabilities: ['chat']});
  for (const fields of [{tier: 'x'.repeat(257)}, {tier: {nested: true}}, {'Bad-Id': 'x'}, ['x'], null]) {
    f.workers[0].phase('awaiting-disclosure', {preview: {...preview, fields}});
    assert.equal('fields' in f.manager.status(true).preview, false, JSON.stringify(fields));
    assert.equal(f.manager.status(true).preview.response, 'b', 'the review itself survives a malformed summary');
  }
});
