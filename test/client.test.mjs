import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {createTlsnClient} from '../client.mjs';

const recipient = '0x' + 'a'.repeat(40);
const schema = {schemaId: 'pines.fixture.httpbingo', version: 1, digest: 'sha256:' + 'd'.repeat(64)};
const capabilities = {ok: true, admissionErrorScreen: true, protocol: 'pines-tlsn-bridge-v1', engine: 'tlsn', mode: 'Proxy', chainId: 4664, application: 'pines-test', wasmVersion: '0.1.0-alpha.15', claimable: false, schemas: [schema]};
// A fake clock: `sleep` advances time instantly; `pace` simulates the extension worker's paced reply.
function clock(start = 1_790_000_000_000) {
  const c = {time: start, sleeps: [], now: () => c.time, sleep: async ms => { c.sleeps.push(ms); c.time += Math.max(ms, 1); }, random: () => 0};
  return c;
}
function harness(t, {caps = capabilities, result, configuration, time} = {}) {
  const messages = [], requests = [];
  const attempt = {attemptId: randomUUID(), ticket: 'public-test-ticket', schema, resultExpiresAt: (time?.now() ?? Date.now())+1800000};
  const runId = randomUUID();
  const old = globalThis.chrome;
  globalThis.chrome = {runtime: {sendMessage(_id, message, done) {
    messages.push(message);
    done(message.type === 'bridge-ping' ? caps : {ok: true, runId, attemptId: attempt.attemptId, recipient, schema, phase: 'completed'});
  }}};
  t.after(() => { globalThis.chrome = old; });
  const client = createTlsnClient({chainId: 4664, application: 'pines-test', configuration, ...(time ? {now: time.now, sleep: time.sleep, random: time.random} : {}), request: async (path, init) => {
    requests.push({path, init});
    return {ok: true, status: 200, json: async () => path === '/verification-attempts' ? attempt : result ?? {attemptId: attempt.attemptId, recipient, schema, mode: 'Proxy', claimable: false, status: 'verified', receiptId: randomUUID()}};
  }});
  return {client, messages, requests, handle: {attempt, runId, recipient}};
}
test('page refuses a foreign engine or a mismatched network/runtime capability handshake', async t => {
  for (const change of [{engine: 'other'}, {mode: 'Mpc'}, {chainId: 4663}, {protocol: 'old'}, {wasmVersion: 'alpha.12'}, {claimable: true}]) {
    const f = harness(t, {caps: {...capabilities, ...change}});
    await assert.rejects(f.client.capabilities(), /EXTENSION_VERSION_MISMATCH/);
    assert.equal(f.requests.length, 0);
  }
});
test('page starts a pinned attempt and sends only admission context to the extension', async t => {
  const f = harness(t); const handle = await f.client.start(recipient);
  assert.equal(handle.recipient, recipient); assert.equal(handle.runId, f.handle.runId);
  const issued = JSON.parse(f.requests[0].init.body);
  assert.deepEqual(issued, {recipient, schema});
  assert.deepEqual(Object.keys(f.messages[1]).sort(), ['protocol', 'type', 'recipient', 'attempt'].sort());
  await assert.rejects(f.client.start(recipient, 'pines.chatgpt.plan'), /SCHEMA_UNAVAILABLE/);
});
test('receipt polling rejects a context change even when the server response says verified', async t => {
  const f = harness(t, {result: {attemptId: randomUUID(), recipient: '0x'+'b'.repeat(40), schema, mode: 'Proxy', status: 'verified', receiptId: randomUUID(), claimable: false}});
  await assert.rejects(f.client.waitForReceipt(f.handle), /RECEIPT_CONTEXT_MISMATCH/);
});
test('cancel signals the worker and durable API attempt; abort never starts another proof', async t => {
  const f = harness(t); const controller = new AbortController(); controller.abort();
  await assert.rejects(f.client.waitForReceipt(f.handle, {signal: controller.signal}), /CANCELLED/);
  assert.equal(f.messages.length, 1); assert.equal(f.messages[0].type, 'cancel-verification');
  assert.equal(f.requests[0].path, `/verification-attempts/${f.handle.attempt.attemptId}/cancel`);
  assert.equal(f.requests[0].init.method, 'POST');
});
test('wallet disconnection still cancels the API attempt if the extension is unavailable', async t => {
  const f = harness(t);
  globalThis.chrome.runtime.sendMessage = (_id, _message, done) => done(null);
  await assert.rejects(f.client.recipientChanged(f.handle, null), /EXTENSION_UNAVAILABLE/);
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].path, `/verification-attempts/${f.handle.attempt.attemptId}/cancel`);
});
test('server-selected verifier revision and schema are checked before creating an attempt', async t => {
  const configuration = {verifierOrigin: 'https://verifier.example', verifierRevision: 'release-a', schemas: [schema]};
  const f = harness(t, {configuration, caps: {...capabilities, verifierOrigin: configuration.verifierOrigin, verifierRevision: 'release-b'}});
  await assert.rejects(f.client.start(recipient), /EXTENSION_VERSION_MISMATCH/);
  assert.equal(f.requests.length, 0);
});
test('cancellation while an attempt is being issued persists no ticket and never starts the proof', async t => {
  const f = harness(t); const controller = new AbortController(); let saved;
  await assert.rejects(f.client.start(recipient, schema.schemaId, {signal: controller.signal, onAttempt: handle => {saved = handle; controller.abort();}}), /CANCELLED/);
  assert.equal(JSON.stringify(saved).includes('ticket'), false);
  assert.deepEqual(f.messages.map(message => message.type), ['bridge-ping']);
  assert.equal(f.requests[1].path, `/verification-attempts/${f.handle.attempt.attemptId}/cancel`);
});
test('receipt polling binds the server audience and release even after page reload', async t => {
  const configuration = {verifierOrigin: 'https://verifier.example', verifierRevision: 'release-a', schemas: [schema]};
  const result = {};
  const f = harness(t, {configuration, result});
  Object.assign(result, {attemptId: f.handle.attempt.attemptId, recipient, schema, engine: 'tlsn', mode: 'Proxy', status: 'verified', receiptId: randomUUID(), claimable: false, application: 'pines-test', chainId: 4663, verifierRevision: 'release-a'});
  await assert.rejects(f.client.receiptStatus({...f.handle, runId: undefined}), /RECEIPT_CONTEXT_MISMATCH/);
});

test('claim-enabled v3 status is accepted only for the bound attempt and an activated API', async t => {
  const identity = {schemaId: 'pines.chatgpt.plan', version: 3, digest: 'sha256:7b14d797875c45886e8f5b9fc6a6103b6f4c39a1caa3b1e26b40c05437af7b64'};
  const configuration = {claimable: true, verifierOrigin: 'https://verifier.example', verifierRevision: 'release-a', schemas: [identity]};
  const result = {}, f = harness(t, {configuration, result});
  f.handle.attempt.schema = identity;
  Object.assign(result, {attemptId: f.handle.attempt.attemptId, recipient, schema: identity, engine: 'tlsn', mode: 'Proxy', status: 'verified', receiptId: randomUUID(), claimable: true, application: 'pines-test', chainId: 4664, verifierRevision: 'release-a'});
  assert.equal((await f.client.receiptStatus(f.handle)).claimable, true);
  configuration.claimable = false;
  await assert.rejects(f.client.receiptStatus(f.handle), /RECEIPT_CONTEXT_MISMATCH/);
  configuration.claimable = true; result.schema = {...identity, version: 2};
  await assert.rejects(f.client.receiptStatus(f.handle), /RECEIPT_CONTEXT_MISMATCH/);
});
test('claim-enabled Claude v1 status is accepted like ChatGPT identity, and only for an activated API', async t => {
  const claude = {schemaId: 'pines.claude.plan', version: 1, digest: 'sha256:6e7573443be1b7e5ae748076ae5542d47b5884dce6ca3d7d31a03e24c980e174'};
  const configuration = {claimable: true, verifierOrigin: 'https://verifier.example', verifierRevision: 'release-a', schemas: [claude]};
  const result = {}, f = harness(t, {configuration, result});
  f.handle.attempt.schema = claude;
  Object.assign(result, {attemptId: f.handle.attempt.attemptId, recipient, schema: claude, engine: 'tlsn', mode: 'Proxy', status: 'verified', receiptId: randomUUID(), claimable: true, application: 'pines-test', chainId: 4664, verifierRevision: 'release-a'});
  assert.equal((await f.client.receiptStatus(f.handle)).claimable, true);
  result.status = 'verifying'; await assert.rejects(f.client.receiptStatus(f.handle), /RECEIPT_CONTEXT_MISMATCH/);
  result.status = 'verified'; configuration.claimable = false;
  await assert.rejects(f.client.receiptStatus(f.handle), /RECEIPT_CONTEXT_MISMATCH/);
  configuration.claimable = true;
  for (const schema of [{...claude, version: 2}, {...claude, schemaId: 'pines.fixture.httpbingo'}]) {
    f.handle.attempt.schema = result.schema = schema;
    await assert.rejects(f.client.receiptStatus(f.handle), /RECEIPT_CONTEXT_MISMATCH/);
  }
});
test('claim-enabled Grok v1 status is accepted like Claude', async t => {
  const grok = {schemaId: 'pines.grok.plan', version: 1, digest: 'sha256:9d8cd003ba63f0658de65300fca00d32a3163f6008584245e728bab6da605cd0'};
  const configuration = {claimable: true, verifierOrigin: 'https://verifier.example', verifierRevision: 'release-a', schemas: [grok]};
  const result = {}, f = harness(t, {configuration, result});
  f.handle.attempt.schema = grok;
  Object.assign(result, {attemptId: f.handle.attempt.attemptId, recipient, schema: grok, engine: 'tlsn', mode: 'Proxy', status: 'verified', receiptId: randomUUID(), claimable: true, application: 'pines-test', chainId: 4664, verifierRevision: 'release-a'});
  assert.equal((await f.client.receiptStatus(f.handle)).claimable, true);
  f.handle.attempt.schema = result.schema = {...grok, version: 2};
  await assert.rejects(f.client.receiptStatus(f.handle), /RECEIPT_CONTEXT_MISMATCH/);
});
test('wallet change suppresses a late verified receipt even through a restored handle', async t => {
  const f = harness(t); let release, requested;
  const read = new Promise(resolve => {requested = resolve;});
  const client = createTlsnClient({chainId: 4664, application: 'pines-test', request: async path => {
    if (path.endsWith('/cancel')) return {ok: false, status: 409, json: async () => ({error: 'ATTEMPT_TERMINAL'})};
    requested();
    return new Promise(resolve => {release = () => resolve({ok: true, json: async () => ({attemptId: f.handle.attempt.attemptId,
      recipient, schema, mode: 'Proxy', status: 'verified', receiptId: randomUUID(), claimable: false})});});
  }});
  const waiting = client.waitForReceipt(f.handle);
  const rejected = assert.rejects(waiting, /CANCELLED/);
  await read; await client.recipientChanged({...f.handle}, null); release();
  await rejected;
});
test('only a validated API receipt acknowledges completion to the matching extension run', async t => {
  const f = harness(t); await f.client.waitForReceipt(f.handle);
  assert.deepEqual(f.messages.at(-1), {protocol: 'pines-tlsn-bridge-v1', type: 'receipt-verified', runId: f.handle.runId, recipient});
  const bad = harness(t, {result: {status: 'verified', receiptId: randomUUID()}});
  await assert.rejects(bad.client.waitForReceipt(bad.handle), /RECEIPT_CONTEXT_MISMATCH/);
  assert.equal(bad.messages.length, 0);
});

test('a validated binding conflict preserves the address and stops extension confirmation waiting', async t => {
  const result = {}, f = harness(t, {result}), linkedWallet = '0x' + 'b'.repeat(40);
  Object.assign(result, {attemptId: f.handle.attempt.attemptId, recipient, schema, mode: 'Proxy', claimable: false,
    status: 'failed', error: 'PROVIDER_ACCOUNT_BOUND', linkedWallet});
  await assert.rejects(f.client.waitForReceipt(f.handle), error => error.message === 'PROVIDER_ACCOUNT_BOUND' && error.linkedWallet === linkedWallet);
  assert.deepEqual(f.messages[0], {protocol: 'pines-tlsn-bridge-v1', type: 'receipt-rejected', runId: f.handle.runId, recipient, error: 'PROVIDER_ACCOUNT_BOUND', linkedWallet});
  assert(!f.messages.some(message => message.type === 'receipt-verified'));
  assert.equal(f.messages.at(-1).type, 'cancel-verification');
});

test('foreign or malformed binding details are not forwarded to the extension', async t => {
  for (const change of [{linkedWallet: 'private-provider-data'}, {linkedWallet: '0x' + '0'.repeat(40)}, {error: 'CHECK_FAILED'}, {status: 'verified'}, {recipient: '0x' + 'c'.repeat(40)}]) {
    const result = {}, f = harness(t, {result});
    Object.assign(result, {attemptId: f.handle.attempt.attemptId, recipient, schema, mode: 'Proxy', claimable: false,
      status: 'failed', error: 'PROVIDER_ACCOUNT_BOUND', linkedWallet: '0x' + 'b'.repeat(40)}, change);
    await assert.rejects(f.client.waitForReceipt(f.handle), /RECEIPT_CONTEXT_MISMATCH/);
    assert.equal(f.messages.length, 0);
  }
});

test('extension-paced waiting never uses page timers and reads the API at most every 2 s', async t => {
  const result = {}, time = clock();
  const f = harness(t, {result, time});
  Object.assign(result, {attemptId: f.handle.attempt.attemptId, recipient, schema, mode: 'Proxy', claimable: false, status: 'verifying'});
  const send = globalThis.chrome.runtime.sendMessage;
  let polls = 0;
  globalThis.chrome.runtime.sendMessage = (id, message, done) => {
    if (message.type !== 'verification-status') return send(id, message, done);
    polls++; time.time += 500; // the extension worker paces its reply
    if (polls === 2) Object.assign(result, {status: 'verified', receiptId: randomUUID()});
    done({ok: true, runId: f.handle.runId, recipient, phase: 'proving', pollDelayMs: 500});
  };
  const receipt = await f.client.waitForReceipt(f.handle);
  assert.equal(receipt.status, 'verified');
  assert.deepEqual(time.sleeps, [], 'a hidden Pines tab must not depend on its own throttled timers');
  const reads = f.requests.filter(r => r.path === `/verification-attempts/${f.handle.attempt.attemptId}`).length;
  assert.equal(reads, 2, 'one read at start, the next only after 2 s');
  assert.equal(f.messages.at(-1).type, 'receipt-verified');
});

test('the extension reporting completion triggers a prompt API read', async t => {
  const result = {}, time = clock();
  const f = harness(t, {result, time});
  Object.assign(result, {attemptId: f.handle.attempt.attemptId, recipient, schema, mode: 'Proxy', claimable: false, status: 'verifying'});
  const send = globalThis.chrome.runtime.sendMessage;
  globalThis.chrome.runtime.sendMessage = (id, message, done) => {
    if (message.type !== 'verification-status') return send(id, message, done);
    time.time += 100;
    Object.assign(result, {status: 'verified', receiptId: randomUUID()});
    done({ok: true, runId: f.handle.runId, recipient, phase: 'completed', pollDelayMs: 500});
  };
  const started = time.now();
  assert.equal((await f.client.waitForReceipt(f.handle)).status, 'verified');
  assert(time.now() - started < 1000, 'confirmed without waiting for the next 2-second read');
});

test('older or unavailable extensions and restored handles keep bounded API-only polling', async t => {
  for (const kind of ['older', 'unavailable', 'restored']) {
    const result = {}, time = clock();
    const f = harness(t, {result, time});
    Object.assign(result, {attemptId: f.handle.attempt.attemptId, recipient, schema, mode: 'Proxy', claimable: false, status: 'verifying'});
    if (kind === 'unavailable') globalThis.chrome.runtime.sendMessage = (_id, _message, done) => done(null);
    if (kind === 'older') { const send = globalThis.chrome.runtime.sendMessage; globalThis.chrome.runtime.sendMessage = (id, message, done) => message.type === 'verification-status' ? done({ok: true, runId: f.handle.runId, recipient, phase: 'proving'}) : send(id, message, done); }
    const handle = kind === 'restored' ? {...f.handle, runId: undefined} : f.handle;
    const sleep = time.sleep;
    time.sleep = async ms => { await sleep(ms); if (time.now() > 1_790_000_000_000 + 5000) Object.assign(result, {status: 'verified', receiptId: randomUUID()}); };
    const client = createTlsnClient({chainId: 4664, application: 'pines-test', now: time.now, sleep: ms => time.sleep(ms), random: time.random,
      request: async (path, init) => { f.requests.push({path, init}); return {ok: true, json: async () => result}; }});
    assert.equal((await client.waitForReceipt(handle)).status, 'verified');
    const reads = f.requests.filter(r => !r.path.endsWith('/cancel'));
    assert(reads.length >= 2 && reads.length <= 5, `${kind}: ${reads.length} API reads in ~6 s`);
    assert(time.sleeps.every(ms => ms <= 1000));
    assert(!f.requests.some(r => r.path.endsWith('/cancel')));
  }
});

test('transient API failures and restarts are retried with bounded backoff and never cancel the attempt', async t => {
  const time = clock(), f = harness(t, {time});
  let calls = 0;
  const statuses = [new TypeError('network'), 503, 429, 502, 'verifying', 'verified'];
  const client = createTlsnClient({chainId: 4664, application: 'pines-test', now: time.now, sleep: time.sleep, random: time.random, request: async path => {
    if (path.endsWith('/cancel')) throw Error('must not cancel');
    const next = statuses[Math.min(calls++, statuses.length - 1)];
    if (next instanceof Error) throw next;
    if (typeof next === 'number') return {ok: false, status: next, json: async () => ({error: next === 429 ? 'RATE_LIMITED' : 'VERIFICATION_UNAVAILABLE'})};
    return {ok: true, json: async () => ({attemptId: f.handle.attempt.attemptId, recipient, schema, mode: 'Proxy', claimable: false, status: next, ...(next === 'verified' ? {receiptId: randomUUID()} : {})})};
  }});
  const handle = {...f.handle, runId: undefined};
  const started = time.now();
  assert.equal((await client.waitForReceipt(handle)).status, 'verified');
  assert.equal(calls, 6);
  assert(time.now() - started >= 1000 + 2000 + 4000 + 8000, 'exponential backoff between failures');
});

test('a receipt-wait timeout, an ambiguous post-reveal failure and a lost wallet session keep the attempt recoverable', async t => {
  for (const scenario of ['timeout', 'post-reveal', 'auth']) {
    const result = {}, time = clock();
    const f = harness(t, {result, time});
    Object.assign(result, {attemptId: f.handle.attempt.attemptId, recipient, schema, mode: 'Proxy', claimable: false, status: 'verifying'});
    if (scenario === 'post-reveal') scriptStatuses(f, [{phase: 'proving'}, {phase: 'failed', error: 'PROOF_FAILED'}], time);
    else scriptStatuses(f, [{phase: 'awaiting-disclosure'}], time);
    let client = f.client;
    if (scenario === 'auth') client = createTlsnClient({chainId: 4664, application: 'pines-test', now: time.now, sleep: time.sleep, random: time.random,
      request: async path => path.endsWith('/cancel') ? {ok: true, json: async () => ({})} : {ok: false, status: 403, json: async () => ({error: 'WALLET_UNAUTHORIZED'})}});
    const expected = scenario === 'auth' ? /WALLET_UNAUTHORIZED/ : /RECEIPT_PENDING/;
    await assert.rejects(client.waitForReceipt(f.handle, {timeoutMs: 30_000}), expected);
    assert(!f.requests.some(r => r.path.endsWith('/cancel')), `${scenario}: nothing was cancelled`);
    assert(!f.messages.some(m => m.type === 'cancel-verification'), `${scenario}: the extension run was not stopped`);
  }
});

test('an assigned attempt carries its verifier; status is bound to that assignment, restored references to the API', async t => {
  const configuration = {verifierOrigin: 'https://legacy.example', verifierRevision: 'legacy-rev', schemas: [schema], attemptRouting: ['pinned', 'assigned']};
  const caps = {...capabilities, verifierOrigin: 'https://legacy.example', verifierRevision: 'legacy-rev', routing: ['pinned', 'assigned']};
  const result = {};
  const f = harness(t, {configuration, caps, result});
  const verifier = {instanceId: 'v2', origin: 'https://v2.verifier.pines.family', revision: 'rev-2'};
  Object.assign(f.handle.attempt, {verifierOrigin: verifier.origin, verifier});
  const handle = await f.client.start(recipient);
  assert.deepEqual(JSON.parse(f.requests[0].init.body), {recipient, schema, routing: 'assigned'});
  assert.deepEqual(handle.attempt.verifier, verifier);
  assert.equal(f.messages.find(m => m.type === 'verify-provider').attempt.verifier.instanceId, 'v2');
  Object.assign(result, {attemptId: handle.attempt.attemptId, recipient, schema, engine: 'tlsn', mode: 'Proxy', status: 'verifying', receiptId: null, claimable: false, application: 'pines-test', chainId: 4664, verifierRevision: 'rev-2'});
  assert.equal((await f.client.receiptStatus(handle)).verifierRevision, 'rev-2');
  result.verifierRevision = 'legacy-rev';
  await assert.rejects(f.client.receiptStatus(handle), /RECEIPT_CONTEXT_MISMATCH/, 'bound to the assignment');
  const restored = {recipient, attempt: {attemptId: handle.attempt.attemptId, schema, resultExpiresAt: handle.attempt.resultExpiresAt}};
  assert.equal((await f.client.receiptStatus(restored)).verifierRevision, 'legacy-rev', 'a restored reference survives a verifier upgrade');
  // An assigned-capable API with a pinned extension that no longer matches the pin asks for an update.
  const old = harness(t, {configuration: {...configuration, verifierRevision: 'legacy-rev-2'}, caps: {...caps, routing: undefined}});
  await assert.rejects(old.client.start(recipient), /EXTENSION_UPDATE_REQUIRED/);
  assert.equal(old.requests.length, 0);
});

test('cancellation during an extension-paced poll never acknowledges a late receipt', async t => {
  const result = {};
  const f = harness(t, {result}); const abort = new AbortController();
  Object.assign(result, {attemptId: f.handle.attempt.attemptId, recipient, schema, mode: 'Proxy', claimable: false, status: 'verifying'});
  const send = globalThis.chrome.runtime.sendMessage;
  globalThis.chrome.runtime.sendMessage = (id, message, done) => {
    if (message.type !== 'verification-status') return send(id, message, done);
    abort.abort(); Object.assign(result, {status: 'verified', receiptId: randomUUID()});
    done({ok: true, phase: 'completed', pollDelayMs: 500});
  };
  await assert.rejects(f.client.waitForReceipt(f.handle, {signal: abort.signal}), /CANCELLED/);
  assert(!f.messages.some(message => message.type === 'receipt-verified'));
});

// Extension status replies for each poll; the last one repeats.
function scriptStatuses(f, statuses, time) {
  const send = globalThis.chrome.runtime.sendMessage;
  let index = 0;
  globalThis.chrome.runtime.sendMessage = (id, message, done) => {
    if (message.type !== 'verification-status') return send(id, message, done);
    if (time) time.time += 500;
    done({ok: true, runId: f.handle.runId, recipient, pollDelayMs: 500, ...statuses[Math.min(index++, statuses.length - 1)]});
  };
}
test('a verifier refusal before the review is reported at once and cancels the attempt', async t => {
  const result = {};
  const f = harness(t, {result});
  Object.assign(result, {attemptId: f.handle.attempt.attemptId, recipient, schema, mode: 'Proxy', claimable: false, status: 'pending'});
  scriptStatuses(f, [{phase: 'awaiting-capture'}, {phase: 'failed', error: 'ADMISSION_REFUSED'}]);
  const started = Date.now();
  await assert.rejects(f.client.waitForReceipt(f.handle), /ADMISSION_REFUSED/);
  assert(Date.now() - started < 5000, 'A refusal must not wait for the receipt deadline');
  assert(f.requests.some(request => request.path === `/verification-attempts/${f.handle.attempt.attemptId}/cancel`));
  assert(f.messages.some(message => message.type === 'cancel-verification'));
});
test('a failure after the reveal still accepts a result the verifier is delivering, however late', async t => {
  const result = {}, time = clock();
  const f = harness(t, {result, time});
  Object.assign(result, {attemptId: f.handle.attempt.attemptId, recipient, schema, mode: 'Proxy', claimable: false, status: 'verifying'});
  scriptStatuses(f, [{phase: 'proving'}, {phase: 'failed', error: 'PROOF_FAILED'}], time);
  const sleep = time.sleep;
  // Well beyond the former 15-second grace, the verifier's completion reaches the API.
  time.sleep = async ms => { await sleep(ms); if (time.now() > 1_790_000_000_000 + 60_000) Object.assign(result, {status: 'verified', receiptId: randomUUID()}); };
  const client = createTlsnClient({chainId: 4664, application: 'pines-test', now: time.now, sleep: ms => time.sleep(ms), random: time.random, request: async (path, init) => {
    f.requests.push({path, init});
    return {ok: true, json: async () => result};
  }});
  const receipt = await client.waitForReceipt(f.handle);
  assert.equal(receipt.status, 'verified');
  assert(!f.requests.some(request => request.path.endsWith('/cancel')), 'A result in flight must not be cancelled');
});
for (const waitingPhase of ['awaiting-disclosure', 'awaiting-permission']) test(`a panel cancellation during ${waitingPhase} cancels the API attempt`, async t => {
  const result = {};
  const f = harness(t, {result});
  Object.assign(result, {attemptId: f.handle.attempt.attemptId, recipient, schema, mode: 'Proxy', claimable: false, status: 'pending'});
  scriptStatuses(f, [{phase: waitingPhase}, {phase: 'cancelled', error: waitingPhase === 'awaiting-permission' ? 'PROVIDER_PERMISSION_DENIED' : null}]);
  await assert.rejects(f.client.waitForReceipt(f.handle), /CANCELLED/);
  assert(f.requests.some(request => request.path.endsWith('/cancel')));
});

test('refused admission sends only bounded error context, with clock-adjusted retry time', async t => {
  const f = harness(t); const now = 1_790_000_000_000;
  for (const body of [{error: 'RATE_LIMITED', retryAt: now - 9999, retryAfterSeconds: 120}, {error: 'RATE_LIMITED'},
    {error: 'RATE_LIMITED', retryAt: 'bad', retryAfterSeconds: 999999}]) {
    const client = createTlsnClient({chainId: 4664, application: 'pines-test', now: () => now,
      request: async () => ({ok: false, status: 429, json: async () => ({...body, secret: 'must not cross bridge'})})});
    await assert.rejects(client.start(recipient), /RATE_LIMITED/);
    const message = f.messages.at(-1);
    assert.equal(message.type, 'verification-refused');
    assert.equal(message.retryAt, body.retryAfterSeconds === 120 ? now + 120000 : null);
    assert.deepEqual(Object.keys(message).sort(), ['protocol', 'type', 'recipient', 'schema', 'error', 'retryAt'].sort());
    assert(!f.messages.some(m => m.type === 'verify-provider'));
  }
});


test('older extensions receive no unsupported refusal message', async t => {
  const f = harness(t, {caps: {...capabilities, admissionErrorScreen: undefined}});
  const client = createTlsnClient({chainId: 4664, application: 'pines-test',
    request: async () => ({ok: false, status: 429, json: async () => ({error: 'RATE_LIMITED'})})});
  await assert.rejects(client.start(recipient), /RATE_LIMITED/);
  assert.deepEqual(f.messages.map(m => m.type), ['bridge-ping']);
});

test('preparation waits for permission before issuing exactly one API attempt', async t => {
  const f = harness(t, {caps: {...capabilities, prepareProvider: true, ownerConnection: true}, time: clock()});
  const send = chrome.runtime.sendMessage, preparationId = randomUUID(); let polls = 0, connections = 0;
  chrome.runtime.connect = (_id, options) => {connections++; assert.equal(options.name, 'pines-tlsn-owner-v1');
    return {onMessage: {addListener() {}}, onDisconnect: {addListener() {}}};};
  chrome.runtime.sendMessage = (id, message, done) => {
    if (['prepare-provider', 'preparation-status'].includes(message.type)) {
      assert.equal(f.requests.length, 0, 'no admission while waiting for the grant');
      polls++; done({ok: true, runId: preparationId, phase: 'awaiting-permission', preparationReady: polls === 4});
    } else {if (message.type === 'verify-provider') assert.equal(message.preparationId, preparationId); send(id, message, done);}
  };
  await f.client.start(recipient); assert.equal(polls, 4); assert.equal(connections, 1); assert.equal(f.requests.length, 1);
});
test('permission denial or cancellation during preparation consumes no attempt', async t => {
  for (const denied of [false, true]) {
    const f = harness(t, {caps: {...capabilities, prepareProvider: true}, time: clock()}), controller = new AbortController();
    const send = chrome.runtime.sendMessage;
    chrome.runtime.sendMessage = (id, message, done) => {
      if (message.type === 'prepare-provider') {
        if (!denied) controller.abort();
        done({ok: true, runId: randomUUID(), phase: denied ? 'cancelled' : 'awaiting-permission', error: 'PROVIDER_PERMISSION_DENIED', preparationReady: false});
      } else send(id, message, done);
    };
    await assert.rejects(f.client.start(recipient, schema.schemaId, {signal: controller.signal}), denied ? /PROVIDER_PERMISSION_DENIED/ : /CANCELLED/);
    assert.equal(f.requests.length, 0); assert.equal(f.messages.at(-1).type, 'cancel-verification');
  }
});
