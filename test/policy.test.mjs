import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash, randomUUID} from 'node:crypto';
import {ownerOf, owns, recipientOf, validateAttempt, publicState, buildEntries, entryOf, supported, verifierOriginAllowed, assignmentOf} from '../src/policy.js';
import {createHmac} from 'node:crypto';
import {loadRegistry} from '../verification-schemas/src/index.ts';
import {canonicalJson} from '../verification-schemas/src/json.ts';

// The API's ticket format: base64url(canonical JSON) and an HMAC the extension only checks for shape.
const serviceKey = (id, hex) => ({id, bytes: Buffer.from(hex, 'hex')});
const signTicket = (ticket, key) => { const payload = Buffer.from(canonicalJson(ticket)).toString('base64url'); return `${payload}.${createHmac('sha256', key.bytes).update(`pines-tlsn-ticket-v1\n${payload}`).digest('hex')}`; };

const registry = await loadRegistry();
const entry = registry.list().find(entry => entry.schema.schemaId === 'pines.fixture.httpbingo');
const recipient = '0x' + 'a'.repeat(40);
const config = {verifierOrigin: 'http://127.0.0.1:17447', application: 'pines-test', chainId: 4664, verifierRevision: 'test-build', testBuild: true, verifierPolicy: {legacy: [], test: ['http://127.0.0.1:17447']}};
function fixture() {
  const now = Date.now(); const id = randomUUID();
  const ticket = {format: 'pines-tlsn-ticket-v1', keyId: 'test', attemptId: id, recipient, application: config.application, chainId: config.chainId, schema: entry.reference, mode: 'Proxy', serverName: 'httpbingo.org', verifierRevision: config.verifierRevision, issuedAt: now, expiresAt: now + 60000, resultExpiresAt: now + 1800000, maxSentBytes: 4096, maxRecvBytes: 16384, maxRecvRecords: 256, sessionTimeoutMs: 120000};
  const attempt = {attemptId: id, ticket: signTicket(ticket, serviceKey('test', '01'.repeat(32))), schema: entry.reference, expiresAt: ticket.expiresAt, resultExpiresAt: ticket.resultExpiresAt, claimable: false, verifierOrigin: config.verifierOrigin};
  return {ticket, attempt};
}
test('bridge authorizes the exact origin, top frame and browser-owned document/tab/window', () => {
  const origins = ['https://app.pines.family', 'http://localhost:5180'];
  const sender = {origin: origins[1], url: origins[1] + '/verify', frameId: 0, documentId: randomUUID(), tab: {id: 4, windowId: 5, url: origins[1] + '/verify', incognito: false}};
  const owner = ownerOf(sender, origins);
  for (const changed of [{id: 'foreign-extension'}, {origin: 'http://localhost:5199'}, {origin: 'https://evil.example'}, {frameId: 1}, {documentId: ''}, {url: 'https://evil.example'}, {tab: {...sender.tab, incognito: true}}, {tab: {...sender.tab, url: 'https://evil.example'}}]) assert.throws(() => ownerOf({...sender, ...changed}, origins), /UNAUTHORIZED/);
  for (const changed of [{tabId: 8}, {windowId: 8}, {documentId: randomUUID()}, {origin: origins[0]}]) assert.equal(owns(owner, {...owner, ...changed}), false);
  assert.equal(owns(owner, {...owner}), true);
});
test('recipient cannot fall back to bearer/zero-address verification', () => {
  assert.equal(recipientOf(recipient.toUpperCase().replace('0X', '0x')), recipient);
  for (const value of [null, '', '0x'+'0'.repeat(40), '0x1', 'malformed']) assert.throws(() => recipientOf(value), /INVALID_RECIPIENT/);
});
test('client checks bind the attempt to packaged schema, configured verifier and wallet', () => {
  const {attempt, ticket} = fixture();
  assert.deepEqual(validateAttempt(attempt, recipient, entry.reference, entry.schema, config), ticket);
  for (const changed of [{recipient: '0x'+'b'.repeat(40)}, {mode: 'Mpc'}, {application: 'foreign'}, {chainId: 1}, {serverName: 'example.com'}, {verifierRevision: 'old'}, {maxRecvBytes: 65536}, {schema: {...entry.reference, digest: 'sha256:'+'0'.repeat(64)}}]) {
    const value = {...attempt, ticket: signTicket({...ticket, ...changed}, serviceKey('test', '01'.repeat(32)))};
    assert.throws(() => validateAttempt(value, recipient, entry.reference, entry.schema, config));
  }
  for (const changed of [{verifierOrigin: 'http://127.0.0.1:1'}, {schema: {...entry.reference, version: 2}}, {claimable: true}, {extra: 'client-policy'}]) assert.throws(() => validateAttempt({...attempt, ...changed}, recipient, entry.reference, entry.schema, config));
  assert.throws(() => validateAttempt(attempt, recipient, entry.reference, entry.schema, config, ticket.expiresAt), /TICKET_EXPIRED/);
});
test('the packaged verifier policy admits only canonical HTTPS instances beneath verifier.pines.family', () => {
  const production = {verifierPolicy: {legacy: ['https://verifier.legacy.example'], test: ['http://127.0.0.1:17447']}, testBuild: false};
  for (const origin of ['https://v1.verifier.pines.family', 'https://a-2.verifier.pines.family', 'https://verifier.legacy.example'])
    assert.equal(verifierOriginAllowed(origin, production), true, origin);
  for (const origin of ['https://verifier.pines.family', 'https://a.b.verifier.pines.family', 'https://v1.verifier.pines.family.evil.example',
    'https://evilverifier.pines.family', 'https://v1-verifier.pines.family', 'http://v1.verifier.pines.family', 'https://v1.verifier.pines.family:8443',
    'https://user@v1.verifier.pines.family', 'https://v1.verifier.pines.family/', 'https://v1.verifier.pines.family/path', 'https://v1.verifier.pines.family?x=1',
    'https://v1.verifier.pines.family#x', 'https://V1.verifier.pines.family', 'https://-v1.verifier.pines.family', 'http://127.0.0.1:17447',
    'http://localhost:7047', 'https://10.0.0.5', 'wss://v1.verifier.pines.family', 'https://v1.verifier.pines.family.', null, 42, 'x'.repeat(300)])
    assert.equal(verifierOriginAllowed(origin, production), false, String(origin));
  assert.equal(verifierOriginAllowed('http://127.0.0.1:17447', {...production, testBuild: true}), true, 'loopback only in an explicit test build');
});
test('an assigned attempt carries its instance; its ticket must name the same revision and origin', () => {
  const {attempt, ticket} = fixture();
  const assigned = {...attempt, verifierOrigin: 'https://v2.verifier.pines.family', verifier: {instanceId: 'v2', origin: 'https://v2.verifier.pines.family', revision: 'rev-2'}};
  const signed = {...ticket, verifierRevision: 'rev-2'};
  assigned.ticket = signTicket(signed, serviceKey('test', '01'.repeat(32)));
  const validated = validateAttempt(assigned, recipient, entry.reference, entry.schema, config);
  assert.deepEqual(assignmentOf(assigned, validated), {origin: 'https://v2.verifier.pines.family', revision: 'rev-2', instanceId: 'v2'});
  for (const verifier of [{instanceId: 'v2', origin: 'https://v3.verifier.pines.family', revision: 'rev-2'}, {instanceId: 'v2', origin: 'https://v2.verifier.pines.family', revision: 'rev-3'},
    {instanceId: 'V2!', origin: 'https://v2.verifier.pines.family', revision: 'rev-2'}, {instanceId: 'v2', origin: 'https://v2.verifier.pines.family', revision: 'rev-2', extra: 1}])
    assert.throws(() => validateAttempt({...assigned, verifier}, recipient, entry.reference, entry.schema, config));
  assert.throws(() => validateAttempt({...assigned, verifierOrigin: 'https://evil.example', verifier: {...assigned.verifier, origin: 'https://evil.example'}}, recipient, entry.reference, entry.schema, config), /VERIFIER_ORIGIN_REFUSED/);
  // A pinned (seven-key) attempt still has to match the build's pin exactly.
  assert.throws(() => validateAttempt({...attempt, ticket: signTicket(signed, serviceKey('test', '01'.repeat(32)))}, recipient, entry.reference, entry.schema, config), /ATTEMPT_MISMATCH/);
});
test('page-facing state excludes tickets, request headers, preview and transcripts', () => {
  const value = publicState({runId: 'run', attemptId: 'attempt', recipient, schema: entry.reference, phase: 'awaiting-disclosure', ticket: 'private-ticket-canary', preview: {response: 'private-body-canary'}, requestHeaders: {Authorization: 'secret'}, owner: {documentId: 'private'}});
  assert.deepEqual(Object.keys(value).sort(), ['attemptId', 'claimable', 'error', 'phase', 'recipient', 'runId', 'schema'].sort());
  assert.equal(JSON.stringify(value).includes('private'), false);
});
test('the extension ID is derived from the packaged public key', () => {
  const identity = JSON.parse(readFileSync(new URL('../config/identity.json', import.meta.url)));
  const id = [...createHash('sha256').update(Buffer.from(identity.key, 'base64')).digest('hex').slice(0,32)].map(c => String.fromCharCode(97+parseInt(c,16))).join('');
  assert.equal(identity.id, id);
});

test('one build carries a list of digest-pinned schemas and admits nothing outside it', () => {
  const find = (schemaId, version) => registry.list().find(entry => entry.reference.schemaId === schemaId && entry.reference.version === version);
  const chatgpt = find('pines.chatgpt.plan', 3), claude = find('pines.claude.plan', 1), fixture = find('pines.fixture.httpbingo', 1);
  const both = {captureProvider: true, schemas: [{schemaId: 'pines.chatgpt.plan', version: 3}, {schemaId: 'pines.claude.plan', version: 1}]};
  const entries = buildEntries(registry, both);
  assert.deepEqual(entries.map(entry => entry.reference), [chatgpt.reference, claude.reference]);
  assert.equal(entryOf(entries, claude.reference), entries[1]); assert.equal(entryOf(entries, chatgpt.reference), entries[0]);
  for (const reference of [fixture.reference, find('pines.chatgpt.plan', 2).reference, {...claude.reference, digest: 'sha256:' + '0'.repeat(64)}, undefined, {}])
    assert.throws(() => entryOf(entries, reference), /SCHEMA_UNAVAILABLE/);
  assert.equal(supported(claude.schema, both), true); assert.equal(supported(chatgpt.schema, both), true);
  assert.equal(supported(find('pines.chatgpt.plan', 2).schema, both), false); assert.equal(supported(fixture.schema, both), false);
  // The ChatGPT-only identity build and the fixture default keep their single schema.
  const identity = {captureProvider: true, schemas: [{schemaId: 'pines.chatgpt.plan', version: 3}]};
  assert.deepEqual(buildEntries(registry, identity).map(entry => entry.reference), [chatgpt.reference]);
  assert.equal(supported(claude.schema, identity), false);
  const grok = find('pines.grok.plan', 1);
  const three = {captureProvider: true, schemas: [...both.schemas, {schemaId: 'pines.grok.plan', version: 1}]};
  assert.deepEqual(buildEntries(registry, three).map(entry => entry.reference), [chatgpt.reference, claude.reference, grok.reference]);
  assert.equal(supported(grok.schema, both), false, 'Grok is proven only by a build that lists it');
  const fixtures = {captureProvider: false, schemas: [{schemaId: 'pines.fixture.httpbingo', version: 1}]};
  assert.deepEqual(buildEntries(registry, fixtures).map(entry => entry.reference), [fixture.reference]);
  // A provider schema needs a capture build; an unknown or empty list is refused outright.
  for (const config of [{...both, captureProvider: false}, {captureProvider: true, schemas: []}, {captureProvider: true},
    {captureProvider: true, schemas: [{schemaId: 'pines.claude.plan', version: 2}]}, {captureProvider: true, schemas: [{schemaId: 'pines.unknown.plan', version: 1}]}])
    assert.throws(() => buildEntries(registry, config), /SCHEMA_UNAVAILABLE/);
});
