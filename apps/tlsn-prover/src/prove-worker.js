// Adapted from BringID/tlsn-extension's ProveManager/worker.ts at 604694d8.
// Keep WASM/prover/transcripts inside the worker; expose only bounded progress and
// an extension-only disclosure preview.
import initWasm, {initialize, Prover} from './wasm/tlsn_wasm.js';
import {loadRegistry, prepareReplay, requestTarget, planDisclosure} from './schemas/src/index.js';
import {openSocket} from './transport.js';
import config from './config.js';
import {validateAttempt, recipientOf, check, supported} from './policy.js';

let active;
let approve;
let captured;
self.onmessage = ({data}) => {
  if (data.type === 'replay' && data.runId === active) { captured?.(data.replay); captured = undefined; return; }
  if (data.type === 'approve' && data.runId === active) { approve?.(); return; }
  if (data.type !== 'start' || active) return;
  active = data.runId;
  void prove(data);
};
async function prove({runId, attempt, recipient, verifierOrigin}) {
  let session, protocol, prover, completion, serverError, succeeded = false;
  const phase = (phase, preview) => self.postMessage({runId, phase, ...(preview ? {preview} : {})});
  const receive = async () => {
    const bytes = await session.read(); check(bytes && bytes.length < 32768, 'VERIFIER_UNAVAILABLE');
    let value; try { value = JSON.parse(bytes); } catch { throw Error('VERIFIER_UNAVAILABLE'); }
    if (value.type === 'error') { serverError = /^[A-Z_]{1,64}$/.test(value.code) ? value.code : 'VERIFIER_REFUSED'; throw Error(serverError); }
    return value;
  };
  try {
    check(self.crossOriginIsolated && typeof SharedArrayBuffer === 'function', 'ISOLATION_REQUIRED');
    const registry = await loadRegistry(); const schema = registry.resolve(attempt.schema);
    // resolve() pins the digest; the build's schema list decides which may run here.
    check(supported(schema, config), 'SCHEMA_UNAVAILABLE');
    validateAttempt(attempt, recipientOf(recipient), attempt.schema, schema, config);
    // The background checked this instance's /info; the worker connects nowhere else.
    check(verifierOrigin === attempt.verifierOrigin, 'ATTEMPT_MISMATCH');
    let replay;
    if (config.captureProvider) {
      const incoming = new Promise(resolve => { captured = resolve; });
      phase('awaiting-capture');
      const value = await incoming;
      replay = prepareReplay(schema, {url: value.url, method: value.method, body: value.body,
        headers: Object.entries(value.headers).map(([name, value]) => ({name, value}))});
      validateAttempt(attempt, recipientOf(recipient), attempt.schema, schema, config);
    } else {
      replay = prepareReplay(schema, {url: schema.request.origin + requestTarget(schema), method: schema.request.method, headers: []});
    }
    phase('initializing');
    await initWasm(); await initialize({level: 'Error', crate_filters: [], span_events: []}, 2);
    const base = new URL(verifierOrigin); base.protocol = base.protocol === 'https:' ? 'wss:' : 'ws:';
    // A refused WebSocket upgrade (capacity, drain) is not a provider or proof failure: report it as reachability.
    session = await openSocket(new URL('/session', base)).catch(() => { throw Error('VERIFIER_UNREACHABLE'); });
    await session.write(JSON.stringify({type: 'register', ticket: attempt.ticket, maxSentData: schema.limits.maxSentBytes, maxRecvData: schema.limits.maxRecvBytes}));
    const registered = await receive(); check(registered.type === 'session_registered', 'VERIFIER_REFUSED');
    completion = receive(); const failed = completion.then(() => new Promise(() => {})); void failed.catch(() => {});
    const checked = promise => Promise.race([promise, failed]);
    prover = new Prover({server_name: new URL(schema.request.origin).hostname, mode: 'Proxy', network: 'Bandwidth', max_sent_data: schema.limits.maxSentBytes, max_recv_data: schema.limits.maxRecvBytes});
    const url = new URL('/verifier', base); url.searchParams.set('sessionId', registered.sessionId);
    protocol = await openSocket(url, true).catch(() => { throw Error('VERIFIER_UNREACHABLE'); }); await checked(prover.setup(protocol));
    phase('requesting');
    const headers = new Map(Object.entries(replay.headers).map(([key, value]) => [key, Array.from(new TextEncoder().encode(value))]));
    await checked(prover.send_request(undefined, {uri: requestTarget(schema), method: replay.method, headers, body: undefined}));
    const transcript = prover.transcript(); const sent = new Uint8Array(transcript.sent); const recv = new Uint8Array(transcript.recv);
    const status = /^HTTP\/1\.1 ([1-5]\d{2}) /.exec(new TextDecoder().decode(recv.subarray(0, 128)))?.[1];
    if (status !== '200') throw Error(['401', '403', '429'].includes(status) ? `PROVIDER_HTTP_${status}` : 'PROVIDER_RESPONSE_UNSUPPORTED');
    const disclosure = planDisclosure(schema, sent, recv, recipient);
    // `fields` are the values the verifier will judge, read by the same selector: a list response (Grok's
    // subscriptions, Claude's organizations) is summarized by the entry that qualifies, never by its first one.
    phase('awaiting-disclosure', {request: disclosedText(sent, disclosure.sent), response: disclosedText(recv, disclosure.recv), sentBytes: sent.length, recvBytes: recv.length, fields: {...disclosure.preview.values}});
    await checked(new Promise(resolve => { approve = resolve; })); approve = undefined;
    phase('proving');
    const ranges = (entries, type) => entries.map(range => ({...range, handler: {type, part: 'ALL', action: {kind: 'REVEAL'}}}));
    await session.write(JSON.stringify({type: 'reveal_config', sent: ranges(disclosure.sent, 'SENT'), recv: ranges(disclosure.recv, 'RECV')}));
    await checked(prover.reveal({sent: disclosure.sent, recv: disclosure.recv, server_identity: true}));
    const result = await completion;
    check(result.type === 'session_completed' && Array.isArray(result.results) && result.results.length === 0, 'INVALID_VERIFIER_RESULT');
    succeeded = true; phase('completed');
  } catch (error) {
    const known = new Set(['ISOLATION_REQUIRED', 'TICKET_EXPIRED', 'ATTEMPT_MISMATCH', 'SCHEMA_UNAVAILABLE', 'VERIFIER_UNREACHABLE', 'VERIFIER_ORIGIN_REFUSED', 'PROVIDER_HTTP_401', 'PROVIDER_HTTP_403', 'PROVIDER_HTTP_429', 'PROVIDER_RESPONSE_UNSUPPORTED']);
    self.postMessage({runId, phase: 'failed', error: serverError ?? (known.has(error.message) ? error.message : 'PROOF_FAILED')});
  } finally {
    approve = undefined; captured = undefined;
    await session?.close(); await protocol?.close();
    // A rejected WASM future can retain a borrow; its owner terminates this worker.
    if (succeeded) prover?.free();
  }
}

// Preview exactly what native selective disclosure shares; credentials never
// leave this worker, including in extension-only review messages.
function disclosedText(bytes, ranges) {
  const decoder = new TextDecoder('utf-8', {fatal: true});
  let text = '', cursor = 0;
  for (const range of ranges) {
    if (range.start > cursor) text += '[hidden]';
    text += decoder.decode(bytes.subarray(range.start, range.end)); cursor = range.end;
  }
  if (cursor < bytes.length) text += '[hidden]';
  return text;
}
