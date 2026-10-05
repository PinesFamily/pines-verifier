// Maintained provider flow, with native selective disclosure over the quote-bound
// encrypted channel. No transcript, raw identifier or pseudonym leaves this worker.
import initWasm, {initialize, Prover} from './wasm/tlsn_wasm.js';
import {providerForSchema, planDisclosureForProvider, providerPseudonym} from '../../../tools/tee-native/profile.mjs';
import {policyForSchema} from '../../../tools/tee-native/policy.mjs';
import {prepareReplay} from '../../../packages/verification-schemas/src/capture.ts';
import {encryptedClient} from '../../../tools/tee-native/client.mjs';
import {initializeNitro} from '../../../tools/tee-native/nitro.mjs';
import {check} from '../../../tools/tee-native/wire.mjs';
import config from './config.js';
let active, captured, consent;
self.onmessage = ({data}) => {
  if (data.type === 'replay' && data.runId === active) {captured?.(data.replay); captured = undefined;}
  if (data.type === 'approve' && data.runId === active) {consent?.(); consent = undefined;}
  if (data.type === 'start' && !active) {active = data.runId; void run(data);}
};
async function run({runId, attempt, recipient}) {
  let io, prover, sent, recv, failureCode = 'PROOF_FAILED';
  const phase = (phase, preview) => self.postMessage({runId, phase, ...(preview ? {preview} : {})});
  try {
    check(self.crossOriginIsolated, 'ISOLATION_REQUIRED');
    const provider = providerForSchema(attempt?.schema);
    check(provider && config.tee, 'HARDWARE_PROFILE_UNQUALIFIED');
    const policy = await policyForSchema(config.tee.policySet, provider.reference);
    check(policy?.admissionEnabled && provider.inventory.qualified, 'HARDWARE_PROFILE_UNQUALIFIED');
    const pending = new Promise(resolve => {captured = resolve;}); phase('awaiting-capture');
    const value = await pending;
    const replay = prepareReplay(provider.schema, {url: value.url, method: value.method, body: value.body,
      headers: Object.entries(value.headers).map(([name, value]) => ({name, value}))});
    phase('initializing');
    failureCode = 'TEE_ATTESTATION_INIT_FAILED';
    await initializeNitro(await (await fetch(new URL('./nitro-validation.wasm', import.meta.url))).arrayBuffer());
    failureCode = 'TEE_CHANNEL_FAILED';
    io = await encryptedClient({...config.tee, policy, schema: provider.reference, wallet: recipient, authorization: attempt.ticket, attemptId: attempt.attemptId});
    failureCode = 'TEE_NATIVE_INIT_FAILED';
    await initWasm(); await initialize({level: 'Error', crate_filters: [], span_events: []}, 2);
    failureCode = 'TEE_NATIVE_CONFIG_FAILED';
    prover = new Prover({server_name: provider.host, mode: 'Proxy', network: 'Bandwidth', max_sent_data: provider.schema.limits.maxSentBytes, max_recv_data: provider.schema.limits.maxRecvBytes,
      ...(config.tee.fixture?.hardware === true ? {root_certs: [config.tee.fixture.root]} : {})});
    failureCode = 'TEE_NATIVE_SETUP_FAILED';
    phase('requesting'); await prover.setup(io);
    const headers = new Map(Object.entries(replay.headers).map(([name, value]) => [name, Array.from(new TextEncoder().encode(value))]));
    failureCode = 'TEE_PROVIDER_REQUEST_FAILED';
    await prover.send_request(undefined, {uri: provider.endpoint, method: provider.schema.request.method, headers, body: undefined});
    const transcript = prover.transcript(); sent = new Uint8Array(transcript.sent); recv = new Uint8Array(transcript.recv);
    const status = /^HTTP\/1\.1 ([1-5]\d{2}) /.exec(new TextDecoder().decode(recv.subarray(0, 128)))?.[1];
    if (status !== '200') throw Error(['401', '403', '429'].includes(status) ? `PROVIDER_HTTP_${status}` : 'PROVIDER_RESPONSE_UNSUPPORTED');
    failureCode = 'TEE_DISCLOSURE_FAILED';
    const plan = planDisclosureForProvider(provider, sent, recv, recipient);
    const facts = {pseudonym: await providerPseudonym(provider, plan.facts.id), plan: plan.facts.plan, sentBytes: sent.length, recvBytes: recv.length};
    const approved = new Promise(resolve => {consent = resolve;});
    phase('awaiting-disclosure', {plan: facts.plan}); await approved;
    failureCode = 'TEE_PROOF_FAILED';
    phase('proving'); await prover.reveal(plan.reveal); await io.finish(facts);
    prover.free(); prover = undefined; await io.close(); io = undefined;
    // The page still waits for its own authenticated API status before success.
    phase('completed');
  } catch (error) {
    const safe = new Set(['HARDWARE_PROFILE_UNQUALIFIED', 'PROVIDER_INVENTORY_UNQUALIFIED', 'UNQUALIFIED_FIELD', 'UNQUALIFIED_HEADER',
      'PROVIDER_HTTP_401', 'PROVIDER_HTTP_403', 'PROVIDER_HTTP_429', 'PROVIDER_RESPONSE_UNSUPPORTED', 'ISOLATION_REQUIRED', 'ADMISSION_REFUSED', 'API_REFUSED', 'CHANNEL_REFUSED', 'TICKET_EXPIRED', 'INELIGIBLE_PLAN']);
    // API_REFUSED occurs only after independent receipt validation. Keep the
    // proof complete but unconfirmed while the page polls durable outbox delivery.
    if (error?.message === 'API_REFUSED') phase('completed');
    else self.postMessage({runId, phase: 'failed', error: safe.has(error?.message) ? error.message : failureCode});
  } finally {
    captured = undefined; consent = undefined; sent?.fill(0); recv?.fill(0); await io?.close();
    // Rejected Rust futures may retain borrows. Background closes the complete
    // offscreen document/thread group on every terminal outcome.
    self.close();
  }
}
