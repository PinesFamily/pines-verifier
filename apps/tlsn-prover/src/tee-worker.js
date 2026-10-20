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
import {UPFRONT_CONSENT_VERSION} from './preparation.js';
import {sessionSnapshot} from './session-timing.js';
import {newReplayMetadata,updateReplayMetadata,advanceReplayProofStep,measureDecodedBody} from './replay-metadata.mjs';
import {PRIVATE_HEADERS_POLICY_ID,PRIVATE_HEADERS_FAILURES,isPrivateHeadersSchema,pathParamsFrom,policyIdOf,requiresPathParams,schemaFailureCode} from './private-headers.mjs';
import {prepareReplayFor,requestTargetFor} from '../capture/schema-adapter.mjs';
import {gunzip} from '../../../packages/verification-schemas/src/gzip.ts';
import {previewExchange} from '../../../packages/verification-schemas/src/evaluate.ts';
import {metadataChannel,replayMetadataFailureCode} from './qualification-metadata-channel.mjs';
let active;
const metadataAcks=metadataChannel({send:message=>self.postMessage(message)});
self.onmessage = ({data}) => {
  if(data.type==='replay-metadata-ack'&&data.runId===active){metadataAcks.acknowledge(data);return;}
  if (data.type === 'start' && !active) {active = data.runId; void run(data);}
};
// A plan this release does not verify (ChatGPT Free or Go, say) fails the schema's plan check as a bare CHECK_FAILED,
// which would read as a broken response. Re-run the same local precheck without the plan field's checks: when it then
// passes, the plan was the only refusal. Nothing is revealed either way; this only picks the code the panel explains.
function onlyThePlanFailed(error, provider, sent, recv, recipient) {
  if (error?.name !== 'SchemaError' || error.code !== 'CHECK_FAILED' || typeof provider.planField !== 'string') return false;
  const checks = provider.schema.checks.filter(rule => rule.field !== provider.planField);
  if (checks.length === provider.schema.checks.length) return false;
  try {previewExchange({...provider.schema, checks}, sent, recv, recipient); return true;} catch {return false;}
}
async function persistMetadata(runId,record) {
  await metadataAcks.persist(runId,record);
}
function metadataRecord(create) {
  try{return create();}catch{throw Error('REPLAY_METADATA_BUILD_FAILED');}
}
async function run({runId, attempt, recipient, upfrontConsent, replay: value}) {
  let io, prover, sent, recv, metadata, receiptVerified=false, failureCode = 'PROOF_FAILED';
  const phase = (phase, preview) => self.postMessage({runId, phase, ...(preview ? {preview} : {})});
  try {
    check(upfrontConsent === UPFRONT_CONSENT_VERSION && value, 'CONSENT_REQUIRED');
    check(self.crossOriginIsolated, 'ISOLATION_REQUIRED');
    // The build's signed policy selects its provider set (B2 providersFor); full-response gives today's providers.
    const provider = providerForSchema(attempt?.schema, config.tee?.disclosurePolicy);
    check(provider && config.tee, 'HARDWARE_PROFILE_UNQUALIFIED');
    const policy = await policyForSchema(config.tee.policySet, provider.reference, config.tee?.disclosurePolicy);
    check(policy?.admissionEnabled && provider.inventory.qualified, 'HARDWARE_PROFILE_UNQUALIFIED');
    // private-headers-gzip-v1 (plan D3/D12): the target is the instantiated per-org path or the filtered route,
    // re-derived from this one replay's own URL. Every other schema keeps its fixed endpoint and call.
    const privateHeaders = isPrivateHeadersSchema(provider.schema);
    const pathParams = privateHeaders && requiresPathParams(provider.schema) ? pathParamsFrom(provider.schema, value.url, {exact: true}) : undefined;
    check(pathParams !== null, 'CLAUDE_ORG_UNAVAILABLE');
    const captured = {url: value.url, method: value.method, body: value.body,
      headers: Object.entries(value.headers).map(([name, value]) => ({name, value}))};
    const replay = privateHeaders ? prepareReplayFor(provider.schema, captured, pathParams) : prepareReplay(provider.schema, captured);
    const target = privateHeaders ? requestTargetFor(provider.schema, pathParams) : provider.endpoint;
    phase('initializing');
    failureCode = 'TEE_ATTESTATION_INIT_FAILED';
    await initializeNitro(await (await fetch(new URL('./nitro-validation.wasm', import.meta.url))).arrayBuffer());
    failureCode = 'TEE_CHANNEL_FAILED';
    const timing = sessionSnapshot(attempt);
    io = await encryptedClient({...config.tee, policy, schema: provider.reference, wallet: recipient, authorization: attempt.ticket, attemptId: attempt.attemptId,
      sessionPolicySnapshot: {issuedAt: attempt.issuedAt, ...timing}});
    // The consent shown was keyed on this build's policy; a private-headers schema runs only under that policy.
    if (privateHeaders || policyIdOf(io.disclosurePolicy) === PRIVATE_HEADERS_POLICY_ID)
      check(privateHeaders && policyIdOf(io.disclosurePolicy) === PRIVATE_HEADERS_POLICY_ID && config.tee.disclosurePolicy === PRIVATE_HEADERS_POLICY_ID, 'DISCLOSURE_POLICY_BINDING');
    failureCode = 'TEE_NATIVE_INIT_FAILED';
    await initWasm(); await initialize({level: 'Error', crate_filters: [], span_events: []}, 2);
    failureCode = 'TEE_NATIVE_CONFIG_FAILED';
    prover = new Prover({server_name: provider.host, mode: 'Proxy', network: 'Bandwidth', max_sent_data: provider.schema.limits.maxSentBytes, max_recv_data: provider.schema.limits.maxRecvBytes,
      ...(config.tee.fixture?.hardware === true ? {root_certs: [config.tee.fixture.root]} : {})});
    failureCode = 'TEE_NATIVE_SETUP_FAILED';
    phase('requesting'); await prover.setup(io);
    const headers = new Map(Object.entries(replay.headers).map(([name, value]) => [name, Array.from(new TextEncoder().encode(value))]));
    failureCode = 'TEE_PROVIDER_REQUEST_FAILED';
    try {await prover.send_request(undefined, {uri: target, method: provider.schema.request.method, headers, body: undefined});}
    catch(error){
      // Some SDK failures leave a partial transcript. Capture bounded status
      // categories if available; absence remains explicit, never a guessed 403.
      let partial;
      try{partial=new Uint8Array(prover.transcript().recv);}catch{}
      try{metadata=metadataRecord(()=>newReplayMetadata({config,runId,attemptId:attempt.attemptId,provider:provider.id,
        bytes:partial??new Uint8Array(),transport:partial?'failed':'unavailable',...(privateHeaders?{privateHeaders}:{})}));await persistMetadata(runId,metadata);}
      finally{partial?.fill(0);}
      throw error;
    }
    const transcript = prover.transcript(); sent = new Uint8Array(transcript.sent); recv = new Uint8Array(transcript.recv);
    // Only this replay response is inspected, after the strict attested channel
    // handshake. Never persist request headers, raw response values or the body.
    // Private-headers runs add value-free framing: gzip honoured or not, encoded and decoded sizes (§7.1).
    try{metadata=newReplayMetadata({config,runId,attemptId:attempt.attemptId,provider:provider.id,bytes:recv,
      ...(privateHeaders?{privateHeaders,decodedBodyBytes:config.qualificationResponseMetadata?await measureDecodedBody(recv,
        {maxDecodedBytes:provider.schema.limits.maxDecodedBodyBytes,decode:gunzip}):undefined}:{})});}
    catch{throw Error('REPLAY_METADATA_BUILD_FAILED');}
    await persistMetadata(runId,metadata);
    check(recv.length<=provider.schema.limits.maxRecvBytes,'PROVIDER_RESPONSE_TOO_LARGE');
    const status = /^HTTP\/1\.1 ([1-5]\d{2}) /.exec(new TextDecoder().decode(recv.subarray(0, 128)))?.[1];
    if (status !== '200') {
      metadata=metadataRecord(()=>updateReplayMetadata(metadata,'http-error'));await persistMetadata(runId,metadata);
      throw Error(['401', '403', '429'].includes(status) ? `PROVIDER_HTTP_${status}` : 'PROVIDER_RESPONSE_UNSUPPORTED');
    }
    failureCode = 'TEE_DISCLOSURE_FAILED';
    let plan;
    try {plan = planDisclosureForProvider(provider, sent, recv, recipient, io.disclosurePolicy);}
    catch (error) {throw onlyThePlanFailed(error, provider, sent, recv, recipient) ? Error('INELIGIBLE_PLAN') : error;}
    const facts = {...(policy.identity?{accountId:plan.facts.id}:{pseudonym:await providerPseudonym(provider,plan.facts.id)}),
      plan: plan.facts.plan, sentBytes: sent.length, recvBytes: recv.length};
    metadata=metadataRecord(()=>updateReplayMetadata(metadata,'signed-in-shape'));await persistMetadata(runId,metadata);
    failureCode = 'TEE_PROOF_FAILED';
    phase('proving', {plan: facts.plan});
    metadata=metadataRecord(()=>advanceReplayProofStep(metadata,'reveal-started'));await persistMetadata(runId,metadata);
    await prover.reveal(plan.reveal);
    metadata=metadataRecord(()=>advanceReplayProofStep(metadata,'reveal-completed'));await persistMetadata(runId,metadata);
    metadata=metadataRecord(()=>advanceReplayProofStep(metadata,'finish-started'));await persistMetadata(runId,metadata);
    await io.finish(facts);receiptVerified=true;
    metadata=metadataRecord(()=>updateReplayMetadata(metadata,'receipt-verified'));await persistMetadata(runId,metadata);
    prover.free(); prover = undefined; await io.close(); io = undefined;
    // The page still waits for its own authenticated API status before success.
    phase('completed');
  } catch (error) {
    // API_REFUSED follows checkReceipt inside encryptedClient.finish; it does
    // not assert durable API acceptance. The operator must join attemptId.
    receiptVerified=receiptVerified||error?.message==='API_REFUSED';
    let metadataFailure=replayMetadataFailureCode(error?.message);
    if(metadata&&!metadataFailure){
      try{metadata=metadataRecord(()=>updateReplayMetadata(metadata,receiptVerified?'receipt-verified':metadata.outcome==='http-error'?'http-error':'proof-failed'));
        await persistMetadata(runId,metadata);}catch(metadataError){metadataFailure=replayMetadataFailureCode(metadataError?.message)??'REPLAY_METADATA_UNAVAILABLE';}
    }
    const safe = new Set(['HARDWARE_PROFILE_UNQUALIFIED', 'PROVIDER_INVENTORY_UNQUALIFIED', 'UNQUALIFIED_FIELD', 'UNQUALIFIED_HEADER',
      'PROVIDER_HTTP_401', 'PROVIDER_HTTP_403', 'PROVIDER_HTTP_429', 'PROVIDER_RESPONSE_UNSUPPORTED', 'PROVIDER_RESPONSE_TOO_LARGE', 'ISOLATION_REQUIRED', 'ADMISSION_REFUSED', 'API_REFUSED', 'CHANNEL_REFUSED', 'TICKET_EXPIRED', 'INELIGIBLE_PLAN',
      'CONSENT_REQUIRED', 'SESSION_POLICY_UNSUPPORTED', 'SESSION_POLICY_INVALID', 'PROOF_TIMEOUT', 'REPLAY_METADATA_UNAVAILABLE',
      'DISCLOSURE_POLICY', 'DISCLOSURE_POLICY_BINDING', 'DISCLOSURE_LIMIT', 'DISCLOSURE_REQUEST_RANGES', 'FULL_RESPONSE_REQUIRED', ...PRIVATE_HEADERS_FAILURES]);
    // The schema package reports its refusals as SchemaError codes; only the private-headers ones get their own.
    const mapped = schemaFailureCode(error);
    // API_REFUSED occurs only after independent receipt validation. Keep the
    // proof complete but unconfirmed while the page polls durable outbox delivery.
    if (error?.message==='API_REFUSED'||metadataFailure&&receiptVerified) self.postMessage({runId,phase:'completed',...(metadataFailure?{error:metadataFailure}:{})});
    else self.postMessage({runId, phase: 'failed', error: metadataFailure??(safe.has(error?.message) ? error.message : mapped ?? failureCode)});
  } finally {
    value = undefined; sent?.fill(0); recv?.fill(0); await io?.close();
    // Rejected Rust futures may retain borrows. Background closes the complete
    // offscreen document/thread group on every terminal outcome.
    self.close();
  }
}
