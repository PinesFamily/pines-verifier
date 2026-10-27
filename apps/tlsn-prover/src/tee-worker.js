// Maintained provider flow, with native selective disclosure over the quote-bound
// encrypted channel. No transcript, raw identifier or pseudonym leaves this worker.
import initWasm, {initialize, Prover} from './wasm/tlsn_wasm.js';
import {providerForSchema, planDisclosureForProvider, providerPseudonym} from '../../../tools/tee-native/profile.mjs';
import {policyForSchema} from '../../../tools/tee-native/policy.mjs';
import {MANIFEST_AUDIENCE, admittedSet} from '../../../tools/tee-native/trust-manifest.mjs';
import {verifyTrustManifest} from '../../../packages/verification-schemas/src/sybil/manifest.ts';
import {OWNER_KEYS} from '../../../packages/verification-schemas/src/sybil/owner-keys.ts';
import {manifestKeysOf, manifestRequired} from './trust-manifest.mjs';
import {prepareReplay} from '../../../packages/verification-schemas/src/capture.ts';
import {encryptedClient} from '../../../tools/tee-native/client.mjs';
import {initializeNitro} from '../../../tools/tee-native/nitro.mjs';
import {check} from '../../../tools/tee-native/wire.mjs';
import config from './config.js';
import {grokCompanion} from './grok-companion.mjs';
import {UPFRONT_CONSENT_VERSION} from './preparation.js';
import {sessionSnapshot} from './session-timing.js';
import {newReplayMetadata,updateReplayMetadata,advanceReplayProofStep,measureDecodedBody} from './replay-metadata.mjs';
import {PRIVATE_HEADERS_POLICY_ID,GROK_CLEARANCE_POLICY_ID,privatePolicyForSchema,PRIVATE_HEADERS_FAILURES,isPrivateHeadersSchema,pathParamsFrom,policyIdOf,requiresPathParams,schemaFailureCode} from './private-headers.mjs';
import {prepareReplayFor,requestTargetFor} from '../capture/schema-adapter.mjs';
import {gunzip} from '../../../packages/verification-schemas/src/gzip.ts';
import {previewExchange} from '../../../packages/verification-schemas/src/evaluate.ts';
import {metadataChannel,replayMetadataFailureCode} from './qualification-metadata-channel.mjs';
import {exchangeCount,sessionReplays} from './exchanges.mjs';
import {emailCommitment} from '../../../packages/verification-schemas/src/sybil/facts.ts';
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
/**
 * The policy this run proves under: from the owner-signed manifest the background fetched, verified here again with
 * the pinned keys and the build's audience and reduced to this class's policy set exactly as the identity does
 * (every bundled definition's digest must match; the images and revocations must agree with the policies); or,
 * for a build that opted out (qualification and fixture harnesses only), the policy set bundled at build time.
 */
async function policyFor(provider, manifest, config) {
  if (!manifestRequired(config)) return policyForSchema(config.tee.policySet, provider.reference, config.tee?.disclosurePolicy);
  check(manifest, 'MANIFEST_REQUIRED');
  let verified;
  try {verified = await verifyTrustManifest(manifest, {keys: manifestKeysOf(config, OWNER_KEYS), audience: {...MANIFEST_AUDIENCE, application: config.application, chain: config.chainId}});}
  catch (error) {throw Error(/^MANIFEST_[A-Z_]+$/.test(error?.code ?? '') ? error.code : 'MANIFEST_INVALID');}
  const set = await admittedSet(verified.manifest, config.tee?.disclosurePolicy, config.tee?.generation === undefined ? {} : {generation: config.tee.generation});
  return set.policies.get(provider.id) ?? null;
}
async function run({runId, attempt, recipient, upfrontConsent, replay: value, manifest, extensionVersion, assisted}) {
  const selectedConfig = assisted === true ? grokCompanion(config) : config;
  return runSelected({runId, attempt, recipient, upfrontConsent, replay: value, manifest, extensionVersion}, selectedConfig);
}
async function runSelected({runId, attempt, recipient, upfrontConsent, replay: value, manifest, extensionVersion}, config) {
  let io, prover, sent, recv, metadata, receiptVerified=false, failureCode = 'PROOF_FAILED';
  const phase = (phase, preview) => self.postMessage({runId, phase, ...(preview ? {preview} : {})});
  try {
    check(upfrontConsent === UPFRONT_CONSENT_VERSION && value, 'CONSENT_REQUIRED');
    check(self.crossOriginIsolated, 'ISOLATION_REQUIRED');
    // The build's signed policy selects its provider set (B2 providersFor); full-response gives today's providers.
    const provider = providerForSchema(attempt?.schema, config.tee?.disclosurePolicy);
    check(provider && config.tee, 'HARDWARE_PROFILE_UNQUALIFIED');
    failureCode = 'MANIFEST_INVALID';
    const policy = await policyFor(provider, manifest, config);
    failureCode = 'PROOF_FAILED';
    check(policy?.admissionEnabled && provider.inventory.qualified, 'HARDWARE_PROFILE_UNQUALIFIED');
    // private-headers-gzip-v1 (plan D3/D12): the target is the instantiated per-org path or the filtered route,
    // re-derived from this one replay's own URL. Every other schema keeps its fixed endpoint and call.
    const privateHeaders = isPrivateHeadersSchema(provider.schema);
    // A templated first request (Claude's per-org route) is a property of the schema, not of its class: the
    // facts-complete class carries it too (multi-exchange protocol §2.2).
    const templated = requiresPathParams(provider.schema);
    // The target is re-derived from the schema (its filtered route — Grok's `?status=SUBSCRIPTION_STATUS_ACTIVE` — or its
    // instantiated path) for the private-headers and facts-complete classes and for any templated schema; only the
    // legacy full-response schemas keep their fixed endpoint (sybil integration, identity integration specification §6a).
    const derived = templated || privateHeaders || policyIdOf(provider.schema) === 'facts-complete-v1';
    const pathParams = templated ? pathParamsFrom(provider.schema, value.url, {exact: true}) : undefined;
    check(pathParams !== null, 'CLAUDE_ORG_UNAVAILABLE');
    // The capture's exchange-only headers (capture/session.mjs) join the first exchange's for the session's replays.
    const captured = {url: value.url, method: value.method, body: value.body,
      headers: [...Object.entries(value.headers).map(([name, value]) => ({name, value})), ...(Array.isArray(value.exchangeHeaders) ? value.exchangeHeaders : [])]};
    const replay = derived ? prepareReplayFor(provider.schema, captured, pathParams) : prepareReplay(provider.schema, captured);
    const target = derived ? requestTargetFor(provider.schema, pathParams) : provider.endpoint;
    // A multi-exchange schema (multi-exchange protocol §1.7) needs every request of the session issued on ONE TLS
    // connection: `send_requests`, which the pinned prover carries since patch 0002. A prover
    // without it (stock `tlsn-wasm` sends one request per session) refuses such a schema here, before any admission
    // is spent. The ordered replays are prepared first so a capture that cannot serve every exchange refuses as a capture.
    const session = exchangeCount(provider.schema) > 1 ? sessionReplays(provider.schema, captured, pathParams) : undefined;
    check(!session || typeof Prover.prototype.send_requests === 'function', 'EXCHANGES_UNSUPPORTED');
    phase('initializing');
    failureCode = 'TEE_ATTESTATION_INIT_FAILED';
    await initializeNitro(await (await fetch(new URL('./nitro-validation.wasm', import.meta.url))).arrayBuffer());
    failureCode = 'TEE_CHANNEL_FAILED';
    const timing = sessionSnapshot(attempt);
    io = await encryptedClient({...config.tee, policy, schema: provider.reference, wallet: recipient, authorization: attempt.ticket, attemptId: attempt.attemptId,
      sessionPolicySnapshot: {issuedAt: attempt.issuedAt, ...timing}, ...(typeof extensionVersion === 'string' ? {clientHeaders: {'x-pines-extension-version': extensionVersion}} : {})});
    // The consent shown was keyed on this build's policy; a private-headers schema runs only under that policy.
    if (privateHeaders || [PRIVATE_HEADERS_POLICY_ID, GROK_CLEARANCE_POLICY_ID].includes(policyIdOf(io.disclosurePolicy))) {
      const expectedPolicy = privatePolicyForSchema(provider.schema);
      check(privateHeaders && policyIdOf(io.disclosurePolicy) === expectedPolicy && config.tee.disclosurePolicy === expectedPolicy, 'DISCLOSURE_POLICY_BINDING');
    }
    failureCode = 'TEE_NATIVE_INIT_FAILED';
    await initWasm(); await initialize({level: 'Error', crate_filters: [], span_events: []}, 2);
    failureCode = 'TEE_NATIVE_CONFIG_FAILED';
    prover = new Prover({server_name: provider.host, mode: 'Proxy', network: 'Bandwidth', max_sent_data: provider.schema.limits.maxSentBytes, max_recv_data: provider.schema.limits.maxRecvBytes,
      ...(config.tee.fixture?.hardware === true ? {root_certs: [config.tee.fixture.root]} : {})});
    failureCode = 'TEE_NATIVE_SETUP_FAILED';
    phase('requesting'); await prover.setup(io);
    const encodeHeaders = value => new Map(Object.entries(value.headers).map(([name, text]) => [name, Array.from(new TextEncoder().encode(text))]));
    const headers = encodeHeaders(replay);
    failureCode = 'TEE_PROVIDER_REQUEST_FAILED';
    // One session: the requests in schema order, each the exact replay the schema package built for its exchange.
    try {if (session) await prover.send_requests(undefined, session.replays.map((entry, index) => ({uri: session.targets[index], method: provider.schema.request.method, headers: encodeHeaders(entry), body: undefined})));
      else await prover.send_request(undefined, {uri: target, method: provider.schema.request.method, headers, body: undefined});}
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
      const headEnd = recv.findIndex((byte, index) => byte === 13 && recv[index + 1] === 10 && recv[index + 2] === 13 && recv[index + 3] === 10);
      if (headEnd > 0 && /^cf-mitigated:\s*challenge\s*$/im.test(new TextDecoder().decode(recv.subarray(0, headEnd))))
        throw Error('PROVIDER_CHALLENGE');
      throw Error(['401', '403', '429'].includes(status) ? `PROVIDER_HTTP_${status}` : 'PROVIDER_RESPONSE_UNSUPPORTED');
    }
    failureCode = 'TEE_DISCLOSURE_FAILED';
    let plan;
    try {plan = planDisclosureForProvider(provider, sent, recv, recipient, io.disclosurePolicy);}
    catch (error) {throw onlyThePlanFailed(error, provider, sent, recv, recipient) ? Error('INELIGIBLE_PLAN') : error;}
    // The receipt facts (multi-exchange protocol §1.4) ride beside the plan; absent when the schema discloses none. The
    // e-mail (§2.5) is never a receipt value: the local facts carry its commitment under the enclave session, as the
    // enclave signs it; the address itself stays in the enclave's transient member and never in this worker's messages.
    const values = plan.facts.values || plan.facts.transient
      ? {...(plan.facts.values ?? {}), ...(plan.facts.transient?.email ? {pines_email_commitment: await emailCommitment(io.session, plan.facts.transient.email)} : {})} : undefined;
    const facts = {...(policy.identity?{accountId:plan.facts.id}:{pseudonym:await providerPseudonym(provider,plan.facts.id)}),
      plan: plan.facts.plan, sentBytes: sent.length, recvBytes: recv.length, ...(values ? {values} : {})};
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
    const safe = new Set(['MANIFEST_REQUIRED', 'MANIFEST_INVALID', 'MANIFEST_SIGNATURE', 'MANIFEST_UNSIGNED', 'MANIFEST_KEY_UNKNOWN', 'MANIFEST_AUDIENCE', 'MANIFEST_ROLLBACK', 'MANIFEST_FIELDS', 'MANIFEST_FORMAT',
      'TRUST_MANIFEST_CAPABILITY', 'TRUST_MANIFEST_IMAGES', 'TRUST_MANIFEST_REVOCATIONS', 'TRUST_MANIFEST_PROFILE', 'TRUST_MANIFEST_CONTEXT', 'TRUST_MANIFEST_AUDIENCE', 'TRUST_MANIFEST_POLICY',
      'HARDWARE_PROFILE_UNQUALIFIED', 'PROVIDER_INVENTORY_UNQUALIFIED', 'UNQUALIFIED_FIELD', 'UNQUALIFIED_HEADER', 'PROVIDER_CHALLENGE',
      'PROVIDER_HTTP_401', 'PROVIDER_HTTP_403', 'PROVIDER_HTTP_429', 'PROVIDER_RESPONSE_UNSUPPORTED', 'PROVIDER_RESPONSE_TOO_LARGE', 'ISOLATION_REQUIRED', 'ADMISSION_REFUSED', 'API_REFUSED', 'CHANNEL_REFUSED', 'TICKET_EXPIRED', 'INELIGIBLE_PLAN',
      'CONSENT_REQUIRED', 'SESSION_POLICY_UNSUPPORTED', 'SESSION_POLICY_INVALID', 'PROOF_TIMEOUT', 'REPLAY_METADATA_UNAVAILABLE', 'EXCHANGES_UNSUPPORTED',
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
