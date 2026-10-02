// Page-side adapter. Provider data and API login tokens never enter bridge messages.
// Lifecycle: the page stops *waiting* on its own; it asks the API to cancel only for
// an explicit user action or a run the extension reports as stopped before its reveal. A transient API error, a
// receipt-wait timeout or an unknown extension state never cancels: the proof may already be durable at the verifier.
import {linkedWalletOf} from './src/binding-error.mjs';
import {admissionErrors, retryTime} from './src/retry.js';
// The Chrome Web Store item's id. The store assigns an item its own id and refuses a manifest carrying `key`, so this
// is the store's key; an unpacked build from before 0.9.3 keeps the old pilot id and has to be reinstalled.
// It is `config/identity.json`'s `id`, and `release.mjs` refuses a build where the two disagree.
export const TLSN_EXTENSION_ID = 'lanmbpkmblcijblbllbikenpnceidmpj';
const protocol = 'pines-tlsn-bridge-v1';
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const revisionPattern = /^[a-zA-Z0-9._-]{1,80}$/;
// Schema versions whose receipts may be claimable once the API enables claims.
const claimableSchemas = ['pines.chatgpt.plan@2', 'pines.chatgpt.plan@3', 'pines.claude.plan@1', 'pines.grok.plan@1'];
const sameSchema = (a, b) => a && b && ['schemaId', 'version', 'digest'].every(key => a[key] === b[key]);
// A run that stops in these phases never sent its reveal, so no verifier result can follow it (src/prove-worker.js).
const PRE_PROOF_PHASES = new Set(['initializing', 'awaiting-permission', 'awaiting-capture', 'requesting', 'awaiting-disclosure']);
// The verifier refuses admission at registration, and a ticket expires before capture ends: both precede any reveal.
const PRE_PROOF_ERRORS = new Set(['ADMISSION_REFUSED', 'TICKET_EXPIRED', 'VERIFIER_UNREACHABLE', 'VERIFIER_BUSY', 'VERIFIER_VERSION_MISMATCH', 'VERIFIER_ORIGIN_REFUSED']);
/** API polling: at most one status read per 2 s (plus jitter) while waiting; faster only right after completion. */
export const POLL_INTERVAL_MS = 2000;
const POLL_JITTER_MS = 500;
/** Bounded exponential backoff for failed status reads: 1 s, 2 s, 4 s … 30 s, with jitter. */
const BACKOFF_MAX_MS = 30_000;
/** Page pacing when no extension answers (older extension, restored reference, extension gone). */
const IDLE_WAIT_MS = 1000;
const TRANSIENT = /^(API_(5\d\d|429|408)|VERIFICATION_UNAVAILABLE|WALLET_AUTH_UNAVAILABLE|NETWORK_ERROR|RATE_LIMITED|PROVIDER_CONTROL_UNAVAILABLE)$/;
export function createTlsnClient({request, extensionId = TLSN_EXTENSION_ID, chainId, application, configuration, now = Date.now, random = Math.random,
  sleep = ms => new Promise(resolve => setTimeout(resolve, ms))}) {
  const cancelled = new Set();
  let ownerPort;
  const connectOwner = () => {
    if (ownerPort) return;
    const port = chrome.runtime.connect(extensionId, {name: 'pines-tlsn-owner-v1'}); ownerPort = port;
    port.onMessage.addListener(value => {if (typeof value?.nonce === 'string') port.postMessage({nonce: value.nonce});});
    port.onDisconnect.addListener(() => {if (ownerPort === port) ownerPort = undefined; void chrome.runtime.lastError;});
  };
  const message = (type, value = {}) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Error('EXTENSION_TIMEOUT')), 12_000);
    try {
      chrome.runtime.sendMessage(extensionId, {protocol, type, ...value}, response => {
        clearTimeout(timer);
        if (chrome.runtime.lastError || !response) reject(Error('EXTENSION_UNAVAILABLE'));
        else if (!response.ok) reject(Error(response.error ?? 'EXTENSION_UNAVAILABLE'));
        else resolve(response);
      });
    } catch { clearTimeout(timer); reject(Error('EXTENSION_UNAVAILABLE')); }
  });
  const api = async (path, init = {}) => {
    let response;
    try { response = await request(path, {...init, cache: 'no-store'}); }
    catch (error) { throw Object.assign(Error(/^[A-Z_]{1,64}$/.test(error?.message ?? '') ? error.message : 'NETWORK_ERROR'), {transient: true}); }
    if (!response.ok) {
      const body = await response.json().catch(() => null);
      const code = typeof body?.error === 'string' && /^[A-Z_]{1,64}$/.test(body.error) ? body.error : `API_${response.status}`;
      // Relative delay avoids a wrong countdown when the user's clock differs from the server.
      const delay = body?.retryAfterSeconds;
      const retryAt = Number.isSafeInteger(delay) && delay > 0 && delay <= 3600 ? now() + delay * 1000 : retryTime(body?.retryAt, now());
      throw Object.assign(Error(response.status === 401 ? 'WALLET_UNAUTHORIZED' : code), {status: response.status, retryAt});
    }
    return response.json();
  };
  const assignedRouting = value => configuration?.attemptRouting?.includes?.('assigned') === true && Array.isArray(value?.routing) && value.routing.includes('assigned');
  const checkStatus = (handle, value) => {
    if (value.attemptId !== handle.attempt.attemptId || value.recipient !== handle.recipient || value.mode !== 'Proxy' || typeof value.claimable !== 'boolean' || (value.claimable && (!configuration?.claimable || !claimableSchemas.includes(`${value.schema?.schemaId}@${value.schema?.version}`) || value.status !== 'verified')) || !sameSchema(value.schema, handle.attempt.schema)) throw Error('RECEIPT_CONTEXT_MISMATCH');
    // The API decides which verifier served an attempt. A pinned attempt must match discovery; an assigned one its
    // assignment; a restored reference (no assignment kept) any well-formed revision the API reports.
    const expectedRevision = handle.attempt.verifier?.revision ?? (handle.attempt.routing === 'pinned' ? configuration?.verifierRevision : undefined);
    if (configuration && (value.engine !== 'tlsn' || value.application !== application || value.chainId !== chainId || typeof value.verifierRevision !== 'string' || !revisionPattern.test(value.verifierRevision) || (expectedRevision !== undefined && value.verifierRevision !== expectedRevision))) throw Error('RECEIPT_CONTEXT_MISMATCH');
    if (value.linkedWallet !== undefined && (value.status !== 'failed' || !linkedWalletOf(value))) throw Error('RECEIPT_CONTEXT_MISMATCH');
    if (value.cancelRequested !== undefined && typeof value.cancelRequested !== 'boolean') throw Error('RECEIPT_CONTEXT_MISMATCH');
    return value;
  };
  // A request, not a verdict: the API settles it from the verifier's authenticated outcome.
  // `reason`: a bounded code for monitoring provider refusals (the API's stop reasons); never trusted for the result.
  const cancelAttempt = (handle, reason) => api(`/verification-attempts/${handle.attempt.attemptId}/cancel`, {method: 'POST', keepalive: true,
    ...(reason ? {headers: {'content-type': 'application/json'}, body: JSON.stringify({reason})} : {})}).catch(error => { if (error.status !== 409) throw error; });
  // The cancel request is recorded before the run stops, so the
  // verifier's end of the session settles the attempt as cancelled, not failed. The wait is bounded: an unreachable
  // API never keeps a run going, and after 2 s the run stops while the request finishes.
  const requestThenStop = async (handle, reason, stop) => {
    const request = cancelAttempt(handle, reason);
    await Promise.race([request.catch(() => {}), sleep(2000)]);
    try { await stop(); } finally { await request; }
  };
  const STOP_REASONS = new Set(['PROVIDER_HTTP_401', 'PROVIDER_HTTP_403', 'PROVIDER_HTTP_429', 'PROVIDER_RESPONSE_UNSUPPORTED', 'PROVIDER_SIGN_IN_REQUIRED',
    'CAPTURE_TIMEOUT', 'CAPTURE_TAB_CLOSED', 'ADMISSION_REFUSED', 'VERIFIER_BUSY', 'VERIFIER_UNREACHABLE', 'VERIFIER_VERSION_MISMATCH', 'VERIFIER_ORIGIN_REFUSED',
    'TICKET_EXPIRED', 'PROOF_TIMEOUT', 'OWNER_LEFT', 'CANCELLED']);
  const client = {
    // Call directly in the click handler, before login/bootstrap/attempt awaits.
    openPanel: () => message('bridge-open-panel'),
    closePanel: () => message('bridge-close-panel'),
    async capabilities() {
      const value = await message('bridge-ping');
      if (value.protocol !== protocol || value.engine !== 'tlsn' || value.mode !== 'Proxy' || value.chainId !== chainId || value.application !== application || value.wasmVersion !== '0.1.0-alpha.15' || value.claimable !== false || !Array.isArray(value.schemas)) throw Error('EXTENSION_VERSION_MISMATCH');
      const routing = assignedRouting(value) ? 'assigned' : 'pinned';
      // A pinned (pre-assignment) extension can only use the one verifier its build names.
      if (configuration && (routing === 'pinned' && (value.verifierOrigin !== configuration.verifierOrigin || value.verifierRevision !== configuration.verifierRevision)
        || !configuration.schemas.some(schema => value.schemas.some(candidate => sameSchema(candidate, schema))))) throw Error(routing === 'pinned' && configuration.attemptRouting?.includes?.('assigned') ? 'EXTENSION_UPDATE_REQUIRED' : 'EXTENSION_VERSION_MISMATCH');
      return {...value, routingMode: routing};
    },
    async start(recipient, schemaId = 'pines.fixture.httpbingo', {signal, onAttempt = () => {}} = {}) {
      if (typeof recipient !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(recipient) || recipient === '0x' + '0'.repeat(40)) throw Error('INVALID_RECIPIENT');
      recipient = recipient.toLowerCase();
      const capabilities = await client.capabilities();
      const schema = capabilities.schemas.find(schema => schema.schemaId === schemaId && (!configuration || configuration.schemas.some(enabled => sameSchema(enabled, schema))));
      if (!schema) throw Error('SCHEMA_UNAVAILABLE');
      if (signal?.aborted) throw Error('CANCELLED');
      if (capabilities.ownerConnection) connectOwner();
      let preparation;
      if (capabilities.prepareProvider) {
        preparation = await message('prepare-provider', {recipient, schema});
        try {
          while (!preparation.preparationReady) {
            if (signal?.aborted) throw Error('CANCELLED');
            if (['cancelled', 'failed'].includes(preparation.phase)) throw Error(preparation.error ?? 'CANCELLED');
            await sleep(300);
            preparation = await message('preparation-status', {runId: preparation.runId, recipient});
          }
          if (signal?.aborted) throw Error('CANCELLED');
        } catch (error) {
          await message('cancel-verification', {runId: preparation.runId, recipient}).catch(() => {}); throw error;
        }
      }
      const routing = capabilities.routingMode;
      let attempt;
      try {
        attempt = await api('/verification-attempts', {method: 'POST', headers: {'content-type': 'application/json'},
          body: JSON.stringify(routing === 'assigned' ? {recipient, schema, routing} : {recipient, schema})});
      } catch (error) {
        if (!signal?.aborted && capabilities.admissionErrorScreen === true && admissionErrors.has(error.message)) {
          await message('verification-refused', {recipient, schema, error: error.message, retryAt: error.message === 'RATE_LIMITED' ? error.retryAt : null}).catch(() => {});
        }
        if (preparation) await message('cancel-verification', {runId: preparation.runId, recipient}).catch(() => {});
        throw error;
      }
      if (routing === 'assigned' && (typeof attempt.verifier?.instanceId !== 'string' || attempt.verifier.origin !== attempt.verifierOrigin || !revisionPattern.test(attempt.verifier.revision ?? ''))) throw Error('ATTEMPT_MISMATCH');
      const assignment = routing === 'assigned' ? {instanceId: attempt.verifier.instanceId, origin: attempt.verifier.origin, revision: attempt.verifier.revision} : undefined;
      let handle = {attempt: {...attempt, routing, ...(assignment ? {verifier: assignment} : {})}, recipient};
      try {
        onAttempt({recipient, attempt: {attemptId: attempt.attemptId, schema: attempt.schema, resultExpiresAt: attempt.resultExpiresAt}});
        if (signal?.aborted) throw Error('CANCELLED');
        const started = await message('verify-provider', {recipient, attempt, ...(preparation ? {preparationId: preparation.runId} : {})});
        if (!uuid.test(started.runId) || started.attemptId !== attempt.attemptId || started.recipient !== recipient || !sameSchema(started.schema, schema)) throw Error('ATTEMPT_MISMATCH');
        handle = {runId: started.runId, attempt: handle.attempt, recipient};
        if (signal?.aborted) { await client.cancel(handle).catch(() => {}); throw Error('CANCELLED'); }
        return handle;
      } catch (error) {
        // The run never started (or its start is unknown). A cancel request is safe either way: it frees the wallet
        // and lets the API revoke the unredeemed ticket; a proof that did start and completes is still accepted.
        await cancelAttempt(handle).catch(() => {});
        if (preparation) await message('cancel-verification', {runId: preparation.runId, recipient}).catch(() => {});
        throw error;
      }
    },
    extensionStatus: handle => handle.runId ? message('verification-status', {runId: handle.runId, recipient: handle.recipient}) : Promise.resolve(null),
    receiptStatus: async handle => checkStatus(handle, await api(`/verification-attempts/${handle.attempt.attemptId}`)),
    /** Explicit user cancellation: record the cancel request, then stop the extension run (a revealed run is spared). */
    async cancel(handle) {
      cancelled.add(handle.attempt.attemptId);
      await requestThenStop(handle, 'USER', async () => { if (handle.runId) await message('cancel-verification', {runId: handle.runId, recipient: handle.recipient}); });
    },
    async recipientChanged(handle, recipient) {
      const stop = async () => { if (handle.runId) await message('recipient-changed', {runId: handle.runId, recipient}); };
      if (recipient?.toLowerCase() === handle.recipient) return stop();
      cancelled.add(handle.attempt.attemptId);
      await requestThenStop(handle, 'RECIPIENT_CHANGED', stop);
    },
    /**
     * Waits for the API's authoritative result. Returns the verified status or throws its refusal. Throws
     * `RECEIPT_PENDING` (recoverable; nothing is cancelled) when the wait ends first, and `WALLET_UNAUTHORIZED` when the
     * wallet session must be renewed before the same attempt can be read again.
     */
    async waitForReceipt(handle, {signal, timeoutMs = 120_000, onProgress = () => {}} = {}) {
      const deadline = Math.min(now() + timeoutMs, handle.attempt.resultExpiresAt);
      const checkCancelled = async () => {
        if (signal?.aborted || cancelled.has(handle.attempt.attemptId)) { await client.cancel(handle).catch(() => {}); throw Error('CANCELLED'); }
      };
      const jitter = span => Math.floor(random() * span);
      let nextApiAt = now(), failures = 0, lastPhase, revealed = false, completedSeen = false, state;
      while (now() < deadline) {
        await checkCancelled();
        if (now() >= nextApiAt) {
          try {
            state = await client.receiptStatus(handle);
            failures = 0; nextApiAt = now() + POLL_INTERVAL_MS + jitter(POLL_JITTER_MS);
          } catch (error) {
            if (error.message === 'RECEIPT_CONTEXT_MISMATCH' || error.message === 'WALLET_UNAUTHORIZED' || error.status === 403 || error.status === 404) throw error;
            if (!error.transient && !TRANSIENT.test(error.message)) throw error;
            failures++;
            nextApiAt = now() + Math.min(BACKOFF_MAX_MS, 1000 * 2 ** (failures - 1)) + jitter(POLL_JITTER_MS);
          }
          await checkCancelled();
          if (state?.status === 'verified' && uuid.test(state.receiptId)) {
            if (handle.runId) await message('receipt-verified', {runId: handle.runId, recipient: handle.recipient}).catch(() => {});
            await checkCancelled();
            return state;
          }
          if (state && ['failed', 'cancelled', 'expired'].includes(state.status)) {
            const error = typeof state.error === 'string' && /^[A-Z_]{1,64}$/.test(state.error) ? state.error : state.status.toUpperCase();
            const linkedWallet = linkedWalletOf(state);
            if (handle.runId) await message('receipt-rejected', {runId: handle.runId, recipient: handle.recipient, error, linkedWallet: linkedWallet ?? null}).catch(() => {});
            if (handle.runId) await message('cancel-verification', {runId: handle.runId, recipient: handle.recipient}).catch(() => {});
            throw Object.assign(Error(error), linkedWallet ? {linkedWallet} : {});
          }
        }
        // The extension's state is a UX hint (never proof or release authority). Its reply is paced by the extension
        // worker, so a hidden Pines tab does not depend on throttled page timers.
        const extension = await client.extensionStatus(handle).catch(() => null);
        await checkCancelled();
        if (extension?.phase === 'proving' || extension?.phase === 'completed') revealed = true;
        if (extension?.phase === 'completed' && !completedSeen) { completedSeen = true; nextApiAt = now(); }
        if (extension?.phase === 'failed' || extension?.phase === 'cancelled') {
          const error = extension.phase === 'cancelled' ? 'CANCELLED'
            : typeof extension.error === 'string' && /^[A-Z_]{1,64}$/.test(extension.error) ? extension.error : 'PROOF_FAILED';
          if (!revealed && (PRE_PROOF_PHASES.has(lastPhase) || PRE_PROOF_ERRORS.has(error))) {
            // Stopped before its reveal: no result can follow. Record the cancel request and report the stop.
            await message('cancel-verification', {runId: handle.runId, recipient: handle.recipient}).catch(() => {});
            await cancelAttempt(handle, STOP_REASONS.has(error) ? error : 'EXTENSION_STOPPED').catch(() => {});
            throw Error(error);
          }
          // After a reveal the verifier may already hold a durable result: keep reading the API, never cancel.
          handle = {...handle, runId: undefined};
        }
        if (extension?.phase) lastPhase = extension.phase;
        onProgress({status: state?.status ?? 'pending', phase: extension?.phase ?? 'reconnecting'});
        if (!(extension?.pollDelayMs > 0)) await sleep(Math.max(0, Math.min(IDLE_WAIT_MS, nextApiAt - now(), deadline - now())));
      }
      throw Error('RECEIPT_PENDING');
    },
  };
  return client;
}
