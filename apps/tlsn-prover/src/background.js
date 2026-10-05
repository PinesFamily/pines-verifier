import config from './config.js';
import {providerPermission, checkProviderPermission} from './provider-permission.js';
import {ProviderCapture} from './provider-capture.js';
import {ProviderFlow} from './provider-flow.js';
import {loadRegistry} from './schemas/src/index.js';
import {PROTOCOL, UUID, assignmentOf, buildEntries, check, entryOf, object, ownerOf, owns, recipientOf, validateAttempt, publicState, terminal} from './policy.js';
import {linkedWalletOf} from './binding-error.mjs';
import {admissionErrors, retryTime} from './retry.js';
import {OwnerConnections} from './owner-connection.js';
import {localFailureCode} from './failure-code.js';
const guided = config.chatgptClaims || config.chatgptIdentity;

// Every schema this build carries, digest-pinned by the packaged registry. A run
// uses the one its admitted attempt names; each provider keeps its own flow.
const registered = loadRegistry().then(registry => buildEntries(registry, config));
let job;
let starting = false;
let creating;
let closing;
// Closing the document terminates all WASM/Rayon descendants, not only its immediate worker.
async function closeOffscreen() {
  if (closing) return closing;
  closing = (async () => { if (creating) await creating; if ((await contexts()).length) await chrome.offscreen.closeDocument(); })();
  try { await closing; } finally { closing = undefined; }
}
let writes = Promise.resolve();
const navigation = new Map();
const panelIntents = new Map();
const owners = new OwnerConnections(chrome, config.origins, owner => {
  void ready.then(() => {if (job && owns(job.owner, owner)) return cancel('cancelled', 'OWNER_LEFT', {spareRevealed: true});});
});
const capture = new ProviderCapture({browser: chrome, current: () => job, ownerReady: owner => owners.live(owner),
  deliver: async (runId, replay) => { const result = await offscreen({type: 'replay', runId, replay}); check(result?.ok, 'WORKER_UNAVAILABLE'); },
  fail: code => cancel('failed', code),
  owner: async (current, owner) => { if (job === current && !terminal(current.phase)) { if (owner) job.providerOwner = owner; else delete job.providerOwner; await persist(); } },
});
const ready = chrome.storage.session.get('job').then(async saved => {
  job = saved.job ?? null;
  if (job?.automaticCapture && !terminal(job.phase) && job.phase !== 'proving') {job.phase = 'failed'; job.error = 'WORKER_RESTARTED'; await closeOffscreen(); await persist();}
});
const flow = new ProviderFlow({browser: chrome, current: () => job, capture, persist, ownerReady: owner => owners.live(owner), returned: async current => {
  check(job === current && terminal(current.phase), 'STALE_RUN');
  capture.cancel();
  // Keep the terminal result for the owner page's in-flight status poll, but
  // dismiss its panel view durably. A new verification replaces the whole job.
  current.panelDismissed = true;
  await persist();
}});
function persist() { const snapshot = structuredClone(job); writes = writes.catch(() => {}).then(() => chrome.storage.session.set({job: snapshot})); return writes; }
function updatePhase(phase, error = null) {
  if (job.phase !== phase) job.phaseStartedAt = Date.now();
  job.phase = phase; job.error = error;
}
// Pace active receipt polling here: the original Pines tab is usually hidden
// behind ChatGPT, where page timers may be heavily throttled. Coalesce concurrent
// status requests into one short wait; no perpetual worker timer is needed.
let statusWait;
function waitForStatusPoll() {
  return statusWait ??= new Promise(resolve => setTimeout(resolve, 500)).finally(() => { statusWait = undefined; });
}
function offscreen(message) { return chrome.runtime.sendMessage({...message, target: 'offscreen'}); }
async function contexts() { return chrome.runtime.getContexts({contextTypes: ['OFFSCREEN_DOCUMENT'], documentUrls: [chrome.runtime.getURL('offscreen.html')]}); }
// Adapted from the pinned fork's creation mutex: reuse one offscreen document,
// with a fresh dedicated worker for each ProveManager run.
async function ensureOffscreen() {
  if (closing) await closing;
  if (creating) return creating;
  creating = (async () => { if (!(await contexts()).length) await chrome.offscreen.createDocument({url: 'offscreen.html', reasons: ['WORKERS'], justification: 'Run the Pines TLSNotary proof in a dedicated WASM worker.'}); })();
  try { await creating; } finally { creating = undefined; }
}
// `spareRevealed`: the page stopped (its Cancel, a reload, navigation, a wallet change). After Share and verify the
// user has consented and the verifier may already hold the result, so a revealed run is left to finish; only the
// panel's own Cancel, a deadline or a failure aborts it.
async function cancel(phase = 'cancelled', error = null, {spareRevealed = false} = {}) {
  if (!job) return;
  // A finished proof may already have a durable API receipt. Report that the
  // page stopped waiting without relabeling that proof as cancelled or verified.
  if (job.phase === 'completed' && !job.receiptVerified) { job.receiptWaitStopped = true; await persist(); return; }
  if (spareRevealed && job.phase === 'proving') { job.receiptWaitStopped = true; await persist(); return; }
  if (terminal(job.phase)) return;
  capture.cancel();
  const runId = job.runId; updatePhase(phase, error); await persist();
  if ((await contexts()).length) await offscreen({type: 'cancel', runId}).catch(() => {});
  await closeOffscreen();
}
async function reconcile(preview = false) {
  const current = job;
  if (!current || terminal(current.phase)) return null;
  if (current.deadline <= Date.now()) { await cancel('failed', 'PROOF_TIMEOUT'); return null; }
  if (starting) return null;
  if (!await permissionReady(current) && terminal(current.phase)) return null;
  if (current.preparing) {await persist(); return null;}
  const available = await contexts();
  if (job !== current || terminal(current.phase) || starting) return null;
  if (!available.length) { await cancel('failed', 'WORKER_RESTARTED'); return null; }
  const result = await offscreen({type: 'status', preview}).catch(() => null);
  if (job !== current || terminal(current.phase)) return null;
  if (!result?.ok || result.state?.runId !== current.runId) { await cancel('failed', 'WORKER_RESTARTED'); return null; }
  updatePhase(result.state.phase, result.state.error);
  if (terminal(job.phase)) { capture.cancel(); await closeOffscreen(); }
  await persist();
  advance(current);
  return result.state.preview ?? null;
}
// The worker can wait for capture while the panel asks for access. Public state
// exposes that wait; only this controller can permit opening a provider tab.
async function permissionReady(current) {
  try {
    const allowed = await checkProviderPermission(chrome, current);
    return job === current && !terminal(current.phase) && allowed;
  } catch {
    if (job === current && !terminal(current.phase)) await cancel('failed', 'PERMISSION_REVOKED');
    return false;
  }
}
function advance(current) {
  if (job !== current || current.preparing || !current.automaticCapture || terminal(current.phase)) return;
  if (current.phase === 'awaiting-capture') {
    void registered.then(async entries => {
      if (!await permissionReady(current)) { if (job === current) await persist(); return; }
      return flow.start(current, entryOf(entries, current.schema).schema);
    }).catch(error => {
      if (job === current) void cancel('failed', safeCode(error));
    });
  }
}
function requireOwner(owner, message) {
  check(job && owns(job.owner, owner) && message.runId === job.runId, 'STALE_RUN');
}
async function start(message, owner, epoch) {
  await ready;
  const prepared = job?.preparing && job.runId === message.preparationId && owns(job.owner, owner) ? job : null;
  check(!starting && (!job || terminal(job.phase) || prepared), 'BUSY');
  if (guided) {
    check(prepared, 'EXTENSION_UPDATE_REQUIRED');
    check(!terminal(prepared.phase) && prepared.deadline > Date.now(), 'CANCELLED');
    check(prepared.recipient === recipientOf(message.recipient), 'RECIPIENT_CHANGED');
    check(await permissionReady(prepared), 'PERMISSION_REVOKED');
  }
  check(await owners.live(owner), 'OWNER_LEFT');
  check(navigation.get(owner.tabId) === epoch, 'STALE_DOCUMENT');
  check(!prepared || job === prepared && !terminal(prepared.phase), 'CANCELLED');
  check(!starting && (!job || terminal(job.phase) || job === prepared), 'BUSY');
  starting = true;
  let current;
  try {
    const recipient = recipientOf(message.recipient);
    const entry = entryOf(await registered, message.attempt?.schema);
    if (prepared) check(prepared.schema.digest === entry.reference.digest, 'SCHEMA_UNAVAILABLE');
    const assignment = assignmentOf(message.attempt, validateAttempt(message.attempt, recipient, entry.reference, entry.schema, config));
    if (guided) {
      const intent = panelIntents.get(owner.documentId);
      panelIntents.delete(owner.documentId);
      check(intent && owns(intent.owner, owner) && intent.expiresAt > Date.now(), 'PANEL_GESTURE_REQUIRED');
      check(await intent.opened, 'PANEL_GESTURE_REQUIRED');
    }
    check(navigation.get(owner.tabId) === epoch, 'STALE_DOCUMENT');
    check(!prepared || job === prepared && !terminal(prepared.phase) && prepared.deadline > Date.now(), 'CANCELLED');
    current = {runId: crypto.randomUUID(), owner, recipient, attemptId: message.attempt.attemptId, schema: entry.reference, verifier: assignment, captureExpiresAt: message.attempt.expiresAt, phase: 'initializing', startedAt: Date.now(), automaticCapture: guided === true, permissionGranted: prepared?.permissionGranted === true, deadline: Math.min(Date.now() + entry.schema.limits.sessionTimeoutMs, message.attempt.resultExpiresAt), error: null};
    job = current;
    current.permissionPending = Boolean(providerPermission(current.schema.schemaId));
    const allowed = await permissionReady(current);
    check(!terminal(current.phase) && (!guided || allowed), 'PERMISSION_REVOKED');
    await persist();
    // The assigned instance must run the revision its ticket names and speak this build's protocol and WASM version.
    // A compatible server upgrade needs no extension release; a protocol or TLSN version change still does.
    if (!config.tee) {
    const info = await fetch(assignment.origin + '/info', {credentials: 'omit', redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(8000)}).then(async response => { check(response.ok && Number(response.headers.get('content-length') ?? 0) < 16384, 'VERIFIER_UNAVAILABLE'); const text = await response.text(); check(text.length < 16384, 'VERIFIER_UNAVAILABLE'); return JSON.parse(text); }, error => { throw Error(error?.message === 'VERIFIER_UNAVAILABLE' ? 'VERIFIER_UNAVAILABLE' : 'VERIFIER_UNREACHABLE'); });
    check(info.git_hash === assignment.revision && info.tlsn_version === config.wasmVersion && info.admission === 'pines-tlsn-ticket-v1' && info.receipt_protocol === 'pines-tlsn-event-v1' && info.supported_modes?.length === 1 && info.supported_modes[0] === 'Proxy' && info.claims_enabled === false
      && (config.testBuild || !Array.isArray(info.build_features) || info.build_features.length === 0)
      && (!assignment.instanceId || info.instance_id === assignment.instanceId), 'VERIFIER_VERSION_MISMATCH');
    }
    check(job === current && !terminal(current.phase), 'CANCELLED');
    await ensureOffscreen();
    check(job === current && !terminal(current.phase), 'CANCELLED');
    const result = await offscreen({type: 'start', runId: current.runId, attempt: message.attempt, recipient, deadline: current.deadline, verifierOrigin: assignment.origin, tee: Boolean(config.tee)});
    check(result?.ok, 'WORKER_UNAVAILABLE');
    return {ok: true, ...publicState(current)};
  } catch (error) {
    if (current && job === current && !terminal(current.phase)) await cancel('failed', safeCode(error));
    throw error;
  } finally { starting = false; }
}
const errors = new Set(['EXTENSION_UPDATE_REQUIRED', 'CAPTURE_NAVIGATED', 'CAPTURE_PERMISSION_LOST', 'INVALID_REQUEST', 'INVALID_RECIPIENT', 'ATTEMPT_MISMATCH', 'INVALID_TICKET', 'TICKET_EXPIRED', 'SCHEMA_UNAVAILABLE', 'BUSY', 'STALE_RUN', 'STALE_DOCUMENT', 'CANCELLED', 'VERIFIER_UNAVAILABLE', 'VERIFIER_UNREACHABLE', 'VERIFIER_ORIGIN_REFUSED', 'VERIFIER_VERSION_MISMATCH', 'WORKER_UNAVAILABLE', 'RECIPIENT_CHANGED', 'CAPTURE_BUSY', 'OPEN_ONE_PROVIDER_TAB', 'CAPTURE_UNAVAILABLE', 'CAPTURE_TIMEOUT', 'CAPTURE_OWNER_CHANGED', 'CAPTURE_CANCELLED', 'CAPTURE_TAB_CLOSED', 'PROVIDER_OPEN_FAILED', 'PROVIDER_SIGN_IN_REQUIRED', 'PANEL_GESTURE_REQUIRED', 'RECEIPT_PENDING', 'OWNER_LEFT', 'PERMISSION_REVOKED', 'PROVIDER_PERMISSION_DENIED']);
function safeCode(error) { return errors.has(error?.message) ? error.message : 'EXTENSION_UNAVAILABLE'; }

chrome.runtime.onMessageExternal.addListener((message, sender, reply) => {
  let owner;
  try {
    owner = ownerOf(sender, config.origins);
    check(message?.protocol === PROTOCOL && JSON.stringify(message).length < 16384);
    const simple = ['bridge-ping', 'bridge-open-panel', 'bridge-close-panel'].includes(message.type);
    object(message, simple ? ['protocol', 'type'] : message.type === 'verification-refused' ? ['protocol', 'type', 'recipient', 'schema', 'error', 'retryAt'] : message.type === 'prepare-provider' ? ['protocol', 'type', 'recipient', 'schema'] : message.type === 'verify-provider' ? ['protocol', 'type', 'recipient', 'attempt', ...(Object.hasOwn(message, 'preparationId') ? ['preparationId'] : [])] : message.type === 'receipt-rejected' ? ['protocol', 'type', 'runId', 'recipient', 'error', 'linkedWallet'] : ['protocol', 'type', 'runId', 'recipient']);
    check(['bridge-ping', 'bridge-open-panel', 'bridge-close-panel', 'verification-refused', 'prepare-provider', 'preparation-status', 'verify-provider', 'verification-status', 'cancel-verification', 'recipient-changed', 'receipt-verified', 'receipt-rejected'].includes(message.type));
  } catch { return; }
  // Keep this as the first async browser API on the gesture path. Report refusal;
  // the page can ask for a fresh Verify click.
  if (message.type === 'bridge-open-panel') {
    const opened = chrome.sidePanel.open({windowId: owner.windowId}).then(() => true, () => false);
    if (panelIntents.size >= 128) panelIntents.delete(panelIntents.keys().next().value);
    panelIntents.set(owner.documentId, {owner, expiresAt: Date.now() + 120_000, opened});
    opened.then(ok => reply(ok ? {ok: true, opened: true} : {ok: false, opened: false, error: 'PANEL_GESTURE_REQUIRED'}));
    return true;
  }
  if (!navigation.has(owner.tabId)) {
    if (navigation.size >= 128) navigation.delete(navigation.keys().next().value);
    navigation.set(owner.tabId, 0);
  }
  const epoch = navigation.get(owner.tabId);
  (async () => {
    if (message.type === 'bridge-ping') {
      const entries = await registered;
      return {ok: true, admissionErrorScreen: true, prepareProvider: guided, ownerConnection: true, protocol: PROTOCOL, engine: 'tlsn', mode: 'Proxy', extensionVersion: chrome.runtime.getManifest().version, wasmVersion: config.wasmVersion, verifierOrigin: config.verifierOrigin, verifierRevision: config.verifierRevision, routing: config.routing, application: config.application, chainId: config.chainId, schemas: entries.map(entry => entry.reference), claimable: false, ...(config.tee ? {tee: config.tee.capability} : {})};
    }
    if (message.type === 'bridge-close-panel') {
      await ready;
      const intent = panelIntents.get(owner.documentId);
      check(intent && owns(intent.owner, owner) && intent.expiresAt > Date.now(), 'PANEL_GESTURE_REQUIRED');
      check(await intent.opened, 'PANEL_GESTURE_REQUIRED');
      check(!job || job.owner.windowId !== owner.windowId || terminal(job.phase), 'BUSY');
      panelIntents.delete(owner.documentId);
      await chrome.sidePanel.close({windowId: owner.windowId});
      return {ok: true, closed: true};
    }
    if (message.type === 'prepare-provider') {
      await ready;
      check(!starting && (!job || terminal(job.phase)), 'BUSY');
      const intent = panelIntents.get(owner.documentId);
      check(intent && owns(intent.owner, owner) && intent.expiresAt > Date.now() && await intent.opened, 'PANEL_GESTURE_REQUIRED');
      const entry = entryOf(await registered, message.schema), recipient = recipientOf(message.recipient);
      check(await owners.live(owner), 'OWNER_LEFT');
      check(!starting && (!job || terminal(job.phase)) && navigation.get(owner.tabId) === epoch, 'STALE_RUN');
      const preparation = job = {runId: crypto.randomUUID(), owner, recipient, schema: entry.reference, phase: 'awaiting-capture',
        preparing: true, startedAt: Date.now(), deadline: intent.expiresAt, automaticCapture: true};
      await permissionReady(preparation); check(job === preparation, 'STALE_RUN'); await persist();
      check(job === preparation, 'STALE_RUN'); return {ok: true, ...publicState(preparation)};
    }
    if (message.type === 'verification-refused') {
      await ready;
      const intent = panelIntents.get(owner.documentId);
      check(intent && owns(intent.owner, owner) && intent.expiresAt > Date.now() && await intent.opened, 'PANEL_GESTURE_REQUIRED');
      const entry = entryOf(await registered, message.schema);
      const recipient = recipientOf(message.recipient);
      check(admissionErrors.has(message.error), 'INVALID_REQUEST');
      check(!starting && (!job || terminal(job.phase) || job.preparing && owns(job.owner, owner)), 'BUSY');
      check(navigation.get(owner.tabId) === epoch && panelIntents.get(owner.documentId) === intent, 'STALE_DOCUMENT');
      // No ticket, worker, capture or provider tab exists for a refused admission.
      panelIntents.delete(owner.documentId);
      job = {runId: crypto.randomUUID(), owner, recipient, schema: entry.reference, phase: 'failed', error: message.error,
        retryAt: message.error === 'RATE_LIMITED' ? retryTime(message.retryAt) : null, startedAt: Date.now()};
      await persist();
      return {ok: true};
    }
    if (message.type === 'verify-provider') return start(message, owner, epoch);
    await ready; requireOwner(owner, message);
    const owned = job;
    if (message.type === 'recipient-changed') {
      if (message.recipient === null || recipientOf(message.recipient) !== job.recipient) await cancel('cancelled', 'RECIPIENT_CHANGED', {spareRevealed: true});
      check(job === owned, 'STALE_RUN');
      return {ok: true, ...publicState(owned)};
    }
    if (recipientOf(message.recipient) !== job.recipient) { await cancel('cancelled', 'RECIPIENT_CHANGED', {spareRevealed: true}); throw Error('RECIPIENT_CHANGED'); }
    if (message.type === 'preparation-status') {
      check(owned.preparing, 'STALE_RUN'); await reconcile(); check(job === owned, 'STALE_RUN');
      return {ok: true, ...publicState(owned)};
    }
    if (message.type === 'verification-status') {
      await waitForStatusPoll();
      requireOwner(owner, message);
      check(job === owned && navigation.get(owner.tabId) === epoch, 'STALE_DOCUMENT');
    }
    if (message.type === 'receipt-verified') {
      check(!['failed', 'cancelled'].includes(job.phase), 'STALE_RUN');
      // Owner-page UI acknowledgment after authenticated API polling. This is
      // never proof evidence; the API independently revalidates every claim.
      // It may arrive before the last worker-state message. Continue still
      // requires the worker's completed phase as well as this acknowledgment.
      job.receiptVerified = true; job.receiptVerifiedAt ??= Date.now(); delete job.receiptWaitStopped; await persist();
    } else if (message.type === 'receipt-rejected') {
      check(!job.receiptVerified && typeof message.error === 'string' && /^[A-Z_]{1,64}$/.test(message.error), 'STALE_RUN');
      check(message.linkedWallet === null || linkedWalletOf(message), 'INVALID_REQUEST');
      // Display-only acknowledgment from the same authenticated polling page.
      // This never changes the API's binding, quota, or claim decision.
      const local = job.phase === 'failed' ? localFailureCode(job.error) : null;
      updatePhase('failed', message.error === 'ENCLAVE_TERMINATED' && local ? local : message.error);
      job.receiptRejected = true; job.receiptError = message.error;
      job.linkedWallet = linkedWalletOf(message); capture.cancel();
      const retiring = closeOffscreen(); await persist(); await retiring;
    } else if (message.type === 'cancel-verification') await cancel('cancelled', null, {spareRevealed: true}); else await reconcile();
    check(job === owned, 'STALE_RUN');
    return {ok: true, ...publicState(owned), ...(message.type === 'verification-status' ? {pollDelayMs: 500} : {})};
  })().then(reply, error => reply({ok: false, error: safeCode(error)}));
  return true;
});

chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message?.target !== 'background' || sender.id !== chrome.runtime.id) return;
  const panel = sender.url === chrome.runtime.getURL('panel.html');
  const worker = sender.url === chrome.runtime.getURL('offscreen.html');
  if (!panel && !worker) return;
  (async () => {
    await ready;
    if (worker && message.type === 'worker-state') {
      if (job && message.state?.runId === job.runId) {
        if (!terminal(job.phase)) { updatePhase(message.state.phase, message.state.error); if (terminal(job.phase)) { capture.cancel(); await closeOffscreen(); } await persist(); advance(job); }
        // A failure already queued by this run's owned worker may arrive after
        // the API's generic terminal. Enrich its diagnostic only: never reopen a
        // run, accept a receipt, or replace a specific authoritative refusal.
        else if (job.phase === 'failed' && job.receiptRejected && job.receiptError === 'ENCLAVE_TERMINATED' && job.error === 'ENCLAVE_TERMINATED'
          && message.state.phase === 'failed' && localFailureCode(message.state.error)) {
          job.error = localFailureCode(message.state.error); await persist();
        }
      }
      return {ok: true};
    }
    if (!panel) throw Error('INVALID_REQUEST');
    if (!job || job.owner.windowId !== message.windowId) return {ok: true, state: null};
    const owned = job;
    if (message.type === 'panel-status') {
      if (owned.panelDismissed) return {ok: true, state: null};
      const preview = await reconcile(true);
      check(job === owned, 'STALE_RUN');
      if (owned.panelDismissed) return {ok: true, state: null};
      return {ok: true, state: {...publicState(owned), origin: owned.owner.origin, deadline: owned.deadline, startedAt: owned.startedAt, phaseStartedAt: owned.phaseStartedAt, receiptVerified: owned.receiptVerified === true, receiptVerifiedAt: owned.receiptVerifiedAt, receiptRejected: owned.receiptRejected === true, linkedWallet: owned.linkedWallet, receiptWaitStopped: owned.receiptWaitStopped === true, automaticCapture: owned.automaticCapture === true, providerStarted: Number.isInteger(owned.ownedProviderTabId), providerOpening: owned.providerOpening === true, captureActive: Boolean(capture.active(owned.runId)), ...(preview ? {preview} : {})}};
    }
    check(message.runId === job.runId && UUID.test(message.runId), 'STALE_RUN');
    check(!owned.panelDismissed, 'STALE_RUN');
    if (message.type === 'panel-permission') {
      // Polling may already have observed a grant while Chrome resolved the prompt.
      if (message.granted === true && owned.permissionGranted && !terminal(owned.phase)) return {ok: true};
      check(owned.phase === 'awaiting-capture' && owned.permissionPending, 'STALE_RUN');
      if (message.granted !== true) await cancel('cancelled', 'PROVIDER_PERMISSION_DENIED');
      else {
        // The panel's result is not authority: independently check Chrome's grant.
        check(await permissionReady(owned), 'PERMISSION_REVOKED');
        await persist(); advance(owned);
      }
    } else if (message.type === 'panel-capture') {
      check(await permissionReady(owned), 'PERMISSION_REVOKED');
      check(config.captureProvider, 'INVALID_REQUEST');
      // Manual diagnostics also capture in a fresh run-owned tab.
      const entry = entryOf(await registered, owned.schema);
      await capture.start(owned, entry.schema, {});
    } else if (message.type === 'panel-approve') {
      check(job.phase === 'awaiting-disclosure', 'STALE_RUN');
      check(await permissionReady(owned), 'PERMISSION_REVOKED');
      check(job === owned && owned.phase === 'awaiting-disclosure', 'STALE_RUN');
      if (owned.automaticCapture) await capture.validate(owned);
      check(job === owned && owned.phase === 'awaiting-disclosure', 'STALE_RUN');
      const result = await offscreen({type: 'approve', runId: owned.runId}); check(result?.ok, 'WORKER_UNAVAILABLE');
    } else if (message.type === 'panel-continue') await flow.continue(owned);
    else if (message.type === 'panel-recover') await flow.recover(owned);
    else if (message.type === 'panel-cancel') await cancel();
    else throw Error('INVALID_REQUEST');
    return {ok: true};
  })().then(reply, error => reply({ok: false, error: safeCode(error)}));
  return true;
});

function ownerGone(tabId, includeProvider = true) {
  if (navigation.has(tabId)) navigation.set(tabId, navigation.get(tabId) + 1);
  void ready.then(() => { if (job?.owner.tabId === tabId) return cancel('cancelled', 'OWNER_LEFT', {spareRevealed: true}); if (includeProvider && job?.providerOwner?.tabId === tabId) return cancel('cancelled', 'PROVIDER_LEFT'); }).catch(() => {});
}
chrome.tabs.onRemoved.addListener(tabId => ownerGone(tabId));
chrome.tabs.onUpdated.addListener((tabId, change) => { if (change.status === 'loading' || change.url) ownerGone(tabId, false); });
chrome.tabs.onDetached.addListener(tabId => ownerGone(tabId));
chrome.permissions.onRemoved.addListener(() => { void ready.then(() => cancel('failed', 'PERMISSION_REVOKED')).catch(() => {}); });
chrome.alarms.onAlarm.addListener(alarm => { if (alarm.name === 'tlsn-lifecycle') void ready.then(() => reconcile()).catch(() => {}); });
void chrome.alarms.create('tlsn-lifecycle', {periodInMinutes: 1});
void chrome.sidePanel.setPanelBehavior({openPanelOnActionClick: true});
