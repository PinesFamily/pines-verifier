import config from './config.js';
import {providerPermission} from './provider-permission.js';
import {loadRegistry} from './schemas/src/index.js';
import {progressOf, stepsFor, failureHelp, failureDiagnostic, providerOf, receiptProgressOf, reviewRowsOf} from './progress.js';
import {mountOrb} from './orb.js';
import {retryCopy} from './retry.js';
import {nativePlanLabel} from './tee-provider.mjs';

// The side panel (Pines Verifier): the welcome screen while no verification runs in this window, and a run as three
// task rows under the provider it checks, each opening onto what is happening inside it. It asks the background
// worker for the run every 500 ms and sends its buttons there; the worker owns every decision.
const node = id => document.getElementById(id);
const panel = document.querySelector('.panel');
// The review, held here: it moves into the second step whenever the steps are drawn again for another provider.
const disclosure = node('disclosure');
const guided = config.chatgptClaims || config.chatgptIdentity;
let runId;
let actionError;
let busy = false;
const windowId = (await chrome.windows.getCurrent()).id;
const registry = (await loadRegistry()).list();
const entries = config.tee ? config.tee.providers : config.schemas.map(({schemaId, version}) => registry.find(entry => entry.schema.schemaId === schemaId && entry.schema.version === version));

const view = name => { panel.dataset.view = name; };
const shortWallet = address => typeof address === 'string' && address.length > 12 ? `${address.slice(0, 6)}…${address.slice(-4)}` : address ?? '';
const clock = ms => { const s = Math.max(0, Math.ceil(ms / 1000)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`; };
const icons = {
  check: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="m3.8 8.3 2.7 2.7 5.7-6"/></svg>',
  alert: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 4.2v4.6"/><circle cx="8" cy="11.6" r=".4"/></svg>',
  lock: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="10.5" width="14" height="9.5" rx="2.5"/><path d="M8.5 10.5V8a3.5 3.5 0 0 1 7 0v2.5"/></svg>',
  chevron: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>',
};

// The copy follows the running job's schema; before any run, the build's first.
let shown, provider, host, connecting;
// Rows the reader opened or closed by hand, until the run moves to its next step.
const openBy = new Map();
let openFor;
function show(schemaId) {
  const entry = entries.find(entry => entry.schema.schemaId === schemaId) ?? entries[0];
  if (shown === entry.schema.schemaId) return;
  shown = entry.schema.schemaId;
  provider = providerOf(shown);
  node('provider-logo').src = `art/app-${shown.split('.')[1]}.png`;
  host = new URL(entry.schema.request.origin).hostname;
  node('progress').replaceChildren(...stepsFor(shown).map((label, index) => {
    const item = document.createElement('li');
    item.className = 'task';
    item.innerHTML = `<button type="button" class="task-head" aria-expanded="false"><span class="task-mark"></span><span class="task-title"></span><span class="task-meta"></span><span class="task-chevron">${icons.chevron}</span></button><div class="task-body"><div class="task-clip"><div class="task-content"><div class="task-rows"></div></div></div></div>`;
    item.querySelector('.task-title').textContent = label;
    item.querySelector('.task-head').addEventListener('click', () => {
      openBy.set(index, item.dataset.open !== 'true');
      void refresh();
    });
    return item;
  }));
  // The review is the second step's inside.
  node('progress').children[1].querySelector('.task-rows').replaceWith(disclosure);
  // Evaluated rows summarize the plan; the complete response is still disclosed (0.8.0 privacy scope).
  node('sharing').textContent = config.tee ? 'Your complete account response is encrypted and checked inside a protected AWS enclave, a trusted execution environment (TEE). Pines receives only your plan and a hashed account identifier. Login tokens and cookies stay hidden from both Pines and the TEE.' : `The full response from ${host} is shared, including any email, names or billing IDs it contains. Review it below. Your login token and cookies stay hidden.`;
  node('sharing').hidden = false;
  node('capture-start').textContent = `Open ${provider.name} and capture`;
}
show();

// A step's mark: a check behind, a spinning ring on the one running, a still ring ahead, a mark for a wait.
const marks = {
  done: () => `<span class="mark-done">${icons.check}</span>`,
  active: n => `<span class="mark-ring is-running"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10.5"/><circle class="arc" cx="12" cy="12" r="10.5"/></svg><b>${n}</b></span>`,
  waiting: n => `<span class="mark-ring"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10.5"/></svg><b>${n}</b></span>`,
  attention: () => `<span class="mark-alert">${icons.alert}</span>`,
};
// Inside a step: one line per thing it does, and where it is: a check once done, a small spinning ring while it
// runs (with its time, when it has one), a word for a wait, nothing ahead.
const statusOf = (status, extra) => status === 'done' ? `<span class="line-done">${icons.check}</span>`
  : status === 'running' ? `${extra ? '<span class="line-time"></span>' : ''}<span class="line-spin" aria-label="In progress"></span>`
  // A line that waits on the visitor ends in the site toasts' warning light, after its word where it has one, so the
  // step the button below finishes reads as the one to act on (Pines lab /lab/extension v4, 2026-10-03).
  : status === 'wait' ? '<span class="line-wait"></span><span class="line-lamp" role="img" aria-label="Waiting for you"></span>' : '';
function lines(item, list) {
  const rows = item.querySelector('.task-rows');
  const key = JSON.stringify(list);
  if (!rows || rows.dataset.key === key) return;
  rows.dataset.key = key;
  rows.replaceChildren(...list.map(([label, status = '', extra = '', tone]) => {
    const line = document.createElement('div');
    line.className = 'task-line-row';
    line.dataset.status = status || 'ahead';
    if (tone) line.dataset.tone = tone;
    line.innerHTML = `<span class="line-label"></span><span class="line-status">${statusOf(status, extra)}</span>`;
    line.querySelector('.line-label').textContent = label;
    const text = line.querySelector('.line-time, .line-wait');
    if (text) text.textContent = extra;
    return line;
  }));
}

// What Pines receives: the values the verifier judges (`reviewRowsOf`, from the worker's `preview.fields`), never this
// panel's own reading of the response, whose first record can be a plan the verifier skips. A long
// identifier is cut in the middle to fit its row; the whole of it is under the toggle.
const fit = text => text.length > 20 && !/\s/.test(text) ? `${text.slice(0, 8)}…${text.slice(-6)}` : text;
let previewShown, summaryShown = false, reviewFor;
// One row of the review: a name and its value; the hidden one with its lock, a settled one with a check.
function reviewRow(label, text, mark = '') {
  const row = document.createElement('div');
  row.className = mark === 'hidden' ? 'row is-hidden' : mark === 'ok' ? 'row is-ok' : 'row';
  row.innerHTML = `<dt></dt><dd><span></span>${mark === 'hidden' ? icons.lock : mark === 'ok' ? icons.check : ''}</dd>`;
  row.querySelector('dt').textContent = label;
  row.querySelector('dd span').textContent = text;
  node('shared-rows').append(row);
}
// A new run starts its review from nothing.
function forRun(id) {
  if (reviewFor === id) return;
  reviewFor = id; previewShown = undefined; summaryShown = false;
  node('shared-rows').replaceChildren(); node('preview').textContent = '';
}
// A done review step this panel never saw (the worker drops the preview once it is shared, and a panel opened
// afterwards has none): what is always true of it, without the full request and response.
function showSummary() {
  if (previewShown || summaryShown) return;
  summaryShown = true;
  node('shared-rows').replaceChildren();
  reviewRow('Plan details', 'Shared', 'ok');
  if (config.chatgptIdentity) reviewRow('Verified for', '30 days', 'ok');
  reviewRow('Login token and cookies', 'Hidden', 'hidden');
  disclosure.querySelector('details').hidden = true;
}
// Kept once shown: after Share and verify the worker drops the preview, and the done step still opens onto it.
function showPreview(preview) {
  if (!preview) return;
  if (config.tee) {
    const label = nativePlanLabel(entries.find(entry => entry.schema.schemaId === shown)?.reference, preview.plan);
    if (!preview.tee || !label) return;
    previewShown = preview.plan;
    node('shared-rows').replaceChildren();
    reviewRow('Plan to verify', label);
    reviewRow('Account details', 'TEE only', 'hidden');
    reviewRow('Login tokens and cookies', 'Hidden', 'hidden');
    disclosure.querySelector('details').hidden = true;
    node('preview').textContent = '';
    return;
  }
  const key = preview.request + preview.response;
  if (previewShown === key) return;
  previewShown = key;
  node('shared-rows').replaceChildren();
  disclosure.querySelector('details').hidden = false;
  const [head, ...rest] = preview.response.split(/\r?\n\r?\n/);
  const body = rest.join('\n\n');
  let data;
  try { data = JSON.parse(body); } catch { data = undefined; }
  const rows = reviewRowsOf(shown, preview.fields);
  for (const {label, value} of rows) reviewRow(label, fit(value), 'ok');
  if (!rows.length) reviewRow('Plan details', 'Shared', 'ok');
  if (config.chatgptIdentity) reviewRow('Verified for', '30 days', 'ok');
  reviewRow('Login token and cookies', 'Hidden', 'hidden');
  const pretty = data === undefined ? body : JSON.stringify(data, null, 2);
  node('preview').textContent = `${preview.request.trim()}\n\n${head.trim()}\n\n${pretty}`;
}

const send = (type, extra = {}) => chrome.runtime.sendMessage({target: 'background', type, windowId, ...extra});
async function refresh() {
  if (busy) return;
  try {
    const result = await send('panel-status'); const state = result?.state;
    if (!state) {
      view('start'); runId = undefined; actionError = undefined;
      forRun(undefined); openBy.clear(); openFor = undefined;
      disclosure.querySelector('details').open = false;
      node('status').textContent = ''; node('help').textContent = ''; node('meta').textContent = '';
      return;
    }
    if (runId !== state.runId) actionError = undefined;
    runId = state.runId; show(state.schema?.schemaId); forRun(state.runId);
    view('run');
    const progress = progressOf(state);
    const receipt = receiptProgressOf(state);
    const running = !progress.stopped && !progress.complete && !progress.recovery;
    const retry = retryCopy(state);
    node('heading').textContent = retry?.title ?? progress.title;
    node('description').textContent = retry?.description ?? progress.description;
    node('description').hidden = !(retry?.description ?? progress.description);
    const diagnostic = failureDiagnostic(state);
    node('failure-code').textContent = diagnostic;
    node('failure-code').hidden = !diagnostic;
    node('receipt-failure').textContent = state.phase === 'failed' && state.receiptRejected ? 'Pines did not save this verification.' : '';
    node('receipt-failure').hidden = !node('receipt-failure').textContent;
    node('retry-countdown').textContent = retry?.countdown ?? '';
    node('retry-countdown').hidden = !retry?.countdown;
    const badge = node('run-badge');
    badge.hidden = !(progress.complete || progress.stopped && state.error || progress.recovery);
    badge.dataset.tone = progress.complete ? 'done' : progress.recovery && !progress.stopped ? 'wait' : 'error';
    badge.innerHTML = progress.complete ? icons.check : icons.alert;

    showPreview(state.preview);
    if (progress.step > 1) showSummary();
    const steps = node('progress');
    steps.hidden = progress.stopped;
    if (openFor !== `${state.runId}:${progress.step}`) { openBy.clear(); openFor = `${state.runId}:${progress.step}`; }
    const started = state.providerStarted, phase = state.phase;
    const inside = [
      [
        phase === 'awaiting-permission' ? [`Allow access to ${host}`, 'wait'] : started ? [`Opened ${host}`, 'done'] : [`Opening ${host}`, 'running'],
        phase === 'requesting' || progress.step > 0 ? ['Signed in', 'done'] : started ? [`Waiting for ${provider.name}`, 'running'] : ['Sign in'],
        progress.step > 0 ? ['Read your plan', 'done'] : phase === 'requesting' ? ['Reading your plan', 'running'] : ['Read your plan'],
        ...(progress.step === 0 && running && phase !== 'awaiting-permission' ? [[`Keep the ${provider.name} tab open.`, '', '', 'hint']] : []),
      ],
      null,
      [
        phase === 'proving' ? ['Checking the proof', 'running'] : phase === 'completed' ? ['Proof checked', 'done'] : ['Check the proof'],
        progress.complete ? ['Saved with Pines', 'done'] : phase === 'completed' ? progress.recovery ? ['Saving with Pines', 'wait', 'not confirmed'] : ['Saving with Pines', 'running', `${receipt.seconds}s`] : ['Save with Pines'],
      ],
    ];
    [...steps.children].forEach((item, index) => {
      const done = index < progress.step;
      const active = index === progress.step && running;
      const attention = index === progress.step && progress.recovery && !progress.stopped;
      const mark = done ? 'done' : active ? 'active' : attention ? 'attention' : 'waiting';
      item.dataset.state = mark;
      if (item.dataset.mark !== mark) { item.dataset.mark = mark; item.querySelector('.task-mark').innerHTML = marks[mark](index + 1); }
      if (active) item.setAttribute('aria-current', 'step'); else item.removeAttribute('aria-current');
      if (inside[index]) lines(item, inside[index]);
      const opens = index === 1 ? Boolean(previewShown) || summaryShown : true;
      const open = opens && (openBy.get(index) ?? (active || attention));
      item.dataset.open = String(open);
      item.dataset.opens = String(opens);
      item.querySelector('.task-head').setAttribute('aria-expanded', String(open));
      // The review waits on the visitor too, for Share and verify: its time left wears the same light.
      item.dataset.waiting = String(index === 1 && active && phase === 'awaiting-disclosure');
      item.querySelector('.task-meta').textContent = index === 0 ? host
        : index === 1 ? active && state.deadline ? clock(state.deadline - Date.now()) : done ? 'Shared' : ''
        : '';
    });

    node('allow-access').hidden = phase !== 'awaiting-permission';
    node('allow-access').textContent = `Allow access to ${host}`;
    const reviewing = phase === 'awaiting-disclosure' && Boolean(state.preview);
    node('capture').hidden = state.automaticCapture || state.phase !== 'awaiting-capture';
    node('capture-start').disabled = state.captureActive;
    node('capture-help').textContent = state.captureActive ? `Refresh usage on the ${provider.name} page now. Keep that tab open.` : `Open a new ${provider.name} tab, then refresh usage within 30 seconds.`;
    node('privacy-note').hidden = !guided || progress.step !== 0 || !running;

    node('approve').hidden = !reviewing;
    node('continue').hidden = !progress.complete;
    node('recover').hidden = !(progress.recovery || progress.stopped);
    node('cancel').hidden = ['completed', 'cancelled', 'failed'].includes(state.phase);
    node('help').dataset.tone = '';
    node('help').textContent = actionError ?? (!guided && state.error && !progress.stopped ? failureHelp(state.error, state.linkedWallet, shown) : '');
    node('meta').textContent = `${new URL(state.origin).hostname} · ${shortWallet(state.recipient)}`;
    // Read aloud, and whole: a linked wallet by its full address, which the screen shortens.
    node('status').textContent = [retry?.title ?? progress.title, retry?.description ?? (progress.bound ? failureHelp(state.error, state.linkedWallet, shown) : progress.description || (running ? progress.detail : ''))].filter(Boolean).join('. ');
  } catch (error) {
    console.warn('[pines verifier]', error);
    if (panel.dataset.view === 'run') { node('help').dataset.tone = 'quiet'; node('help').textContent = 'Reconnecting to the extension…'; }
    else { panel.dataset.view = 'boot'; waitForWorker(); }
  }
}
node('allow-access').addEventListener('click', async () => {
  if (!runId || busy) return;
  const ownedRun = runId, origin = providerPermission(shown);
  if (!origin) return;
  actionError = undefined; busy = true; node('allow-access').disabled = true;
  try {
    // First asynchronous API, directly on the extension-page user gesture.
    const granted = await chrome.permissions.request({origins: [origin]});
    const result = await send('panel-permission', {runId: ownedRun, granted});
    if (!result?.ok) actionError = failureHelp(result?.error, undefined, shown);
  } catch { actionError = 'Chrome could not request access. Click Allow access again, or cancel.'; }
  finally { busy = false; node('allow-access').disabled = false; void refresh(); }
});
for (const [id, type] of [['capture-start', 'panel-capture'], ['approve', 'panel-approve'], ['cancel', 'panel-cancel'], ['continue', 'panel-continue'], ['recover', 'panel-recover']]) node(id).addEventListener('click', async () => {
  if (!runId || busy) return;
  actionError = undefined; busy = true; node(id).disabled = true;
  try { const result = await send(type, {runId}); if (!result?.ok) actionError = failureHelp(result?.error, undefined, shown); }
  catch { actionError = 'The extension couldn’t do that. Try again.'; }
  finally { busy = false; node(id).disabled = false; void refresh(); }
});
// No answer yet: a moment of only the name (a fast worker answers first, so nothing flashes), then the orb.
function waitForWorker() {
  if (panel.dataset.view !== 'boot') return;
  view('connecting');
  if (!connecting) connecting = mountOrb(node('connecting-orb'), {size: 64, state: 'composing', label: 'Connecting'});
}
setTimeout(waitForWorker, 300);
void refresh(); setInterval(refresh, 500);
