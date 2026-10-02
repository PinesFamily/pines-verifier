import {loadRegistry} from '../verification-schemas/src/index.ts';
import {captureProvider} from './session.mjs';

let entry;
const ready = loadRegistry().then(registry => { entry = registry.list().find(entry => entry.reference.schemaId === 'pines.chatgpt.plan'); });
let session, starting = false;
const status = () => ({schema: entry.reference, capture: session?.status() ?? null, claimable: false});

async function start() {
  if (starting || ['waiting', 'captured'].includes(session?.status().phase)) throw Error('CAPTURE_BUSY');
  starting = true;
  try {
    const tabs = await chrome.tabs.query({url: entry.schema.request.origin + '/*'});
    if (tabs.length !== 1 || tabs[0].incognito) throw Error('OPEN_ONE_PROVIDER_TAB');
    const tab = tabs[0];
    const frame = await chrome.webNavigation.getFrame({tabId: tab.id, frameId: 0});
    session = await captureProvider({browser: chrome, schema: entry.schema,
      owner: {runId: crypto.randomUUID(), tabId: tab.id, windowId: tab.windowId, documentId: frame?.documentId},
      deadline: Date.now() + 25_000});
    // Arm the existing document. The user refreshes usage through the provider's
    // own UI; rewriting a legacy settings hash can navigate to a new document.
    return status();
  } finally { starting = false; }
}

// There is no external message listener, content script or website bridge. Only
// the packaged diagnostic page can start/cancel and read bounded metadata.
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (sender.id !== chrome.runtime.id || sender.url !== chrome.runtime.getURL('probe.html')
    || !message || Object.keys(message).length !== 1 || !['start', 'status', 'cancel'].includes(message.type)) return;
  (async () => {
    await ready;
    if (message.type === 'start') return start();
    if (message.type === 'cancel') session?.cancel();
    const value = status();
    // The capture-only probe validates replay construction, then immediately
    // releases the private request. No replay/proof/receipt is sent by this tool.
    if (value.capture?.phase === 'captured') await session.take(value.capture.runId);
    return status();
  })().then(value => reply({ok: true, ...value}), error => reply({ok: false, error: ['CAPTURE_BUSY', 'OPEN_ONE_PROVIDER_TAB'].includes(error.message) ? error.message : 'CAPTURE_UNAVAILABLE'}));
  return true;
});
