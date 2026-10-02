import {ProveManager} from './prove-manager.js';
const manager = new ProveManager(state => { void chrome.runtime.sendMessage({target: 'background', type: 'worker-state', state}).catch(() => {}); });
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message?.target !== 'offscreen' || sender.id !== chrome.runtime.id || sender.url !== chrome.runtime.getURL('background.js')) return;
  try {
    let state;
    if (message.type === 'start') state = manager.start(message);
    else if (message.type === 'replay') state = manager.replay(message.runId, message.replay);
    else if (message.type === 'status') state = manager.status(message.preview === true);
    else if (message.type === 'approve') state = manager.approve(message.runId);
    else if (message.type === 'cancel') state = manager.cancel(message.runId);
    else return;
    reply({ok: true, state});
  } catch { reply({ok: false, error: 'WORKER_UNAVAILABLE'}); }
});
