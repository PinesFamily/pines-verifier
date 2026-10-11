import {ProveManager} from './prove-manager.js';
import config from './config.js';
import {metadataPersistenceFailureCode} from './qualification-metadata-channel.mjs';
const manager = new ProveManager(state => { void chrome.runtime.sendMessage({target: 'background', type: 'worker-state', state}).catch(() => {}); }, {
  teeProviders: config.tee?.providers,
  replayMetadata:config.qualificationResponseMetadata?async record=>{
    let result;
    try{result=await chrome.runtime.sendMessage({target:'background',type:'replay-metadata',record});}catch{throw Error('REPLAY_METADATA_BRIDGE_FAILED');}
    if(result?.ok!==true)throw Error(metadataPersistenceFailureCode(result?.error)??'REPLAY_METADATA_BRIDGE_REFUSED');
  }:null,
});
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
