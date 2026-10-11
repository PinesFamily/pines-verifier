import {ownerOf, owns} from './policy.js';
// The trusted Pines document proves liveness over its browser-bound external port.
// No provider grants, tab URL scans or script injection are needed for the Pines tab.
export class OwnerConnections {
  #ports = new Map(); #lost;
  constructor(browser, origins, lost) {
    this.#lost = lost;
    browser.runtime.onConnectExternal.addListener(port => {
      let owner;
      try {if (port.name !== 'pines-tlsn-owner-v1') throw Error(); owner = ownerOf(port.sender, origins);}
      catch {port.disconnect(); return;}
      const previous = this.#ports.get(owner.documentId);
      if (!previous && this.#ports.size >= 128) {port.disconnect(); return;}
      const entry = {owner, port, pending: new Map()}; this.#ports.set(owner.documentId, entry); previous?.port.disconnect();
      port.onMessage.addListener(message => {if (typeof message?.nonce === 'string') entry.pending.get(message.nonce)?.receive(message);});
      port.onDisconnect.addListener(() => {
        if (this.#ports.get(owner.documentId) === entry) {this.#ports.delete(owner.documentId); this.#lost(owner);}
        for (const request of entry.pending.values()) request.finish(null);
      });
    });
  }
  async live(owner) {
    return await this.#request(owner, {}, message => Object.keys(message).length === 1 ? true : undefined) === true;
  }
  async cancelAttempt(owner, {runId, attemptId, recipient}, signal) {
    return this.#request(owner, {type: 'cancel-attempt', runId, attemptId, recipient}, message => {
      if (Object.keys(message).length !== 3 || message.type !== 'cancel-attempt-result'
        || !['recorded', 'completed', 'terminal', 'refused'].includes(message.outcome)) return undefined;
      return message.outcome;
    }, {signal, timeoutMs: 2000});
  }
  async #request(owner, payload, decode, {signal, timeoutMs = 3000} = {}) {
    const entry = this.#ports.get(owner?.documentId);
    if (signal?.aborted || !entry || entry.pending.size >= 16 || !owns(entry.owner, owner)) return null;
    const nonce = crypto.randomUUID();
    return new Promise(resolve => {
      let done = false;
      const abort = () => finish(null);
      const finish = result => {
        if (done) return; done = true;
        clearTimeout(timer); signal?.removeEventListener('abort', abort); entry.pending.delete(nonce);
        resolve(this.#ports.get(owner.documentId) === entry ? result : null);
      };
      const timer = setTimeout(() => finish(null), timeoutMs);
      entry.pending.set(nonce, {finish, receive(message) {const result = decode(message); if (result !== undefined) finish(result);}});
      signal?.addEventListener('abort', abort, {once: true});
      try {entry.port.postMessage({nonce, ...payload});} catch {finish(null);}
    });
  }
}
