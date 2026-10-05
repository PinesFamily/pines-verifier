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
      port.onMessage.addListener(message => {if (typeof message?.nonce === 'string') entry.pending.get(message.nonce)?.(true);});
      port.onDisconnect.addListener(() => {
        if (this.#ports.get(owner.documentId) === entry) {this.#ports.delete(owner.documentId); this.#lost(owner);}
        for (const finish of entry.pending.values()) finish(false);
      });
    });
  }
  async live(owner) {
    const entry = this.#ports.get(owner?.documentId);
    if (!entry || entry.pending.size >= 16 || !owns(entry.owner, owner)) return false;
    const nonce = crypto.randomUUID();
    return new Promise(resolve => {
      const finish = ok => {clearTimeout(timer); entry.pending.delete(nonce); resolve(ok && this.#ports.get(owner.documentId) === entry);};
      const timer = setTimeout(() => finish(false), 3000);
      entry.pending.set(nonce, finish);
      try {entry.port.postMessage({nonce});} catch {finish(false);}
    });
  }
}
