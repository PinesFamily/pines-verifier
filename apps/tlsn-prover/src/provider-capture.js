import {providerLease} from '../capture/provider-lease.mjs';
import {check, terminal} from './policy.js';
import {providerUrl, isBlankTab} from './provider-flow.js';

// Only this controller hands a one-time replay to the proof worker; never to the Pines page.
export class ProviderCapture {
  #browser; #current; #deliver; #fail; #owner; #ownerReady; #lease;
  constructor({browser, current, deliver, fail, owner, ownerReady}) {
    this.#browser = browser; this.#current = current; this.#deliver = deliver;
    this.#fail = fail; this.#owner = owner; this.#ownerReady = ownerReady;
  }
  #live(lease) {return this.#lease === lease && this.#current() === lease.job && !terminal(lease.job.phase);}
  active(runId) {return this.#lease?.job.runId === runId && !this.#lease.done;}
  cancel() {const lease = this.#lease; this.#lease = undefined; lease?.session?.cancel();}
  async validate(job) {
    const lease = this.#lease;
    try {
      check(lease?.job === job && this.#live(lease), 'CAPTURE_OWNER_CHANGED');
      await lease.session.validate();
      check(await this.#ownerReady(job.owner), 'CAPTURE_OWNER_CHANGED');
      await lease.session.validate();
      check(this.#live(lease), 'CAPTURE_OWNER_CHANGED');
    } catch (error) {
      if (lease) await this.#reject(lease, 'CAPTURE_OWNER_CHANGED');
      throw error;
    }
  }
  async start(job, schema, {tabId, navigateTo} = {}) {
    check(this.#current() === job && job.phase === 'awaiting-capture', 'STALE_RUN');
    check(!this.#lease || !this.#live(this.#lease) || this.#lease.done, 'CAPTURE_BUSY');
    check(Date.now() < job.captureExpiresAt, 'TICKET_EXPIRED'); this.cancel();
    const lease = {job, done: false, taking: false}; this.#lease = lease;
    try {
      await this.#owner(job, null); check(this.#live(lease), 'STALE_RUN');
      if (!Number.isInteger(tabId)) {
        const created = await this.#browser.tabs.create({windowId: job.owner.windowId, url: 'about:blank', active: true});
        check(this.#live(lease), 'STALE_RUN');
        tabId = created.id; job.ownedProviderTabId = tabId;
        navigateTo = schema.schemaId.startsWith('pines.fixture.') ? schema.capture.navigationUrl : providerUrl(schema);
      }
      const tab = await this.#browser.tabs.get(tabId);
      check(tab.incognito === false && tab.windowId === job.owner.windowId && tab.id === job.ownedProviderTabId
        && isBlankTab(tab) && navigateTo, 'CAPTURE_OWNER_CHANGED');
      const url = navigateTo;
      check(new URL(url).origin === schema.request.origin, 'CAPTURE_OWNER_CHANGED');
      lease.session = await providerLease({browser: this.#browser, schema,
        owner: {runId: job.runId, tabId: tab.id, windowId: tab.windowId}, url,
        deadline: Math.min(Date.now() + 30000, job.captureExpiresAt),
        navigate: () => this.#browser.tabs.update(tab.id, {url, active: true}).catch(() => {throw Error('PROVIDER_OPEN_FAILED');}),
        onOwner: owner => {if (this.#live(lease)) void this.#owner(job, owner);},
        onChange: state => {
          if (!this.#live(lease)) return;
          if (state.phase === 'captured') void this.#handoff(lease);
          else if (['failed', 'cancelled'].includes(state.phase)) void this.#reject(lease, state.error);
        }});
      if (!this.#live(lease)) {lease.session.cancel(); throw Error('STALE_RUN');}
      void this.#handoff(lease);
    } catch (error) {if (this.#lease === lease) this.cancel(); throw error;}
  }
  async #handoff(lease) {
    if (!this.#live(lease) || lease.taking || lease.session?.status().phase !== 'captured') return;
    lease.taking = true;
    try {
      const replay = await lease.session.take(lease.job.runId);
      await this.validate(lease.job);
      check(this.#live(lease) && Date.now() < lease.job.captureExpiresAt, 'TICKET_EXPIRED');
      await this.#deliver(lease.job.runId, replay); lease.done = true;
    } catch (error) {await this.#reject(lease, error?.message);}
  }
  async #reject(lease, code) {
    if (!this.#live(lease)) return; this.cancel();
    await this.#fail(/^CAPTURE_[A-Z_]+$/.test(code ?? '') || code === 'TICKET_EXPIRED' ? code : 'CAPTURE_UNAVAILABLE');
  }
}
