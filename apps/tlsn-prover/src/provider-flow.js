import {check, terminal} from './policy.js';

export const CHATGPT_USAGE_URL = 'https://chatgpt.com/settings/usage';
// The browser route each provider's run-owned tab opens. ChatGPT's immutable
// schema retains an old hash URL, so its current route is pinned here; Claude's and
// Grok's schema routes load a page whose own /api/ or /rest/ traffic carries the session cookie.
const routes = {'pines.chatgpt.tee.native': () => CHATGPT_USAGE_URL, 'pines.chatgpt.plan': () => CHATGPT_USAGE_URL, 'pines.claude.plan': schema => schema.capture.navigationUrl,
  'pines.grok.plan': schema => schema.capture.navigationUrl,
  'pines.claude.tee.native': schema => schema.capture.navigationUrl,
  'pines.grok.tee.native': schema => schema.capture.navigationUrl};
export function providerUrl(schema) {
  check(Object.hasOwn(routes, schema?.schemaId), 'SCHEMA_UNAVAILABLE');
  const url = routes[schema.schemaId](schema);
  check(typeof url === 'string' && providerRoute(url) === url, 'SCHEMA_UNAVAILABLE');
  return url;
}
export function providerRoute(value) {
  try { const url = new URL(value); return url.origin + url.pathname; } catch { return null; }
}
// A newly created tab can have no committed URL yet. Check pending navigation
// too, so a run-owned blank tab is never repurposed after the user navigates it.
export function isBlankTab(tab) {
  return !!tab && (!tab.url || tab.url === 'about:blank') && (!tab.pendingUrl || tab.pendingUrl === 'about:blank');
}

// Browser UI only: this never receives credentials or decides claim eligibility.
// The new tab belongs to this run, so an unrelated provider tab is never closed.
export class ProviderFlow {
  #browser; #current; #capture; #persist; #returned; #ownerReady;
  constructor({browser, current, capture, persist, returned = async () => {}, ownerReady}) {
    this.#browser = browser; this.#current = current; this.#capture = capture; this.#persist = persist;
    this.#returned = returned; this.#ownerReady = ownerReady;
  }
  async #closeBlank(job, id) {
    if (!Number.isInteger(id)) return;
    const tab = await this.#browser.tabs.get(id).catch(() => null);
    if (tab?.windowId === job.owner.windowId && tab.url === 'about:blank' && isBlankTab(tab)) await this.#browser.tabs.remove(id).catch(() => {});
  }
  async start(job, schema) {
    check(this.#current() === job, 'STALE_RUN');
    if (job.providerOpening || Number.isInteger(job.ownedProviderTabId)) return;
    check(job.phase === 'awaiting-capture', 'STALE_RUN');
    const navigateTo = providerUrl(schema);
    job.providerOpening = true; job.providerUrl = navigateTo;
    await this.#persist();
    try {
      const tab = await this.#browser.tabs.create({windowId: job.owner.windowId, openerTabId: job.owner.tabId, url: 'about:blank', active: true}).catch(() => {throw Error('PROVIDER_OPEN_FAILED');});
      if (this.#current() !== job || terminal(job.phase)) {
        await this.#closeBlank(job, tab.id);
        throw Error('CANCELLED');
      }
      job.ownedProviderTabId = tab.id;
      await this.#persist();
      // Only the browser navigation route; request, disclosure and receipt pins stay intact.
      await this.#capture.start(job, schema, {tabId: tab.id, navigateTo});
    } catch (error) {
      await this.#closeBlank(job, job.ownedProviderTabId);
      throw error;
    } finally { job.providerOpening = false; if (this.#current() === job) await this.#persist(); }
  }
  async continue(job) {
    check(this.#current() === job && job.phase === 'completed' && job.receiptVerified === true, 'RECEIPT_PENDING');
    await this.#return(job);
  }
  async recover(job) {
    // A stopped run (cancelled, or failed, a rejected receipt among them) has nothing left to wait for: back to Pines
    // at once. A finished one waits for the receipt, or for the wait to run out.
    const stopped = job.phase === 'cancelled' || job.phase === 'failed';
    check(this.#current() === job && (job.phase === 'completed' || stopped), 'RECEIPT_PENDING');
    check(stopped || job.receiptVerified || job.receiptWaitStopped || Date.now() - (job.phaseStartedAt ?? Date.now()) >= 30000, 'RECEIPT_PENDING');
    // This just leaves the stalled panel. The website must still read a valid
    // API receipt before showing claim readiness; no success flag is changed.
    await this.#return(job);
  }
  async #return(job) {
    const browser = this.#browser;
    let pines = await browser.tabs.get(job.owner.tabId).catch(() => null);
    const connected = pines?.windowId === job.owner.windowId && await this.#ownerReady(job.owner);
    check(this.#current() === job, 'STALE_RUN');
    // Focusing/opening a trusted page does not transfer proof ownership or send it credentials.
    if (!connected) pines = await browser.tabs.create({windowId: job.owner.windowId, url: job.owner.origin, active: true});
    check(this.#current() === job, 'STALE_RUN');
    await browser.tabs.update(pines.id, {active: true});
    await browser.windows.update(pines.windowId, {focused: true});
    // Retain the provider tab: URL equality alone cannot prove it is still the captured document.
    check(this.#current() === job, 'STALE_RUN');
    // Persist the home state before closing; reopening (or a refused close) must
    // not resurrect the stopped screen.
    await this.#returned(job);
    check(this.#current() === job, 'STALE_RUN');
    await browser.sidePanel.close({windowId: job.owner.windowId}).catch(() => {});
  }
}
