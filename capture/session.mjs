import {capturedFrom, prepareReplay, requestUrl} from '../verification-schemas/src/index.ts';
import {UUID, check} from '../src/policy.js';

// A full browser cookie jar carries unrelated cookies that prepareReplay drops.
// Bound the raw jar generously; the filtered wire is still bound by maxSentBytes.
const MAX_COOKIE_JAR = 32768;
const active = phase => phase === 'waiting' || phase === 'captured';
const reasons = new Set(['CAPTURE_CANCELLED', 'CAPTURE_NAVIGATED', 'CAPTURE_TAB_CLOSED', 'CAPTURE_OWNER_CHANGED', 'CAPTURE_PERMISSION_LOST', 'CAPTURE_UNAVAILABLE']);

// Internal extension capability, never a page-facing API. Only take() returns
// credential material, once, to the extension's trusted replay consumer.
export class CaptureSession {
  #schema; #owner; #deadline; #maxHeaderBytes; #now; #changed; #state; #replay;
  constructor({schema, owner, deadline, now = Date.now, onChange = () => {}}) {
    // Cookies are only ever an origin-wide credential taken by trigger; an
    // untriggered cookie schema has no qualified capture path here.
    check(schema.request.method === 'GET' && schema.request.body.kind === 'empty' && (schema.capture.cookies.length === 0 || schema.capture.trigger), 'UNSUPPORTED_CAPTURE');
    check(UUID.test(owner?.runId) && Number.isInteger(owner.tabId) && owner.tabId >= 0 && Number.isInteger(owner.windowId) && owner.windowId >= 0
      && typeof owner.documentId === 'string' && owner.documentId.length > 0 && owner.documentId.length <= 128, 'INVALID_CAPTURE_OWNER');
    check(Number.isSafeInteger(deadline) && deadline > now() && deadline - now() <= schema.limits.sessionTimeoutMs, 'INVALID_CAPTURE_DEADLINE');
    this.#schema = schema; this.#owner = Object.freeze({...owner}); this.#deadline = deadline;
    this.#maxHeaderBytes = schema.limits.maxHeaderBytes; this.#now = now; this.#changed = onChange;
    this.#state = {runId: owner.runId, phase: 'waiting', error: null, headers: [], maxHeaderBytes: this.#maxHeaderBytes, claimable: false};
  }
  #set(phase, error = null) {
    if (phase !== 'captured') this.#replay = undefined;
    this.#state.phase = phase; this.#state.error = error;
    this.#changed(structuredClone(this.#state));
  }
  #expire() { if (active(this.#state.phase) && this.#now() >= this.#deadline) this.#set('failed', 'CAPTURE_TIMEOUT'); }
  status() { this.#expire(); return structuredClone(this.#state); }
  cancel(reason = 'CAPTURE_CANCELLED') {
    check(reasons.has(reason), 'INVALID_CAPTURE_REASON');
    this.#expire();
    if (active(this.#state.phase)) this.#set('cancelled', reason);
  }
  observe(details) {
    this.#expire();
    if (this.#state.phase !== 'waiting' || details.tabId !== this.#owner.tabId || details.frameId !== 0
      || details.documentId !== this.#owner.documentId || details.documentLifecycle !== 'active'
      || details.type !== 'xmlhttprequest' || details.initiator !== this.#schema.request.origin
      || typeof details.url !== 'string' || !capturedFrom(this.#schema, details.url) || details.method !== this.#schema.request.method) return false;
    try {
      check(Array.isArray(details.requestHeaders) && details.requestHeaders.length <= 128, 'INVALID_CAPTURE');
      const jar = this.#schema.capture.cookies.length > 0;
      const names = new Set([...this.#schema.capture.headers.map(rule => rule.name), ...(jar ? ['cookie'] : [])]);
      // Never retain a request history. HTTP/2 pseudo-headers, every unselected
      // browser header and (for cookie-free schemas) the jar are dropped here;
      // prepareReplay then keeps only the schema's named cookies.
      const selected = details.requestHeaders.filter(header => typeof header.name === 'string' && names.has(header.name.toLowerCase()));
      check(selected.every(header => typeof header.value === 'string' && header.value.length <= (header.name.toLowerCase() === 'cookie' ? MAX_COOKIE_JAR : this.#schema.limits.maxSentBytes)), 'INVALID_CAPTURE');
      const replay = prepareReplay(this.#schema, {url: details.url, method: details.method, headers: selected});
      const bytes = value => new TextEncoder().encode(value).length;
      // Status carries names and sizes only, never a header or cookie value.
      this.#state.headers = [...this.#schema.capture.headers.filter(rule => replay.headers[rule.name] !== undefined)
        .map(rule => ({name: rule.name, bytes: bytes(replay.headers[rule.name]), secret: rule.secret})),
        ...(jar && replay.headers.cookie !== undefined ? [{name: 'cookie', bytes: bytes(replay.headers.cookie), secret: true}] : [])];
      if (this.#state.headers.some(header => header.bytes > this.#maxHeaderBytes)) {
        this.#set('failed', 'INVALID_CAPTURE'); return true;
      }
      this.#replay = replay; this.#set('captured');
    } catch {
      this.#set('failed', 'INVALID_CAPTURE');
    }
    return true;
  }
  take(runId) {
    this.#expire();
    check(runId === this.#owner.runId && this.#state.phase === 'captured', 'CAPTURE_UNAVAILABLE');
    const replay = this.#replay;
    this.#set('consumed');
    return replay;
  }
}

// Use browser-owned document identity, not a URL or document ID asserted by the
// website. A second check after listener installation closes the setup race.
export async function captureProvider({browser, schema, owner, deadline, onChange = () => {}}) {
  const inspectOwner = async () => {
    const [tab, frame] = await Promise.all([browser.tabs.get(owner.tabId), browser.webNavigation.getFrame({tabId: owner.tabId, frameId: 0})]);
    check(tab.windowId === owner.windowId && tab.incognito === false && new URL(tab.url).origin === schema.request.origin
      && frame?.documentId === owner.documentId && frame.documentLifecycle === 'active' && new URL(frame.url).origin === schema.request.origin, 'INVALID_CAPTURE_OWNER');
  };
  await inspectOwner();
  const removers = []; let timer;
  const unlisten = () => { for (const remove of removers.splice(0)) remove(); clearTimeout(timer); };
  const headers = details => session.observe(details);
  // A trigger listens to the origin's own API traffic under its prefix; the
  // replay still targets the fixed request URL. extraHeaders exposes Cookie.
  const trigger = schema.capture.trigger;
  const session = new CaptureSession({schema, owner, deadline, onChange: state => {
    if (state.phase !== 'waiting') browser.webRequest.onBeforeSendHeaders.removeListener(headers);
    if (!active(state.phase)) unlisten();
    onChange(state);
  }});
  const add = (event, listener, ...arguments_) => {
    event.addListener(listener, ...arguments_); removers.push(() => event.removeListener(listener));
  };
  try {
    add(browser.webRequest.onBeforeSendHeaders, headers,
      {urls: [trigger ? `${schema.request.origin}${trigger.pathPrefix}*` : requestUrl(schema)], tabId: owner.tabId, types: ['xmlhttprequest']}, ['requestHeaders', 'extraHeaders']);
    add(browser.webNavigation.onBeforeNavigate, details => { if (details.tabId === owner.tabId && details.frameId === 0) session.cancel('CAPTURE_NAVIGATED'); });
    add(browser.webNavigation.onCommitted, details => { if (details.tabId === owner.tabId && details.frameId === 0 && details.documentId !== owner.documentId) session.cancel('CAPTURE_OWNER_CHANGED'); });
    add(browser.tabs.onRemoved, id => { if (id === owner.tabId) session.cancel('CAPTURE_TAB_CLOSED'); });
    add(browser.tabs.onDetached, id => { if (id === owner.tabId) session.cancel('CAPTURE_OWNER_CHANGED'); });
    add(browser.tabs.onReplaced, (_added, removed) => { if (removed === owner.tabId) session.cancel('CAPTURE_OWNER_CHANGED'); });
    add(browser.permissions.onRemoved, () => session.cancel('CAPTURE_PERMISSION_LOST'));
    timer = setTimeout(() => session.status(), Math.max(0, deadline - Date.now()));
    await inspectOwner();
    check(session.status().phase !== 'cancelled', 'CAPTURE_UNAVAILABLE');
    return {
      status: () => session.status(), cancel: reason => session.cancel(reason),
      take: async runId => {
        try { await inspectOwner(); }
        catch { session.cancel('CAPTURE_OWNER_CHANGED'); throw Error('CAPTURE_UNAVAILABLE'); }
        return session.take(runId);
      },
    };
  } catch {
    session.cancel('CAPTURE_UNAVAILABLE'); unlisten(); throw Error('CAPTURE_UNAVAILABLE');
  }
}
