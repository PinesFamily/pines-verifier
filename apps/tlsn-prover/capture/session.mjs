import {capturedFrom, prepareReplay, requestUrl} from '../../../packages/verification-schemas/src/index.ts';
import {UUID, check} from '../src/policy.js';
import {isPrivateHeadersSchema, pathParamsFrom, pathParamUnavailableCode, requiresPathParams} from '../src/private-headers.mjs';
import {prepareReplayFor} from './schema-adapter.mjs';
import {capturedHeaderNames} from '../src/exchanges.mjs';

// A full browser cookie jar carries unrelated cookies that prepareReplay drops.
// Bound the raw jar generously; the filtered wire is still bound by maxSentBytes.
const MAX_COOKIE_JAR = 32768;
const active = phase => phase === 'waiting' || phase === 'captured';
const reasons = new Set(['CAPTURE_CANCELLED', 'CAPTURE_NAVIGATED', 'CAPTURE_TAB_CLOSED', 'CAPTURE_OWNER_CHANGED', 'CAPTURE_PERMISSION_LOST', 'CAPTURE_UNAVAILABLE', 'PROVIDER_CHALLENGE', 'PROVIDER_HTTP_401', 'PROVIDER_HTTP_403', 'PROVIDER_HTTP_429', 'PROVIDER_SIGN_IN_REQUIRED', 'CLAUDE_ORG_UNAVAILABLE']);

// Internal extension capability, never a page-facing API. Only take() returns
// credential material, once, to the extension's trusted replay consumer.
export class CaptureSession {
  #schema; #owner; #deadline; #maxHeaderBytes; #now; #changed; #state; #replay; #unscoped = false; #timeout = 'CAPTURE_TIMEOUT';
  constructor({schema, owner, deadline, now = Date.now, onChange = () => {}}) {
    // Cookies are only ever an origin-wide credential taken by trigger; an
    // untriggered cookie schema has no qualified capture path here.
    check(schema.request.method === 'GET' && schema.request.body.kind === 'empty' && (schema.capture.cookies.length === 0 || schema.capture.trigger), 'UNSUPPORTED_CAPTURE');
    check(UUID.test(owner?.runId) && Number.isInteger(owner.tabId) && owner.tabId >= 0 && Number.isInteger(owner.windowId) && owner.windowId >= 0
      && typeof owner.documentId === 'string' && owner.documentId.length > 0 && owner.documentId.length <= 128, 'INVALID_CAPTURE_OWNER');
    check(Number.isSafeInteger(deadline) && deadline > now() && deadline - now() <= schema.limits.sessionTimeoutMs, 'INVALID_CAPTURE_DEADLINE');
    // A path-parameter schema (D3) exists only in the private-headers class, and its capture must name the parameter.
    // A templated route needs a triggered capture to see the parameter in the page's own traffic (any class).
    check(!requiresPathParams(schema) || schema.capture.trigger, 'UNSUPPORTED_CAPTURE');
    if (requiresPathParams(schema)) this.#timeout = pathParamUnavailableCode(schema);
    this.#schema = schema; this.#owner = Object.freeze({...owner}); this.#deadline = deadline;
    this.#maxHeaderBytes = schema.limits.maxHeaderBytes; this.#now = now; this.#changed = onChange;
    this.#state = {runId: owner.runId, phase: 'waiting', error: null, headers: [], maxHeaderBytes: this.#maxHeaderBytes, claimable: false};
  }
  #set(phase, error = null) {
    if (phase !== 'captured') this.#replay = undefined;
    this.#state.phase = phase; this.#state.error = error;
    this.#changed(structuredClone(this.#state));
  }
  // The page's API traffic came, but none of it named the parameter: say which, not a bare timeout.
  #expired() { return this.#unscoped ? this.#timeout : 'CAPTURE_TIMEOUT'; }
  #expire() { if (active(this.#state.phase) && this.#now() >= this.#deadline) this.#set('failed', this.#expired()); }
  status() { this.#expire(); return structuredClone(this.#state); }
  cancel(reason = 'CAPTURE_CANCELLED') {
    if (reason === 'CAPTURE_TIMEOUT' && requiresPathParams(this.#schema)) reason = this.#expired();
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
    // Owner, 2026-10-07: the org is the one the provider page itself requests (/api/organizations/<uuid>/...), read from
    // this request's URL. Its cookie jar is the capture; no other request and no response body names the org.
    const pathParams = requiresPathParams(this.#schema) ? pathParamsFrom(this.#schema, details.url) : undefined;
    if (pathParams === null) { this.#unscoped = true; return false; }
    try {
      check(Array.isArray(details.requestHeaders) && details.requestHeaders.length <= 128, 'INVALID_CAPTURE');
      const jar = this.#schema.capture.cookies.length > 0;
      // Every exchange's header names (multi-exchange protocol §1.7): a later exchange's own header is captured here too.
      const names = new Set([...capturedHeaderNames(this.#schema), ...(jar ? ['cookie'] : [])]);
      // Never retain a request history. HTTP/2 pseudo-headers, every unselected
      // browser header and (for cookie-free schemas) the jar are dropped here;
      // prepareReplay then keeps only the schema's named cookies.
      const selected = details.requestHeaders.filter(header => typeof header.name === 'string' && names.has(header.name.toLowerCase()));
      check(selected.every(header => typeof header.value === 'string' && header.value.length <= (header.name.toLowerCase() === 'cookie' ? MAX_COOKIE_JAR : this.#schema.limits.maxSentBytes)), 'INVALID_CAPTURE');
      const captured = {url: details.url, method: details.method, headers: selected};
      const replay = requiresPathParams(this.#schema) ? prepareReplayFor(this.#schema, captured, pathParams) : prepareReplay(this.#schema, captured);
      // The one-time replay the worker takes carries, beside the first exchange's request, the exchange-only headers
      // the capture saw, so the worker can build every exchange's replay from this one capture.
      const exchangeHeaders = selected.filter(header => !this.#schema.capture.headers.some(rule => rule.name === header.name.toLowerCase()) && header.name.toLowerCase() !== 'cookie')
        .map(header => ({name: header.name.toLowerCase(), value: header.value}));
      const bytes = value => new TextEncoder().encode(value).length;
      // Status carries names and sizes only, never a header or cookie value.
      this.#state.headers = [...this.#schema.capture.headers.filter(rule => replay.headers[rule.name] !== undefined)
        .map(rule => ({name: rule.name, bytes: bytes(replay.headers[rule.name]), secret: rule.secret})),
        ...(jar && replay.headers.cookie !== undefined ? [{name: 'cookie', bytes: bytes(replay.headers.cookie), secret: true}] : [])];
      if (this.#state.headers.some(header => header.bytes > this.#maxHeaderBytes)) {
        this.#set('failed', 'INVALID_CAPTURE'); return true;
      }
      this.#replay = exchangeHeaders.length ? Object.freeze({...replay, exchangeHeaders: Object.freeze(exchangeHeaders)}) : replay; this.#set('captured');
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
