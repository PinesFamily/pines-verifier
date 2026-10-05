import {CaptureSession} from './session.mjs';
import {capturedFrom} from '../../../packages/verification-schemas/src/index.ts';
import {check} from '../src/policy.js';
const route = value => {try {const u = new URL(value); return u.origin + u.pathname;} catch {return null;}};

// One browser-created navigation, one document, one replay. No script injection or navigation permission.
// Register ONLY after the host grant: Chrome can leave an earlier webRequest registration inactive.
export async function providerLease({browser, schema, owner, url, deadline, navigate, onChange, onOwner}) {
  check(await browser.permissions.contains({origins: [schema.request.origin + '/*']}), 'CAPTURE_PERMISSION_LOST');
  const removers = []; let session, documentId, navigationId, invalid, timer, used = false;
  const add = (event, listener, ...args) => {event.addListener(listener, ...args); removers.push(() => event.removeListener(listener));};
  const clear = () => {clearTimeout(timer); for (const remove of removers.splice(0)) remove();};
  const fail = code => {
    if (invalid) return; invalid = code; clear();
    if (session && ['waiting', 'captured'].includes(session.status().phase)) session.cancel(code);
    else onChange({phase: 'failed', error: code});
  };
  const validRequest = d => d.tabId === owner.tabId && d.frameId === 0 && d.type === 'xmlhttprequest'
    && d.initiator === schema.request.origin && d.documentLifecycle === 'active' && typeof d.documentId === 'string'
    && d.documentId.length > 0 && d.documentId.length <= 128;
  const before = d => {
    if (invalid || d.tabId !== owner.tabId || d.frameId !== 0) return;
    if (d.type === 'main_frame') {
      if (navigationId || route(d.url) !== route(url)) {fail('CAPTURE_NAVIGATED'); return;}
      navigationId = d.requestId;
    } else if (navigationId && validRequest(d)) {
      if (documentId && d.documentId !== documentId) {fail('CAPTURE_OWNER_CHANGED'); return;}
      // Bind using browser request metadata before any secret-bearing callback.
      if (!documentId) {
        documentId = d.documentId;
        const bound = {...owner, documentId, route: route(url)};
        onOwner(bound);
        session = new CaptureSession({schema, owner: bound, deadline, onChange});
      }
    }
  };
  const headers = d => {
    if (!invalid && navigationId && validRequest(d) && d.documentId === documentId && capturedFrom(schema, d.url)) session?.observe(d);
  };
  const inspect = async () => {
    check(!invalid && documentId, invalid ?? 'CAPTURE_UNAVAILABLE');
    const [tab, granted] = await Promise.all([browser.tabs.get(owner.tabId), browser.permissions.contains({origins: [schema.request.origin + '/*']})]);
    check(!invalid && granted && tab.windowId === owner.windowId && tab.incognito === false && route(tab.url) === route(url)
      && (!tab.pendingUrl || route(tab.pendingUrl) === route(url)) && tab.status === 'complete', 'CAPTURE_OWNER_CHANGED');
    return true;
  };
  try {
    add(browser.webRequest.onBeforeRequest, before, {urls: [schema.request.origin + '/*'], tabId: owner.tabId, types: ['main_frame', 'xmlhttprequest']});
    add(browser.webRequest.onBeforeSendHeaders, headers, {urls: [schema.request.origin + '/*'], tabId: owner.tabId, types: ['xmlhttprequest']}, ['requestHeaders', 'extraHeaders']);
    add(browser.webRequest.onBeforeRedirect, d => {if (d.tabId === owner.tabId && d.type === 'main_frame') fail('CAPTURE_NAVIGATED');}, {urls: [schema.request.origin + '/*'], tabId: owner.tabId, types: ['main_frame']});
    add(browser.tabs.onUpdated, (id, change, tab) => {
      if (id !== owner.tabId || invalid) return;
      if (change.url && route(change.url) !== route(url) && (change.url !== 'about:blank' || navigationId)) fail('CAPTURE_NAVIGATED');
      // Once bound, a hidden URL (a move to an ungranted origin) also invalidates.
      if (documentId && tab && route(tab.url) !== route(url)) fail('CAPTURE_NAVIGATED');
      // A loading status alone is not a document transition: history.replaceState
      // at the identical URL emits loading without change.url. Real navigations
      // (including silent prerenders) are guarded by main_frame requests, route
      // visibility, document IDs and tab replacement events.
    });
    add(browser.tabs.onRemoved, id => {if (id === owner.tabId) fail('CAPTURE_TAB_CLOSED');});
    add(browser.tabs.onDetached, id => {if (id === owner.tabId) fail('CAPTURE_OWNER_CHANGED');});
    add(browser.tabs.onReplaced, (_id, removed) => {if (removed === owner.tabId) fail('CAPTURE_OWNER_CHANGED');});
    add(browser.permissions.onRemoved, () => fail('CAPTURE_PERMISSION_LOST'));
    timer = setTimeout(() => fail('CAPTURE_TIMEOUT'), Math.max(1, deadline - Date.now()));
    await navigate();
    check(!invalid, invalid);
    return {
      status: () => invalid ? {phase: 'failed', error: invalid} : session?.status() ?? {phase: 'waiting'},
      cancel: () => {invalid ??= 'CAPTURE_CANCELLED'; clear(); session?.cancel();},
      validate: async () => {try {return await inspect();} catch {fail('CAPTURE_OWNER_CHANGED'); throw Error('CAPTURE_OWNER_CHANGED');}},
      take: async runId => {
        check(!used && session?.status().phase === 'captured', 'CAPTURE_UNAVAILABLE');
        // Early API requests can precede the page's complete event. Keep the lease until its initial load settles.
        while (!invalid && Date.now() < deadline) {
          const tab = await browser.tabs.get(owner.tabId);
          if (tab.status === 'complete') break;
          await new Promise(resolve => setTimeout(resolve, 50));
        }
        await inspect(); check(Date.now() < deadline, 'TICKET_EXPIRED');
        const replay = session.take(runId); used = true; clearTimeout(timer);
        browser.webRequest.onBeforeSendHeaders.removeListener(headers);
        // Keep metadata/lifecycle guards through Share; credentials are already consumed.
        return replay;
      },
    };
  } catch (error) {clear(); session?.cancel(); throw error;}
}
