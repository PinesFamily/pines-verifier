// Observe issuance only after the pinned route has been confirmed. An existing
// cookie in a newly routed browser is not evidence it was earned at this address.
// All values stay in service-worker memory and disappear on every restoration.
const check = (value, code = 'ASSISTANCE_CLEARANCE_UNPROVEN') => {if (!value) throw Error(code);};
const grok = url => {try {return new URL(url).origin === 'https://grok.com';} catch {return false;}};
export class GrokClearance {
  #browser; #requests = new Map(); #issued = new Map(); #active = false;
  #before; #headers; #done;
  constructor(browser) {
    this.#browser = browser;
    this.#before = details => {
      if (!this.#active || !grok(details.url) || this.#requests.size >= 64) return;
      const ua = (details.requestHeaders ?? []).filter(h => h.name.toLowerCase() === 'user-agent');
      if (ua.length === 1 && typeof ua[0].value === 'string' && /^[\x20-\x7e]{1,512}$/.test(ua[0].value))
        this.#requests.set(details.requestId, ua[0].value);
    };
    this.#headers = details => {
      const ua = this.#requests.get(details.requestId); this.#requests.delete(details.requestId);
      if (!this.#active || !ua || !grok(details.url) || details.statusCode < 200 || details.statusCode >= 400) return;
      for (const header of details.responseHeaders ?? []) {
        if (header.name.toLowerCase() !== 'set-cookie' || typeof header.value !== 'string') continue;
        const value = /^cf_clearance=([\x21-\x3a\x3c-\x7e]{1,8192})(?:;|$)/.exec(header.value)?.[1];
        if (!value) continue;
        if (this.#issued.size >= 4) this.#issued.delete(this.#issued.keys().next().value);
        this.#issued.set(value, ua);
      }
    };
    this.#done = details => this.#requests.delete(details.requestId);
  }
  start() {
    this.stop(); this.#active = true;
    const filter = {urls: ['https://grok.com/*']}, web = this.#browser.webRequest;
    try {
      web.onBeforeSendHeaders.addListener(this.#before, filter, ['requestHeaders','extraHeaders']);
      web.onHeadersReceived.addListener(this.#headers, filter, ['responseHeaders','extraHeaders']);
      web.onCompleted.addListener(this.#done, filter); web.onErrorOccurred.addListener(this.#done, filter);
    } catch {this.stop(); throw Error('ASSISTANCE_CLEARANCE_UNPROVEN');}
  }
  validate(replay) {
    check(this.#active && grok(replay?.url));
    const cookie = replay.headers?.cookie, ua = replay.headers?.['user-agent'];
    check(typeof cookie === 'string' && typeof ua === 'string');
    const values = cookie.split(';').map(s => s.trim()).filter(s => s.startsWith('cf_clearance=')).map(s => s.slice(13));
    check(values.length === 1 && this.#issued.get(values[0]) === ua);
  }
  optional(replay) {
    check(this.#active && grok(replay?.url));
    const cookie = replay.headers?.cookie, ua = replay.headers?.['user-agent'];
    check(typeof cookie === 'string' && typeof ua === 'string');
    const parts = cookie.split(';').map(s => s.trim());
    const values = parts.filter(s => s.startsWith('cf_clearance=')).map(s => s.slice(13));
    // Even an otherwise valid cookie from before route confirmation is omitted.
    // The older mandatory-clearance profile still calls validate(), not this path.
    const proven = values.length === 1 && this.#issued.get(values[0]) === ua;
    return {...replay, headers: {...replay.headers,
      cookie: parts.filter(s => !s.startsWith('cf_clearance=') || proven).join('; ')}};
  }
  stop() {
    this.#active = false; this.#requests.clear(); this.#issued.clear();
    const web = this.#browser.webRequest;
    for (const [event, listener] of [[web.onBeforeSendHeaders,this.#before],[web.onHeadersReceived,this.#headers],
      [web.onCompleted,this.#done],[web.onErrorOccurred,this.#done]]) event?.removeListener(listener);
  }
}
