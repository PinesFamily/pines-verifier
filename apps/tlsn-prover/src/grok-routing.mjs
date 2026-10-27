// Opt-in browser routing. Pins are packaged/operator-reviewed configuration, never
// page input. Credentials live only in this service worker; recovery needs no secret.
// Assistance can be the first Grok flow in a fresh install. Its route probe and
// proxy authentication require the same explicit host access as provider capture.
export const ROUTING_PERMISSION = Object.freeze({permissions: ['proxy', 'webRequestAuthProvider'], origins: ['https://grok.com/*']});
export const ROUTING_NOTICE = 'All Grok tabs in this browser profile will temporarily connect through a Pines-operated address. Your connection to Grok stays encrypted end to end. Other browsing stays direct. Pines restores your routing when verification ends.';
export const ROUTING_MARKER = 'pines-grok-routing-v1';
export const ROUTING_ALARM = 'pines-grok-routing-expiry-v1';
const check = (condition, code) => {if (!condition) throw Error(code);};
// Chrome can reorder dictionary keys when it returns a proxy configuration.
const canonical = value => value && typeof value === 'object' && !Array.isArray(value)
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const same = (a, b) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
const validIp = ip => typeof ip === 'string' && /^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip)
  && ip.split('.').every(part => String(Number(part)) === part && Number(part) <= 255);
export function grokPac(pin) {
  check(validIp(pin.egressIpv4) && Number.isInteger(pin.browserPort) && pin.browserPort > 0 && pin.browserPort <= 65535, 'ASSISTANCE_PIN');
  return {mode: 'pac_script', pacScript: {mandatory: true,
    data: `function FindProxyForURL(url, host) { if (host === "grok.com") return "HTTPS ${pin.egressIpv4}:${pin.browserPort}"; return "DIRECT"; }`}};
}
const direct = setting => setting?.value?.mode === 'direct'
  && ['controllable_by_this_extension', 'controlled_by_this_extension'].includes(setting.levelOfControl);
async function bounded(operation) {
  const controller = new AbortController(); let timer;
  try {return await Promise.race([operation(controller.signal), new Promise((_, reject) => {
    timer = setTimeout(() => {controller.abort(); reject(Error('ASSISTANCE_TIMEOUT'));}, 10_000);
  })]);} finally {clearTimeout(timer); controller.abort();}
}

export class GrokRouting {
  #browser; #pins; #verifyLease; #observeRoute; #now; #active; #queue = Promise.resolve();
  #auth; #permission; #alarm; #installed = false; #enabled; #qualified; #notify;
  constructor({browser, pins, verifyLease, observeRoute, enabled = false, qualification, now = Date.now, onRestoration = () => {}}) {
    this.#browser = browser; this.#pins = structuredClone(pins ?? []); this.#verifyLease = verifyLease;
    this.#observeRoute = observeRoute; this.#now = now; this.#enabled = enabled;
    this.#qualified = qualification; this.#notify = onRestoration;
    this.#auth = (details, callback) => {
      const current = this.#active;
      // Never supply proxy credentials to a provider's HTTP authentication prompt.
      if (!current || !details.isProxy) {callback({}); return;}
      let url; try {url = new URL(details.url);} catch {callback({cancel: true}); return;}
      const valid = this.#now() < current.expiresAt && details.challenger?.host === current.pin.egressIpv4
        && details.challenger?.port === current.pin.browserPort && details.scheme?.toLowerCase() === 'basic'
        && details.realm === 'Pines verification' && url.origin === 'https://grok.com'
        && !current.authRequests.has(details.requestId) && current.authRequests.size < 32;
      if (!valid) {callback({cancel: true}); return;}
      current.authRequests.add(details.requestId);
      callback({authCredentials: {username: 'pines', password: current.credential}});
    };
    this.#permission = () => {void this.restore('permission-change');};
    this.#alarm = alarm => {if (alarm.name === ROUTING_ALARM) void this.restore('timeout');};
  }
  #serial(operation) {
    const pending = this.#queue.catch(() => {}).then(operation); this.#queue = pending; return pending;
  }
  async initialize() {
    // Called on every service-worker startup, not just runtime.onStartup.
    if (!this.#installed) {
      this.#browser.permissions.onRemoved.addListener(this.#permission);
      this.#browser.alarms.onAlarm.addListener(this.#alarm); this.#installed = true;
    }
    return this.restore('recovery');
  }
  async availability() {
    if (!this.#enabled) return {available: false, reason: 'ASSISTANCE_DISABLED'};
    if (!['existingSockets', 'http3', 'serviceWorkers', 'restartCleanup'].every(key => this.#qualified?.[key] === true))
      return {available: false, reason: 'ASSISTANCE_BROWSER_UNQUALIFIED'};
    if (!await this.#browser.permissions.contains(ROUTING_PERMISSION)) return {available: false, reason: 'ASSISTANCE_PERMISSION_REQUIRED'};
    const setting = await this.#browser.proxy.settings.get({incognito: false});
    return direct(setting) ? {available: true} : {available: false, reason: 'ASSISTANCE_PROXY_UNSUPPORTED'};
  }
  activate({signedLease, attemptId, consentVersion}) {
    return this.#serial(async () => {
      check(consentVersion === 1, 'ASSISTANCE_CONSENT_REQUIRED');
      check(!this.#active && !(await this.#browser.storage.local.get(ROUTING_MARKER))[ROUTING_MARKER], 'ASSISTANCE_BUSY');
      const availability = await this.availability(); check(availability.available, availability.reason);
      const lease = await bounded(signal => this.#verifyLease(signedLease, {signal}));
      const pin = this.#pins.find(pin => pin.group === lease.group && pin.egressIpv4 === lease.egressIpv4 && pin.schemaDigest === lease.schemaDigest);
      check(pin && lease.attemptId === attemptId && typeof attemptId === 'string' && /^[a-f0-9-]{36}$/.test(attemptId), 'ASSISTANCE_PIN');
      check(Number.isSafeInteger(lease.expiresAt) && lease.expiresAt > this.#now() && lease.expiresAt - this.#now() <= 120_000
        && /^[a-f0-9]{64}$/.test(lease.credential), 'ASSISTANCE_LEASE');
      const setting = await this.#browser.proxy.settings.get({incognito: false});
      check(direct(setting), 'ASSISTANCE_PROXY_UNSUPPORTED');
      const value = grokPac(pin);
      const descriptor = {version: 1, value, restore: setting.levelOfControl === 'controlled_by_this_extension' ? 'direct' : 'clear'};
      this.#active = {...lease, pin, authRequests: new Set()};
      try {
        this.#browser.webRequest.onAuthRequired.addListener(this.#auth, {urls: ['https://grok.com/*']}, ['asyncBlocking']);
        // Persist before mutation, including the crash window between set() and its reply.
        await this.#browser.storage.local.set({[ROUTING_MARKER]: descriptor});
        await this.#browser.alarms.create(ROUTING_ALARM, {when: lease.expiresAt});
        await this.#browser.proxy.settings.set({value, scope: 'regular'});
        const current = await this.#browser.proxy.settings.get({incognito: false});
        check(current.levelOfControl === 'controlled_by_this_extension' && same(current.value, value), 'ASSISTANCE_ROUTE_REFUSED');
        // The build's qualified, fixed-host probe must observe the actual address.
        // A caller cannot replace this with a claimed IP in a page message.
        check(await bounded(signal => this.#observeRoute(pin, {signal})) === pin.egressIpv4, 'ASSISTANCE_ADDRESS_MISMATCH');
        check(this.#now() < lease.expiresAt, 'ASSISTANCE_EXPIRED');
        return {active: true, expiresAt: lease.expiresAt, egressIpv4: pin.egressIpv4, group: pin.group};
      } catch (error) {await this.#restore('activation-failed'); throw error;}
    });
  }
  restore(reason = 'terminal') {return this.#serial(() => this.#restore(reason));}
  async #restore(reason) {
    this.#active = undefined;
    this.#browser.webRequest?.onAuthRequired?.removeListener(this.#auth);
    const descriptor = (await this.#browser.storage.local.get(ROUTING_MARKER))[ROUTING_MARKER];
    if (!descriptor) {await this.#browser.alarms.clear(ROUTING_ALARM); return {restored: true};}
    try {
      check(descriptor.version === 1 && ['clear', 'direct'].includes(descriptor.restore), 'ASSISTANCE_RECOVERY_RECORD');
      check(this.#pins.some(pin => same(grokPac(pin), descriptor.value)), 'ASSISTANCE_RECOVERY_RECORD');
      const current = await this.#browser.proxy.settings.get({incognito: false});
      if (current.levelOfControl === 'controlled_by_this_extension' && same(current.value, descriptor.value)) {
        if (descriptor.restore === 'direct') await this.#browser.proxy.settings.set({value: {mode: 'direct'}, scope: 'regular'});
        else await this.#browser.proxy.settings.clear({scope: 'regular'});
        const restored = await this.#browser.proxy.settings.get({incognito: false});
        check(direct(restored), 'ASSISTANCE_RESTORATION_FAILED');
      } else {
        // A user/administrator/other extension superseded our value. Never erase it.
        check(!same(current.value, descriptor.value), 'ASSISTANCE_RESTORATION_FAILED');
      }
      await this.#browser.storage.local.remove(ROUTING_MARKER); await this.#browser.alarms.clear(ROUTING_ALARM);
      this.#notify({restored: true, reason}); return {restored: true};
    } catch {
      // Keep the descriptor and retry alarm; recovery remains visibly incomplete.
      await this.#browser.alarms.create(ROUTING_ALARM, {delayInMinutes: 0.5});
      this.#notify({restored: false, reason}); throw Error('ASSISTANCE_RESTORATION_FAILED');
    }
  }
  async disable() {this.#enabled = false; return this.restore('disabled');}
  status() {return {active: Boolean(this.#active), expiresAt: this.#active?.expiresAt ?? null};}
}
