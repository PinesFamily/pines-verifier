import {GrokRouting} from './grok-routing.mjs';
import {verifyLease} from '../../../tools/grok-cloudflare/lease.mjs';
import {GrokClearance} from './grok-clearance.mjs';
const check = (value, code) => {if (!value) throw Error(code);};
export class GrokAssistance {
  #config; #fetch; #routing; #clearance; #state; #busy; #epoch = 0; #timer; #lost;
  constructor({config, browser, fetch = globalThis.fetch, onLost = () => {}}) {
    // Browser fetch requires Window/WorkerGlobalScope as its receiver. Calling
    // an unbound native fetch through a private field uses this controller.
    this.#config = config; this.#fetch = fetch.bind(globalThis); this.#lost = onLost;
    this.#clearance = new GrokClearance(browser);
    const c = config.grokAssistance;
    this.#routing = new GrokRouting({browser, pins: c ? [c.pin] : [], enabled: c?.enabled === true,
      qualification: c?.qualification,
      verifyLease: signed => verifyLease(signed, {apiKey: c.tee.apiKey, attemptId: this.#state?.attempt.attemptId, pin: c.pin}),
      observeRoute: async (pin, {signal}) => {
        const response = await this.#fetch('https://grok.com/cdn-cgi/trace', {credentials: 'omit', cache: 'no-store', redirect: 'error', signal});
        check(response.ok, 'ASSISTANCE_ADDRESS_MISMATCH');
        const bytes = await this.#read(response, 4096), matches = bytes.match(/^ip=([^\r\n]+)$/gm) ?? [];
        check(matches.length === 1, 'ASSISTANCE_ADDRESS_MISMATCH'); return matches[0].slice(3);
      },
      onRestoration: event => {
        this.#clearance.stop();
        if (!event.restored || this.#state && ['timeout','permission-change'].includes(event.reason))
          void this.#lost(event.restored ? 'ASSISTANCE_ENDED' : 'ASSISTANCE_RESTORATION_FAILED');
      }});
  }
  initialize() {return this.#routing.initialize();}
  supported(userAgent = globalThis.navigator?.userAgent ?? '') {
    const c = this.#config.grokAssistance, major = Number(/Chrome\/(\d+)\./.exec(userAgent)?.[1]);
    return c?.enabled === true && c.qualification?.chromeMajors?.includes(major)
      && ['existingSockets','http3','serviceWorkers','restartCleanup','desktopTransport'].every(k => c.qualification[k] === true);
  }
  async #read(response, limit = 16384) {
    const reader = response.body.getReader(); let bytes = new Uint8Array();
    try {
      for (;;) {const {value, done} = await reader.read(); if (done) break;
        check(bytes.length + value.length <= limit, 'ASSISTANCE_RESPONSE_LIMIT');
        const next = new Uint8Array(bytes.length + value.length); next.set(bytes); next.set(value, bytes.length); bytes = next;}
      return new TextDecoder().decode(bytes);
    } finally {await reader.cancel().catch(() => {}); reader.releaseLock();}
  }
  async #request(path, body, attempt) {
    const response = await this.#fetch(new URL(this.#config.tee.api).origin + path, {method: 'POST', credentials: 'omit', redirect: 'error', cache: 'no-store',
      headers: {'content-type': 'application/json', ...(attempt ? {authorization: 'Bearer ' + attempt.ticket} : {})},
      body: JSON.stringify(body), signal: AbortSignal.timeout(10_000)});
    check(response.ok, 'ASSISTANCE_UNAVAILABLE'); return JSON.parse(await this.#read(response));
  }
  async reserve({runId, recipient, schema, onReserved}) {
    check(this.supported() && !this.#busy && !this.#state, 'ASSISTANCE_UNAVAILABLE');
    this.#busy = true; const epoch = ++this.#epoch;
    try {
      const availability = await this.#routing.availability(); check(availability.available, availability.reason);
      const attempt = await this.#request('/verification-attempts', {recipient, schema, routing: 'pinned'});
      this.#state = {attempt, runId, recipient};
      check(epoch === this.#epoch, 'ASSISTANCE_CANCELLED');
      await onReserved(attempt);
      const {lease} = await this.#request('/tee/grok-assistance/lease', {attemptId: attempt.attemptId}, attempt);
      check(epoch === this.#epoch, 'ASSISTANCE_CANCELLED');
      const active = await this.#routing.activate({signedLease: lease, attemptId: attempt.attemptId, consentVersion: 1});
      check(epoch === this.#epoch, 'ASSISTANCE_CANCELLED');
      this.#state.expiresAt = active.expiresAt;
      this.#clearance.start();
      const poll = async () => {
        if (epoch !== this.#epoch) return;
        try {if (await this.check(runId, true) === 'settled') {await this.finish({delivered: true}); return;}}
        catch {void this.#lost('ASSISTANCE_ENDED'); return;}
        if (epoch === this.#epoch) this.#timer = setTimeout(poll, 3000);
      };
      this.#timer = setTimeout(poll, 3000); return {attempt, expiresAt: active.expiresAt};
    } catch (error) {await this.finish().catch(() => {}); throw error;}
    finally {this.#busy = false;}
  }
  attempt(runId) {return this.#state?.runId === runId ? this.#state.attempt : undefined;}
  validateReplay(runId, replay) {
    check(this.#state?.runId === runId && this.#routing.status().active && Date.now() < this.#state.expiresAt, 'ASSISTANCE_ENDED');
    if (this.#config.grokAssistance.tee.generation === 'grok-email-20261026') return this.#clearance.optional(replay);
    this.#clearance.validate(replay); return replay;
  }
  async check(runId, allowSettled = false) {
    const state = this.#state;
    check(state?.runId === runId && this.#routing.status().active && Date.now() < state.expiresAt, 'ASSISTANCE_ENDED');
    const checked = await this.#request('/tee/grok-assistance/check', {attemptId: state.attempt.attemptId}, state.attempt);
    if (allowSettled && checked.active === false && checked.settled === true && this.#state === state) return 'settled';
    check(checked.active && checked.group === this.#config.grokAssistance.pin.group
      && checked.egressIpv4 === this.#config.grokAssistance.pin.egressIpv4 && checked.expiresAt === state.expiresAt
      && this.#state === state, 'ASSISTANCE_ENDED');
  }
  async finish({delivered = false} = {}) {
    ++this.#epoch; clearTimeout(this.#timer); const state = this.#state; this.#state = undefined;
    this.#clearance.stop();
    // Restore locally even if the identity or relay cannot be reached.
    try {return await this.#routing.restore('terminal');}
    finally {if (state) {
      await this.#request('/tee/grok-assistance/release', {attemptId: state.attempt.attemptId}, state.attempt).catch(() => {});
      if (!delivered) await this.#request('/verification-attempts/' + state.attempt.attemptId + '/cancel', {reason: 'ASSISTANCE_ENDED'}).catch(() => {});
    }}
  }
  async recover(job) {
    await this.initialize();
    if (job?.assisted && job.phase !== 'completed' && /^[a-f0-9-]{36}$/.test(job.assistedAttemptId ?? ''))
      await this.#request('/verification-attempts/' + job.assistedAttemptId + '/cancel', {reason: 'ASSISTANCE_ENDED'}).catch(() => {});
  }
}
