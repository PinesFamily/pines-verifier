// Upfront consent preparation. This object must never enter storage or a page
// message. Only the trusted background controller can consume its private replay.
import {check, owns} from './policy.js';
export const UPFRONT_CONSENT_VERSION = 2;
export const PREPARATION_MS = 120000;
export const PREPARATION_FRESH_MS = 60000;
const sameSchema = (a, b) => ['schemaId', 'version', 'digest'].every(key => a?.[key] === b?.[key]);
export class Preparation {
  #context; #replay; #expires; #monotonicExpires; #approved = false; #claim; #used = false; #now; #monotonic;
  constructor(context, {now = () => Date.now(), monotonic = () => performance.now()} = {}) {
    this.#context = structuredClone(context); this.#now = now; this.#monotonic = monotonic;
    this.#expires = Math.min(context.deadline, now() + PREPARATION_MS);
    this.#monotonicExpires = monotonic() + Math.min(PREPARATION_MS, this.#expires - now());
  }
  #valid(context) {
    check(!this.#used && this.#now() < this.#expires && this.#monotonic() < this.#monotonicExpires, 'PREPARATION_EXPIRED');
    check(context.runId === this.#context.runId && owns(context.owner, this.#context.owner)
      && context.recipient === this.#context.recipient && sameSchema(context.schema, this.#context.schema), 'STALE_RUN');
  }
  captured(context, replay) {
    this.#valid(context); check(!this.#replay && !this.#approved, 'STALE_RUN');
    this.#replay = replay;
    this.#expires = Math.min(this.#expires, this.#now() + PREPARATION_FRESH_MS);
    this.#monotonicExpires = Math.min(this.#monotonicExpires, this.#monotonic() + PREPARATION_FRESH_MS);
  }
  validate(context) {this.#valid(context); return true;}
  approve(context) {this.#valid(context); check(this.#replay && !this.#approved, 'CONSENT_REQUIRED'); this.#approved = true;}
  claim(context) {
    this.#valid(context); check(this.#approved && this.#replay && !this.#claim, 'CONSENT_REQUIRED');
    this.#claim = crypto.randomUUID(); return this.#claim;
  }
  take(context, executionId) {
    this.#valid(context); check(this.#approved && this.#claim && executionId === this.#claim && this.#replay, 'CONSENT_REQUIRED');
    const replay = this.#replay; this.cancel(); return replay;
  }
  cancel() {this.#used = true; this.#replay = undefined; this.#claim = undefined;}
}
