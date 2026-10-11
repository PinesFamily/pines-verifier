// Pines adaptation of the maintained fork's offscreen ProveManager lifecycle.
// Each run owns one worker, keeping cancellation/restart from reusing WASM state.
import {check, terminal} from './policy.js';
import {UPFRONT_CONSENT_VERSION} from './preparation.js';
import {sessionSnapshot} from './session-timing.js';
import {validateReplayMetadata} from './replay-metadata.mjs';
import {metadataPersistenceFailureCode} from './qualification-metadata-channel.mjs';

// The verifier's own evaluated values for the review rows: a few short strings (or string lists) by field id.
const reviewFields = fields => fields !== null && typeof fields === 'object' && !Array.isArray(fields) && Object.keys(fields).length <= 16
  && Object.entries(fields).every(([id, value]) => /^[a-z][a-z0-9_]{0,63}$/.test(id) && (typeof value === 'string' ? value.length <= 256
    : Array.isArray(value) && value.length <= 32 && value.every(entry => typeof entry === 'string' && entry.length <= 64)));

export class ProveManager {
  #teeProviders;
  #worker;
  #timer;
  #job;
  #changed;
  #replayMetadata;
  constructor(changed, {teeProviders = null,replayMetadata = null} = {}) { this.#changed = changed; this.#teeProviders = teeProviders; this.#replayMetadata=replayMetadata; }
  start({runId, attempt, recipient, deadline, verifierOrigin, tee = false, upfrontConsent, replay}) {
    this.#expire();
    check(!this.#job || terminal(this.#job.phase), 'BUSY');
    // Native builds cannot fall back to the ordinary disclosure worker. The
    // selected provider is immutable for this run and resolved before spawning.
    check(!this.#teeProviders || tee === true, 'SCHEMA_UNAVAILABLE');
    const provider = tee ? this.#teeProviders?.find(entry => entry.policy?.admissionEnabled
      && ['schemaId', 'version', 'digest'].every(key => entry.reference[key] === attempt?.schema?.[key])) : null;
    check(!tee || provider, 'SCHEMA_UNAVAILABLE');
    if (tee) check(upfrontConsent === UPFRONT_CONSENT_VERSION && replay, 'CONSENT_REQUIRED');
    if (tee) check(deadline === sessionSnapshot(attempt).sessionExpiresAt, 'SESSION_POLICY_INVALID');
    check(Number.isSafeInteger(deadline) && deadline > Date.now(), 'PROOF_TIMEOUT');
    // Use both clocks: a wall-clock rollback must not buy extra review/proof
    // time, and a throttled timer cannot approve after the signed deadline.
    const remaining = Math.min(deadline - Date.now(), tee ? attempt.sessionBudgetMs : Infinity);
    this.#job = {runId, deadline, monotonicDeadline: performance.now() + remaining, phase: 'initializing', error: null};
    const worker = new Worker(new URL(tee ? './tee-worker.js' : './prove-worker.js', import.meta.url), {type: 'module'});
    this.#worker = worker;
    const finish = (phase, error) => { if (this.#worker !== worker || this.#job?.runId !== runId || terminal(this.#job.phase)) return; this.#job.phase = phase; this.#job.error = error ?? null; this.#stop(); this.#changed(this.status()); };
    worker.onerror = () => finish('failed', 'WORKER_FAILED');
    worker.onmessage = ({data}) => {
      if(data.type==='replay-metadata'){
        if(this.#worker!==worker||data.runId!==runId||!tee||!this.#replayMetadata)return;
        const ack=(ok,error)=>{if(this.#worker===worker)worker.postMessage({type:'replay-metadata-ack',runId,requestId:data.requestId,ok,...(error?{error}:{})});};
        let record;
        try{
          record=validateReplayMetadata(data.record);
          check(record.runId===runId&&record.attemptId===attempt.attemptId,'STALE_RUN');
        }catch{ack(false,'REPLAY_METADATA_RECORD_REFUSED');return;}
        try{
          Promise.resolve(this.#replayMetadata(record)).then(()=>ack(true),error=>ack(false,metadataPersistenceFailureCode(error?.message)??'REPLAY_METADATA_PERSIST_FAILED'));
        }catch(error){ack(false,metadataPersistenceFailureCode(error?.message)??'REPLAY_METADATA_PERSIST_FAILED');}
        return;
      }
      this.#expire();
      if (this.#worker !== worker || data.runId !== runId || !['initializing', 'awaiting-capture', 'requesting', 'awaiting-disclosure', 'proving', 'completed', 'failed'].includes(data.phase)) return;
      if (tee && data.phase === 'awaiting-disclosure') {finish('failed', 'CONSENT_REQUIRED'); return;}
      this.#job.phase = data.phase;
      this.#job.error = /^[A-Z_0-9]{1,64}$/.test(data.error) ? data.error : null;
      if (tee && data.phase === 'proving') {
        delete this.#job.preview;
        if (provider.publicPlanValues.includes(data.preview?.plan)) this.#job.preview = {tee: true, plan: data.preview.plan};
      }
      if (!tee && data.phase === 'awaiting-disclosure' && typeof data.preview?.request === 'string' && typeof data.preview?.response === 'string' && data.preview.request.length <= 8192 && data.preview.response.length <= 65536) {
        const {fields, ...preview} = data.preview;
        this.#job.preview = reviewFields(fields) ? {...preview, fields} : preview;
      }
      if (terminal(data.phase)) this.#stop();
      this.#changed(this.status());
    };
    this.#timer = setTimeout(() => finish('failed', 'PROOF_TIMEOUT'), Math.max(1, remaining));
    worker.postMessage({type: 'start', runId, attempt, recipient, verifierOrigin, ...(tee ? {upfrontConsent, replay} : {})});
    return this.status();
  }
  status(preview = false) { this.#expire(); return this.#job ? {runId: this.#job.runId, phase: this.#job.phase, error: this.#job.error, ...(preview && this.#job.preview ? {preview: this.#job.preview} : {})} : null; }
  replay(runId, replay) {
    this.#expire(); check(this.#job?.runId === runId && this.#job.phase === 'awaiting-capture', 'STALE_RUN');
    this.#job.phase = 'initializing';
    this.#worker.postMessage({type: 'replay', runId, replay});
    return this.status();
  }
  approve(runId) { this.#expire(); check(this.#job?.runId === runId && this.#job.phase === 'awaiting-disclosure' && this.#job.preview, 'STALE_RUN'); this.#job.phase = 'proving'; delete this.#job.preview; this.#worker.postMessage({type: 'approve', runId}); return this.status(); }
  cancel(runId) { check(this.#job?.runId === runId, 'STALE_RUN'); if (!terminal(this.#job.phase)) { this.#job.phase = 'cancelled'; this.#stop(); this.#changed(this.status()); } return this.status(); }
  #expire() {
    if (this.#job && !terminal(this.#job.phase) && (Date.now() >= this.#job.deadline || performance.now() >= this.#job.monotonicDeadline)) {
      this.#job.phase = 'failed'; this.#job.error = 'PROOF_TIMEOUT'; this.#stop();
    }
  }
  #stop() { clearTimeout(this.#timer); this.#worker?.terminate(); this.#worker = undefined; if (this.#job) delete this.#job.preview; }
}
