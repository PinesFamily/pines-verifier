import {spawn} from 'node:child_process';
import {check,random} from './wire.mjs';
import {evaluateAuthenticated, evaluateAuthenticatedForProvider, ALL_PROVIDERS} from './profile.mjs';
import {existsSync} from 'node:fs';
import {SESSION_BUDGET_MIN_MS, SESSION_BUDGET_MAX_MS} from './session-policy.mjs';
import {DEFAULT_RESOURCE_POLICY,nativeAllocation} from './capacity-policy.mjs';
import {disclosurePolicy} from './disclosure-policy.mjs';
import {nativeStageCode} from './session-diagnostics.mjs';

// The frozen policy's nativeMemoryMiB is the only source of the
// per-process budget. The measured launcher installs exactly this value as hard RLIMIT_AS.
// A provider object of either class is admitted when its inventory is qualified; the ticket's signed policy already
// bound it to this boot's class (createOffer). The full-response-only check refused every private-headers session.
export const nativeProviderAdmitted = provider => ALL_PROVIDERS.includes(provider) && provider.inventory.qualified === true;

export function nativeLaunchArguments({providerId, deadline, sessionBudgetMs, resourcePolicy, disclosure, connectionToken}) {
  const allocation=nativeAllocation(resourcePolicy,disclosure);
  check(typeof providerId==='string' && /^[a-f0-9]{64}$/.test(connectionToken ?? ''), 'NATIVE_SCOPE');
  return ['native',providerId,String(deadline),String(sessionBudgetMs),String(allocation.nativeMemoryMiB),connectionToken,allocation.disclosurePolicy];
}

export async function startNative(config, baseline = false) {
  const hardware = config.hardware === true;
  check(hardware ? existsSync('/dev/nsm') && config.binary === '/app/bin/tee-hardware' : /^127\.0\.0\.1:\d+$/.test(config.origin), 'NATIVE_SCOPE');
  if (hardware) {
    check(nativeProviderAdmitted(config.provider), 'PROVIDER_INVENTORY_UNQUALIFIED');
    check(Number.isSafeInteger(config.sessionBudgetMs) && config.sessionBudgetMs >= SESSION_BUDGET_MIN_MS
      && config.sessionBudgetMs <= SESSION_BUDGET_MAX_MS && Number.isSafeInteger(config.deadline)
      && config.deadline > Date.now() && config.deadline - Date.now() <= config.sessionBudgetMs, 'SESSION_DEADLINE');
  }
  // The signed ticket's policy (absent: legacy redacted). The client never
  // selects it; the measured launcher re-checks it against the cap.
  const disclosure=disclosurePolicy(config.disclosurePolicy);
  nativeAllocation(config.resourcePolicy??DEFAULT_RESOURCE_POLICY,disclosure);
  const connectionToken=hardware?random():undefined;
  // The measured launcher sets exactly the frozen boot's RLIMIT_AS before exec.
  const child = spawn(hardware?'/app/bin/pines-nitro-runtime':config.binary,
    hardware ? nativeLaunchArguments({providerId:config.provider.id,deadline:config.deadline,sessionBudgetMs:config.sessionBudgetMs,
      resourcePolicy:config.resourcePolicy??DEFAULT_RESOURCE_POLICY,disclosure,connectionToken})
      : [config.origin, config.root, String(config.records ?? 1024),...(config.fixtureProvider?[disclosure.id,config.fixtureProvider]:[])],
    {stdio: ['ignore', 'pipe', 'pipe'], env: {PATH: process.env.PATH,MALLOC_ARENA_MAX:'2',RAYON_NUM_THREADS:'1'}});
  if(Number.isSafeInteger(child.pid)){
    config.onNativeSpawn?.(child.pid);
    child.once('close',()=>config.onNativeExit?.(child.pid));
  }
  let buffer = '', readyResolve, resultResolve, settled = false, stdoutWork=Promise.resolve(), stopping, stopEvaluation;
  const EVALUATION_STOPPED=Symbol('evaluation-stopped');
  const evaluationStopped=new Promise(resolve=>{stopEvaluation=resolve;});
  const ready = new Promise(r => {readyResolve = r;});
  const result = new Promise(r => {resultResolve = r;});
  const done = data => {if (!settled) {settled = true; resultResolve(data);}};
  const exited = new Promise(r => child.once('close', r));
  const readinessTimer=setTimeout(()=>{readyResolve(null);done({type:'refused',code:'NATIVE_START_TIMEOUT'});},5000);
  child.stdout.on('data', b => {
    buffer += b;
    if (buffer.length > 256 * 1024) {child.kill(); done({type: 'refused', code: 'IPC_LIMIT'}); return;}
    // stdout callbacks may overlap an asynchronous evaluator. Preserve their
    // order, and let process close wait for all output already received.
    stdoutWork=stdoutWork.then(async()=>{
    while (buffer.includes('\n') && !settled) {
      const at = buffer.indexOf('\n'), line = buffer.slice(0, at); buffer = buffer.slice(at + 1);
      let data;
      try {data=JSON.parse(line);}
      catch {done({type:'refused',code:'IPC_PARSE_REFUSED'});continue;}
      try {
        if (data?.type === 'listening') {readyResolve(data.port); continue;}
        if (data?.type !== 'verified') {done({type: 'refused', code: nativeStageCode(data?.code)}); continue;}
        if(data.processPeaks){
          check(Object.keys(data.processPeaks).length===2&&['peakRssBytes','peakVirtualBytes'].every(k=>
            Number.isSafeInteger(data.processPeaks[k])&&data.processPeaks[k]>0&&data.processPeaks[k]<=4096*1024**2),'NATIVE_METRICS');
          config.onNativePeaks?.(data.processPeaks);
        }
        const sent = new Uint8Array(Buffer.from(data.sent, 'base64')), recv = new Uint8Array(Buffer.from(data.recv, 'base64'));
        try {
          // These plaintext bytes exist only in this private evaluator process.
          const evaluating = hardware ? evaluateAuthenticatedForProvider(config.provider, {...data, sent, recv}, config.wallet, disclosure, config.identityAdapter)
            : evaluateAuthenticated({...data, sent, recv}, baseline);
          const facts=await Promise.race([evaluating,evaluationStopped]);
          if(facts===EVALUATION_STOPPED)continue;
          const credentialCanaryAbsent = !Buffer.from(sent).includes('Bearer AAAAAAAA')
            && (disclosure.response === 'complete' || !Buffer.from(recv).includes('SET-COOKIE-CANARY'));
          check(credentialCanaryAbsent, 'CREDENTIAL_LEAK');
          const diagnostic = {credentialCanaryAbsent,
            accountCanaryPresent: Buffer.from(recv).includes('user-Ab9Ab9Ab9Ab9Ab9Ab9Ab9Ab9'),
            unrelatedFieldPresent: Buffer.from(recv).includes('account-detail-canary@example.test')};
          if (!hardware) check(diagnostic.accountCanaryPresent && diagnostic.unrelatedFieldPresent, 'SYNTHETIC_DISCLOSURE_INCOMPLETE');
          done({type: 'verified', facts, diagnostic,
          nativeTiming: {onlineMs: data.onlineMs, finalizationMs: data.finalizationMs}});
        } finally {sent.fill(0); recv.fill(0);}
      } catch {done({type: 'refused', code: 'EVALUATION_REFUSED'});}
    }
    });
  });
  // No native error excerpts or transcript strings escape this process.
  child.stderr.resume();
  child.once('error', () => {readyResolve(null); done({type: 'refused', code: 'NATIVE_START'});});
  child.once('close', () => {
    // 'close' follows stdout closure, unlike 'exit'. A completed verifier can
    // still have a valid output under evaluation; a timer is not its result.
    void stdoutWork.then(()=>{readyResolve(null);done({type:'refused',code:buffer.length?'IPC_PARSE_REFUSED':'NATIVE_EXIT'});});
  });
  const stop = () => {
    if(stopping)return stopping;
    // Cancellation settles result waits immediately, but stop itself still waits
    // for physical process close. A late evaluator cannot create acceptance.
    done({type:'refused',code:'NATIVE_STOPPED'});stopEvaluation(EVALUATION_STOPPED);
    stopping=(async()=>{
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
      let timer;
      await Promise.race([exited, new Promise(r => {timer = setTimeout(r, 2000);})]); clearTimeout(timer);
      if (child.exitCode === null && child.signalCode === null) {child.kill('SIGKILL'); await exited;}
    }
    // exitCode can be set before stdio is closed. Retirement must await both
    // the actual close event and the now-cancelled stdout/evaluator callbacks.
    await exited;await stdoutWork;
    buffer = '';
    })();
    return stopping;
  };
  const port = await ready;clearTimeout(readinessTimer);if(!port){await stop();throw Error('NATIVE_START');}
  return {port, result, stop, pid: child.pid,connectionToken};
}
