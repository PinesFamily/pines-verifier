import {spawn} from 'node:child_process';
import {check} from './wire.mjs';
import {evaluateAuthenticated, evaluateAuthenticatedForProvider, HARDWARE_PROVIDERS} from './profile.mjs';
import {existsSync} from 'node:fs';

export async function startNative(config, baseline = false) {
  const hardware = config.hardware === true;
  check(hardware ? existsSync('/dev/nsm') && config.binary === '/app/bin/tee-hardware' : /^127\.0\.0\.1:\d+$/.test(config.origin), 'NATIVE_SCOPE');
  if (hardware) check(HARDWARE_PROVIDERS.includes(config.provider) && config.provider.inventory.qualified === true, 'PROVIDER_INVENTORY_UNQUALIFIED');
  const child = spawn(config.binary, hardware ? [config.provider.id] : [config.origin, config.root, String(config.records ?? 1024)], {stdio: ['ignore', 'pipe', 'pipe'], env: {PATH: process.env.PATH}});
  let buffer = '', readyResolve, resultResolve, settled = false;
  const ready = new Promise(r => {readyResolve = r;});
  const result = new Promise(r => {resultResolve = r;});
  const done = data => {if (!settled) {settled = true; resultResolve(data);}};
  const exited = new Promise(r => child.once('close', r));
  const readinessTimer=setTimeout(()=>{readyResolve(null);done({type:'refused',code:'NATIVE_START_TIMEOUT'});},5000);
  child.stdout.on('data', async b => {
    buffer += b;
    if (buffer.length > 256 * 1024) {child.kill(); done({type: 'refused', code: 'IPC_LIMIT'}); return;}
    while (buffer.includes('\n')) {
      const at = buffer.indexOf('\n'), line = buffer.slice(0, at); buffer = buffer.slice(at + 1);
      try {
        const data = JSON.parse(line);
        if (data.type === 'listening') {readyResolve(data.port); continue;}
        if (data.type !== 'verified') {done({type: 'refused', code: 'PROTOCOL_REFUSED'}); continue;}
        const sent = new Uint8Array(Buffer.from(data.sent, 'base64')), recv = new Uint8Array(Buffer.from(data.recv, 'base64'));
        try {
          // These plaintext bytes exist only in this private evaluator process.
          const facts = hardware ? await evaluateAuthenticatedForProvider(config.provider, {...data, sent, recv}, config.wallet)
            : await evaluateAuthenticated({...data, sent, recv}, baseline);
          const credentialCanaryAbsent = !Buffer.from(sent).includes('Bearer AAAAAAAA') && !Buffer.from(recv).includes('SET-COOKIE-CANARY');
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
  // No native error excerpts or transcript strings escape this process.
  child.stderr.resume();
  child.once('error', () => {readyResolve(null); done({type: 'refused', code: 'NATIVE_START'});});
  child.once('exit', () => {readyResolve(null); setTimeout(() => done({type: 'refused', code: 'NATIVE_EXIT'}), 200);});
  const stop = async () => {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
      let timer;
      await Promise.race([exited, new Promise(r => {timer = setTimeout(r, 2000);})]); clearTimeout(timer);
      if (child.exitCode === null && child.signalCode === null) {child.kill('SIGKILL'); await exited;}
    }
    buffer = '';
  };
  const port = await ready;clearTimeout(readinessTimer);if(!port){await stop();throw Error('NATIVE_START');}
  return {port, result, stop, pid: child.pid};
}
