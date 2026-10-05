// Fixed measured application: no parent-supplied roots, routes, clock or keys.
import {readFile} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {performance} from 'node:perf_hooks';
import {startEnclave} from '../enclave-service.mjs';
import {check, hex, random, signingKey, publicKey} from '../wire.mjs';
import {checkTicket, envelopeDigest} from '../protocol.mjs';
import {channelKey, exportChannelKey, SUITE} from '../channel.mjs';
import {inspectNitroEncoding, quoteBinding} from '../nitro.mjs';
import {HARDWARE_PROVIDERS, providerForTicket, hardwareCapability} from '../profile.mjs';
import {clockGuard} from './clock-guard.mjs';
import {CONTEXT, WORKER_ID} from './context.mjs';
const bootId = random();
const cfg = JSON.parse(await readFile(new URL('./image-config.json', import.meta.url), 'utf8'));
check(cfg.capabilityVersion === 2 && JSON.stringify(cfg.profiles) === JSON.stringify(HARDWARE_PROVIDERS.map(p => p.profile))
  && typeof cfg.apiKey === 'string' && /^[a-f0-9]{64}$/.test(cfg.apiKey), 'IMAGE_CONFIGURATION');
const guard=clockGuard(()=>Date.now(),()=>performance.now());
async function clockCheck(){
  const value=await new Promise((resolve,reject)=>execFile('/app/bin/pines-nitro-runtime',['time'],{timeout:5000,maxBuffer:1024,encoding:'utf8'},(e,out)=>e?reject(Error('CLOCK_PROVENANCE')):resolve(out)));
  guard(JSON.parse(value).timestamp);
}
async function issue(binding) {
  const input = JSON.stringify(Object.fromEntries([['public_key', binding.publicKey], ['nonce', binding.nonce], ['user_data', binding.userData]].map(([k,v]) => [k, Buffer.from(v).toString('base64')])));
  const document = await new Promise((resolve,reject) => {
    const child = execFile('/app/bin/pines-nitro-runtime', ['attest'], {timeout: 5000, maxBuffer: 32768, encoding: 'utf8'}, (error, stdout) => error ? reject(Error('NSM_REFUSED')) : resolve(Buffer.from(stdout.trim(), 'base64')));
    child.stdin.end(input);
  });
  let parsed;
  try{parsed=inspectNitroEncoding(new Uint8Array(document));}
  catch(error){
    // Public NSM document only. /probe may return it for parser diagnostics;
    // /offer never returns this field and all acceptance checks still fail.
    error.publicQuote=hex(document);throw error;
  }
  guard(parsed.get('timestamp'));
  const pcr = parsed.get('pcrs').get(0); check(pcr?.some(b => b !== 0), 'DEBUG_MEASUREMENT');
  return {bytes: document, pcr: hex(pcr)};
}
await clockCheck();
const server = await startEnclave({port: 18000, health: {workerId: WORKER_ID, bootId, context: CONTEXT, capability: hardwareCapability()}, apiKey: cfg.apiKey, hardware: true, retainOutbox: true, binary: '/app/bin/tee-hardware',
  beforeNative:clockCheck,beforeReceipt:clockCheck,
  async createOffer(ticket, {probe=false}={}) {
    const provider = providerForTicket(ticket?.body); check(provider, 'PROFILE');
    await checkTicket(ticket, cfg.apiKey, provider.profile);
    check(ticket.body.workerId === WORKER_ID && ticket.body.bootId === bootId, 'WORKER_CONTEXT');
    // A signed diagnostic ticket may obtain a fresh quote before provider
    // qualification. /probe never stores a session and cannot start TLSN or
    // contact the provider. Actual offers still require the reviewed inventory.
    check(probe || provider.inventory.qualified === true, 'PROVIDER_INVENTORY_UNQUALIFIED');
    const channel = await channelKey(), receipt = await signingKey();
    const body = {profile: provider.profile, workerId: WORKER_ID, bootId, ticketHash: await envelopeDigest(ticket), session: random(),
      channelKey: await exportChannelKey(channel.publicKey), receiptKey: await publicKey(receipt.publicKey),
      suite: SUITE, measurement: '0'.repeat(96), issuedAt: Date.now()};
    const initial = await issue(await quoteBinding(ticket, body));
    body.measurement = initial.pcr; body.issuedAt = Date.now();
    const bound = await issue(await quoteBinding(ticket, body));
    check(bound.pcr === body.measurement, 'MEASUREMENT');
    return {offer: {body, evidence: {cose: hex(bound.bytes)}}, channel, receipt};
  }});
let checking=false,stopping=false;
async function stop(){if(stopping)return;stopping=true;clearInterval(timer);await server.shutdown();process.exit(0);}
const timer=setInterval(()=>{if(checking||stopping)return;checking=true;void clockCheck().catch(stop).finally(()=>{checking=false;});},1000);
for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => {void stop();});
