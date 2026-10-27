// Fixed measured application: no parent-supplied roots, routes, clock or keys.
import {readFile} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {performance} from 'node:perf_hooks';
import {startEnclave} from '../enclave-service.mjs';
import {check, exact, hex, random, signingKey, publicKey} from '../wire.mjs';
import {checkTicket, envelopeDigest} from '../protocol.mjs';
import {channelKey, exportChannelKey, SUITE} from '../channel.mjs';
import {initializeNitro,inspectNitroEncoding, quoteBinding} from '../nitro.mjs';
import {createKeyedPseudonymAdapter} from '../kms/identity-adapter.mjs';
import {HARDWARE_PROVIDERS, providerForTicket, hardwareCapability} from '../profile.mjs';
import {clockGuard} from './clock-guard.mjs';
import {CONTEXT, workerIdForCid} from './context.mjs';
import {createFleetMembership} from '../fleet-membership.mjs';
import {DEFAULT_CAPACITY_SELECTION,resourcePolicyFor,checkRuntimeAllocation,observeAllocation,checkCapacitySelection} from '../capacity-policy.mjs';
import {nativeAllocation} from '../capacity-policy.mjs';
import {FULL_RESPONSE,PRIVATE_HEADERS,disclosurePolicy} from '../disclosure-policy.mjs';
const bootId = random();
const cidDocument = await new Promise((resolve,reject)=>execFile('/app/bin/pines-nitro-runtime',['verifier-cid'],
  {timeout:5000,maxBuffer:1024,encoding:'utf8'},(error,value)=>error?reject(Error('WORKER_CID')):resolve(value)));
const cid = JSON.parse(cidDocument); exact(cid,['cid']);
const WORKER_ID = workerIdForCid(cid.cid);
const cfg = JSON.parse(await readFile(new URL('./image-config.json', import.meta.url), 'utf8'));
// Capacity is never sealed: the image carries the validators and,
// optionally, the one public authority key. An image configuration naming capacity refuses to boot.
exact(cfg, ['capabilityVersion', 'profiles', 'apiKey', ...(Object.hasOwn(cfg, 'fleetControllerKey') ? ['fleetControllerKey'] : []), ...(Object.hasOwn(cfg, 'keyedIdentity') ? ['keyedIdentity'] : [])]);
check(cfg.capabilityVersion === 2 && JSON.stringify(cfg.profiles) === JSON.stringify(HARDWARE_PROVIDERS.map(p => p.profile))
  && typeof cfg.apiKey === 'string' && /^[a-f0-9]{64}$/.test(cfg.apiKey)
  && (cfg.fleetControllerKey === undefined || typeof cfg.fleetControllerKey === 'string' && /^[a-f0-9]{64}$/.test(cfg.fleetControllerKey)), 'IMAGE_CONFIGURATION');
// Actual guest resources, read here and independent of any selection.
const [cpuInfo,memoryInfo]=await Promise.all([readFile('/proc/stat','utf8'),readFile('/proc/meminfo','utf8')]);
const observedAllocation=observeAllocation({stat:cpuInfo,meminfo:memoryInfo});
// The pinned controller key is the only capacity authority. Without one, the measured default
// applies at boot and the guest must match it exactly, as the earlier fixed C1 image required.
const authority=cfg.fleetControllerKey;
const fixedPolicy=authority?undefined:resourcePolicyFor(DEFAULT_CAPACITY_SELECTION);
const runtimeAllocation=fixedPolicy?checkRuntimeAllocation(fixedPolicy,observedAllocation):undefined;
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
// No proof admission until the native helper has opened the pinned Sydney key.
check(cfg.keyedIdentity,'KEYED_IDENTITY_REQUIRED');
await initializeNitro(await readFile(new URL('../attestation-wasm/pkg/pines_nitro_validation_bg.wasm',import.meta.url)));
const keyedIdentity=await (await import('../kms/startup.mjs')).startMeasuredIdentity({trust:cfg.keyedIdentity,onTimestamp:guard});
// The same EIF performs the one bootstrap, but never offers proofs in that
// mode. Its wrapped result is already durable at the parent; terminate it under
// the maintenance controller, then boot with a signed runtime document.
if(keyedIdentity.bootstrap){await new Promise(()=>{setInterval(()=>{},1000);});}
check(keyedIdentity.ready&&keyedIdentity.identityEnabled,'KEYED_IDENTITY_REQUIRED');
// Absent in the accepted single-host image. A fleet candidate pins the PUBLIC controller key at build time.
// Its membership exists only after the selection freezes, so every attested identity names it.
const capacity=authority ? {capacitySelection:{async select(document){
  await clockCheck();
  const frozen=await checkCapacitySelection(document,{authorityKey:authority,workerId:WORKER_ID,bootId,observed:observedAllocation,now:Date.now()});
  return {...frozen,membership:await createFleetMembership({workerId:WORKER_ID,bootId,context:CONTEXT,resourcePolicy:frozen.resourcePolicy,
    capacitySelectionHash:frozen.selectionHash,controllerKey:authority,clockCheck,issueQuote:async binding=>hex((await issue(binding)).bytes)})};
}}} : {resourcePolicy:fixedPolicy};
const server = await startEnclave({port:18000,controlPort:18010,...capacity,metrics:true,
  health:{workerId:WORKER_ID,bootId,context:CONTEXT,capability:hardwareCapability(),capacityAuthority:authority?'fleet-controller':'none',
    observedAllocation,...(runtimeAllocation?{runtimeAllocation}:{}),...(keyedIdentity?{keyedIdentity:keyedIdentity.health}:{})},

  apiKey: cfg.apiKey, hardware: true, retainOutbox: true, binary: '/app/bin/tee-hardware',
  identityAdapter:createKeyedPseudonymAdapter({handle:keyedIdentity.handle}),
  identityMetrics:()=>keyedIdentity.handle.metrics(),
  beforeNative:clockCheck,beforeReceipt:clockCheck,
  async createOffer(ticket, {probe=false,resourcePolicy:bootPolicy}={}) {
    check(keyedIdentity.ready,'KEYED_IDENTITY_REQUIRED');
    const provider = providerForTicket(ticket?.body); check(provider, 'PROFILE');
    await checkTicket(ticket, cfg.apiKey, provider.profile);
    check(ticket.body.workerId === WORKER_ID && ticket.body.bootId === bootId, 'WORKER_CONTEXT');
    // A signed diagnostic ticket may obtain a fresh quote before provider
    // qualification. /probe never stores a session and cannot start TLSN or
    // contact the provider. Actual offers still require the reviewed inventory.
    check(probe || provider.inventory.qualified === true, 'PROVIDER_INVENTORY_UNQUALIFIED');
    const channel = await channelKey(), receipt = await signingKey();
    // This image serves the full-response class or the private-headers class, never the
    // legacy redacted one, and only the class this boot was frozen on: a ticket signed for
    // the other class is refused before any offer, quote or native work (the service
    // already refused it at /offer; this is the application's own, independent check).
    const disclosure=disclosurePolicy(ticket.body.disclosurePolicy);
    check(disclosure===FULL_RESPONSE||disclosure===PRIVATE_HEADERS,'FULL_RESPONSE_REQUIRED');
    nativeAllocation(bootPolicy??fixedPolicy,disclosure);
    const body = {profile: provider.profile, workerId: WORKER_ID, bootId, identity:keyedIdentity.identity, ticketHash: await envelopeDigest(ticket), session: random(),
      channelKey: await exportChannelKey(channel.publicKey), receiptKey: await publicKey(receipt.publicKey),
      suite: SUITE, measurement: '0'.repeat(96), issuedAt: Date.now()};
    const initial = await issue(await quoteBinding(ticket, body));
    body.measurement = initial.pcr; body.issuedAt = Date.now();
    const bound = await issue(await quoteBinding(ticket, body));
    check(bound.pcr === body.measurement, 'MEASUREMENT');
    return {offer: {body, evidence: {cose: hex(bound.bytes)}}, channel, receipt};
  }});
let checking=false,stopping=false;
async function stop(){if(stopping)return;stopping=true;clearInterval(timer);await server.shutdown();keyedIdentity?.destroy();process.exit(0);}
const timer=setInterval(()=>{if(checking||stopping)return;checking=true;void clockCheck().then(()=>check(keyedIdentity.ready,'KEYED_IDENTITY_REQUIRED')).catch(stop).finally(()=>{checking=false;});},1000);
for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => {void stop();});
