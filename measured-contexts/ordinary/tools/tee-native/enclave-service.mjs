import {createServer} from 'node:http';
import {WebSocket, WebSocketServer} from 'ws';
import {check, decode, encode, exact, verify, digest} from './wire.mjs';
import {channelBinding, checkGrant, makeReceipt, makeTerminal} from './protocol.mjs';
import {FRAME, MAX_FRAME, receiver, sender} from './channel.mjs';
import {startNative} from './native.mjs';
import {providerForTicket} from './profile.mjs';
import {DEFAULT_RESOURCE_POLICY,CAPACITY_ENVELOPE,validateResourcePolicy,nativeAllocation} from './capacity-policy.mjs';
import {startRuntimeMetrics} from './runtime-metrics.mjs';
import {sessionDiagnostics} from './session-diagnostics.mjs';
import {encodeInputCredit} from './input-flow-control.mjs';
import {accountConfirmationMessage} from './identity-binding.mjs';

// A send callback marks retirement from this socket's write queue, not native
// verification. Cancellation must settle the waiter even if the callback never
// arrives, and late callbacks must not revive a closed session.
export function sendSocket(socket, bytes, signal) {
  return new Promise((resolve, reject) => {
    let settled=false;
    const finish=error=>{
      if(settled)return;settled=true;
      signal.removeEventListener('abort',aborted);
      socket.off('close',closed);socket.off('error',closed);
      if(error)reject(error);else resolve();
    };
    const aborted=()=>finish(Error('CLOSED')),closed=()=>finish(Error('SOCKET_SEND_REFUSED'));
    if(signal.aborted){aborted();return;}
    if(socket.readyState!==WebSocket.OPEN){closed();return;}
    signal.addEventListener('abort',aborted,{once:true});
    socket.once('close',closed);socket.once('error',closed);
    try{socket.send(bytes,{binary:true},error=>finish(error?Error('SOCKET_SEND_REFUSED'):undefined));}
    catch{closed();}
  });
}

// Called only by a fixed measured entrypoint or the explicit simulation launcher.
export async function startEnclave(cfg) {
// Capacity is fixed for this service (tests, simulation, an image without an authority), or a
// measured authority hook selects it exactly once, before any admission.
check(cfg.capacitySelection===undefined||cfg.resourcePolicy===undefined&&cfg.membership===undefined
  &&typeof cfg.capacitySelection?.select==='function','CAPACITY_CONFIGURATION');
const OUTBOX_PACKET_BYTES=64*1024,WIRE_QUEUE_BYTES=4*1024*1024,WIRE_QUEUE_MESSAGES=256,servers=[];
let resourcePolicy,capacity=0,OUTBOX_EVENTS=0,membership=cfg.membership,selection,selecting=false;
function freeze(policy,frozen={}){
  check(!resourcePolicy,'CAPACITY_FROZEN');
  resourcePolicy=validateResourcePolicy(policy);capacity=resourcePolicy.proofSlots;
  // Bounds include terminal reservations for offers retained after admission expiry.
  OUTBOX_EVENTS=capacity*4;membership=frozen.membership??membership;
  if(frozen.selectionHash)selection={hash:frozen.selectionHash,runtimeAllocation:frozen.runtimeAllocation};
  for(const server of servers)server.maxConnections=capacity+8;
}
if(!cfg.capacitySelection)freeze(cfg.resourcePolicy??DEFAULT_RESOURCE_POLICY);
let offering=0,outboxBytes=0;
const sessions = new Map(), retainedOffers = new Map(), owned = new Set(), pendingStarts = new Set(), closures = new Set(), cancellations = new Map(); let draining = false, preflights = 0;
const outbox = new Map();
const nativePids=new Set(),queueReaders=new Set();
const diagnostics=sessionDiagnostics(),socketClosures=new Map();
const metrics=cfg.metrics===true?startRuntimeMetrics({nativePids:()=>nativePids,identityMetrics:cfg.identityMetrics,queues:()=>{
  const totals={inputBytes:0,outputBytes:0,inputMessages:0,outputMessages:0,protocolBufferedBytes:0,ciphertextBufferedBytes:0};
  for(const read of queueReaders){const value=read();for(const name of Object.keys(totals))totals[name]+=value[name];}
  return totals;
}}):undefined;
const capacityState=()=>({envelope:CAPACITY_ENVELOPE,state:!cfg.capacitySelection?'fixed':resourcePolicy?'selected':'awaiting-selection',
  selectionHash:selection?.hash??null});
const capacityResult=()=>({configured:true,selectionHash:selection.hash,resourcePolicy,runtimeAllocation:selection.runtimeAllocation});
const health=()=>({sessions:sessions.size,preflights,outbox:outbox.size,outboxBytes,draining,proofSlots:capacity,
  availableSlots:Math.max(0,capacity-sessions.size-offering),reservedSlots:[...sessions.values()].filter(s=>!s.nativeStarted).length,
  executingSlots:[...sessions.values()].filter(s=>s.nativeStarted&&!s.retiring).length,
  retiringSlots:[...sessions.values()].filter(s=>s.retiring).length,capacity:capacityState(),
  ...(resourcePolicy?{resourcePolicy}:{}),...(selection?{runtimeAllocation:selection.runtimeAllocation}:{}),
  ...(metrics?{metrics:metrics.snapshot(),diagnostics:diagnostics.snapshot()}:{})});
const deliveryReservations=()=>outbox.size+sessions.size+retainedOffers.size+offering;
const json = (res, code, value) => res.writeHead(code, {'content-type': 'application/json'}).end(JSON.stringify(value));
async function input(req) {const chunks = []; let size = 0; for await (const b of req) {size += b.length; check(size <= 32768, 'INPUT_LIMIT'); chunks.push(b);} return decode(Buffer.concat(chunks));}
const sameGrant = (a,b) => Buffer.from(encode(a)).equals(Buffer.from(encode(b)));
function forget(state) {
  clearTimeout(state.timer);sessions.delete(state.offer.body.session);retainedOffers.delete(state.offer.body.session);
  state.channel=undefined;state.receipt=undefined;
}
function retain(state) {
  clearTimeout(state.timer);sessions.delete(state.offer.body.session);state.used=false;state.close=undefined;state.retiring=undefined;
  if(Date.now()>=state.ticket.body.resultExpiresAt){forget(state);return;}
  retainedOffers.set(state.offer.body.session,state);
  state.timer=setTimeout(()=>forget(state),Math.max(1,state.ticket.body.resultExpiresAt-Date.now()));
}
async function terminalPacket(state,outcome,receipt) {
  if(state.terminalPromise)return state.terminalPromise;
  // A grant can be up to two seconds ahead of the enclave clock. Record the
  // actual retirement time after that point; never synthesize a past timestamp.
  state.terminalPromise=(async()=>{
    if(Date.now()<state.grant.body.issuedAt)await new Promise(r=>setTimeout(r,state.grant.body.issuedAt-Date.now()));
    const terminal=await makeTerminal(state.ticket,state.offer,state.grant,outcome,receipt,state.receipt.privateKey,Date.now(),
      state.nativeStarted?{}:{nativeStarted:false});
    const packet={terminal,receipt:receipt??null,ticket:state.ticket,offer:state.offer,grant:state.grant};
    if(cfg.retainOutbox){
      const bytes=encode(packet);check(bytes.length<=OUTBOX_PACKET_BYTES && outbox.size<OUTBOX_EVENTS,'OUTBOX_LIMIT');
      outbox.set(await digest(bytes),packet);outboxBytes+=bytes.length;
    }
    try{await cfg.onTerminal?.(packet);}catch{/* Physical occupancy remains until durable delivery. */}
  })();
  return state.terminalPromise;
}
function retireUnstarted(state,outcome='failed') {
  if(state.retiring)return state.retiring;
  check(!state.nativeStarted,'NATIVE_ACTIVE');
  clearTimeout(state.timer);
  const task=(async()=>{if(state.grantValid&&(cfg.onTerminal||cfg.retainOutbox))await terminalPacket(state,outcome);})()
    .finally(()=>{forget(state);closures.delete(task);});
  state.retiring=task;closures.add(task);void task.catch(()=>{});return task;
}

const handleControl = async (req, res) => {
  try {
    if (cfg.health && req.url === '/health' && req.method === 'GET') {json(res, 200, {...cfg.health,...health()}); return;}
    if (req.url === '/capacity' && req.method === 'POST') {
      check(cfg.capacitySelection,'CAPACITY_AUTHORITY_ABSENT');
      const document=await input(req);
      // One selection per boot. Only the identical authority document may be replayed (a lost reply).
      if(resourcePolicy){check(selection.hash===await digest(encode(document)),'CAPACITY_FROZEN');json(res,200,capacityResult());return;}
      check(!selecting&&!draining,'CAPACITY_BUSY');selecting=true;
      try{
        const frozen=await cfg.capacitySelection.select(document);
        check(!draining,'DRAINING');check(/^[a-f0-9]{64}$/.test(frozen?.selectionHash??''),'CAPACITY_SELECTION');
        freeze(frozen.resourcePolicy,frozen);
      }
      finally{selecting=false;}
      json(res,200,capacityResult());return;
    }
    // No offer, probe, admission, cancellation, outbox or membership before the freeze; no fallback.
    check(resourcePolicy,'CAPACITY_UNCONFIGURED');
    if (membership && req.url === '/membership' && req.method === 'POST') {
      json(res,200,await membership(await input(req),health()));return;
    }
    if (cfg.retainOutbox && req.url === '/outbox' && req.method === 'GET') {json(res, 200, [...outbox.values()]); return;}
    if (cfg.retainOutbox && req.url === '/outbox/ack' && req.method === 'POST') {
      const ack = await verify('pines/tee/outbox-ack/v1', await input(req), cfg.apiKey);
      exact(ack, ['hash']); check(typeof ack.hash === 'string', 'ACK'); const packet=outbox.get(ack.hash);if(packet){outboxBytes-=encode(packet).length;outbox.delete(ack.hash);} json(res, 200, {ok:true}); return;
    }
    if(req.url==='/admit' && req.method==='POST') {
      const value=await input(req);exact(value,['session','grant']);
      const state=sessions.get(value.session)??retainedOffers.get(value.session);
      if(!state){
        check([...outbox.values()].some(packet=>packet.offer.body.session===value.session&&sameGrant(packet.grant,value.grant)),'SESSION');
        json(res,200,{admitted:true});return;
      }
      await checkGrant(value.grant,state.ticket,state.offer,cfg.apiKey,Math.min(Date.now(),value.grant?.body?.deadline-1));
      check(!state.grantValid||sameGrant(state.grant,value.grant),'GRANT_CONTEXT');
      state.grant=value.grant;state.grantValid=true;
      if(!state.used){
        if(state.cancelled||Date.now()>=state.grant.body.deadline||sessions.size+offering>=capacity&&!sessions.has(value.session))
          await retireUnstarted(state,state.cancelled?'cancelled':'failed');
        else{
          clearTimeout(state.timer);retainedOffers.delete(value.session);sessions.set(value.session,state);
          state.timer=setTimeout(()=>{void retireUnstarted(state).catch(()=>{});},Math.max(1,state.grant.body.deadline-Date.now()));
        }
      }
      json(res,200,{admitted:true});return;
    }
    if (req.url === '/cancel' && req.method === 'POST') {
      const value=await verify('pines/tee/cancel/v1',await input(req),cfg.apiKey);
      exact(value,['attempt','issuedAt']);
      check(typeof value.attempt==='string' && Number.isSafeInteger(value.issuedAt) && Math.abs(Date.now()-value.issuedAt)<=10000,'CANCEL_CONTEXT');
      for(const [attempt,expires] of cancellations)if(expires<Date.now())cancellations.delete(attempt);
      check(cancellations.size<128,'CANCEL_LIMIT');cancellations.set(value.attempt,Date.now()+60000);
      for(const state of [...sessions.values(),...retainedOffers.values()])if(state.ticket.body.attempt===value.attempt){
        state.cancelled=true;
        if(state.close)await state.close('cancelled');else if(state.grantValid)await retireUnstarted(state,'cancelled');else retain(state);
      }
      json(res,200,{received:true});return;
    }
    check(!draining && req.method === 'POST', 'DRAINING');
    if (req.url === '/offer' || req.url === '/probe') {
      const probe=req.url==='/probe';
      const {ticket} = await input(req);
      // Independently refuse a mismatched disclosure before reserving a slot or
      // issuing an offer. Signature validation follows in createOffer.
      nativeAllocation(resourcePolicy,ticket?.body?.disclosurePolicy);
      check(preflights<1 && (probe || (sessions.size+offering<capacity && deliveryReservations()<OUTBOX_EVENTS)), 'CAPACITY');
      preflights++;if(!probe)offering++;
      try {
        // The frozen boot policy travels with the ticket so the application binds the
        // ticket's signed disclosure policy to this boot's class a second time, independently.
        const state = await cfg.createOffer(ticket, {probe,resourcePolicy});
        check(!draining,'DRAINING');
        check(!cancellations.has(ticket.body.attempt),'CANCELLED');
        if(probe){json(res,200,state.offer);return;}
        state.ticket = ticket; state.used = false;state.nativeStarted=false;
        state.timer = setTimeout(() => retain(state), Math.max(1, ticket.body.expiresAt - Date.now()));
        sessions.set(state.offer.body.session, state); json(res, 200, state.offer);
      } finally {preflights--;if(!probe)offering--;}
    } else json(res, 404, {code: 'ROUTE'});
  } catch (error) {
    // Quote-only diagnostics need fixed failure codes to qualify actual hardware.
    // No dynamic exception text, transcript, key, account value or header escapes.
    const probeCodes=new Set(['SIGNATURE','TICKET_EXPIRED','PROFILE','TICKET_SCOPE','LIMITS','ATTEMPT','TIME','ENCODING',
      'DEPLOYMENT_CONTEXT','WORKER_CONTEXT','CLOCK_PROVENANCE','NSM_REFUSED','QUOTE_ENCODING','QUOTE_LIMIT','COSE','COSE_TAG',
      'COSE_ALGORITHM','QUOTE_FIELDS','PCRS','CERTIFICATE','DEBUG_MEASUREMENT','MEASUREMENT']);
    const quote=req.url==='/probe'&&error?.message==='QUOTE_ENCODING'&&typeof error.publicQuote==='string'
      &&error.publicQuote.length<=32768&&/^(?:[a-f0-9]{2})+$/.test(error.publicQuote)?error.publicQuote:undefined;
    // An operator selecting capacity needs the fixed refusal class; none carries dynamic text.
    const capacityCodes=new Set(['CAPACITY_AUTHORITY_ABSENT','CAPACITY_FROZEN','CAPACITY_BUSY','CAPACITY_AUTHORITY','CAPACITY_SELECTION',
      'CAPACITY_SELECTION_BOOT','CAPACITY_SELECTION_STALE','SIGNATURE','FIELDS','RESOURCE_CLASS','RESOURCE_CLASS_FLOOR','RESOURCE_POLICY',
      'RESOURCE_HEADROOM','RESOURCE_ALLOCATION','CLOCK_PROVENANCE','DRAINING']);
    const code=req.url==='/probe'&&probeCodes.has(error?.message)?error.message
      :req.url==='/capacity'&&capacityCodes.has(error?.message)||error?.message==='CAPACITY_UNCONFIGURED'?error.message:'ENCLAVE_REFUSED';
    json(res, 400, {code,...(quote?{publicQuote:quote}:{})});
  }
};
// Hardware has separate vsock/TCP listeners for proof and control traffic.
// Simulation retains a single loopback address for its existing harness.
const http=createServer(cfg.controlPort===undefined?handleControl:(_req,res)=>json(res,404,{code:'ROUTE'}));
const control=cfg.controlPort===undefined?http:createServer(handleControl);
for(const server of new Set([http,control])){servers.push(server);server.maxConnections=capacity+8;server.requestTimeout=10000;server.headersTimeout=10000;server.keepAliveTimeout=1000;}
const wss = new WebSocketServer({server: http, maxPayload: 128 * 1024});
wss.on('connection', ws => {
  const diagnosis=diagnostics.begin();
  if (draining || !resourcePolicy || wss.clients.size > capacity) {diagnosis.close('CONNECTION_REFUSED');ws.close(); return;}
  let state, native, starting, preparing, protocol, incoming, outgoing, binding, deadline, confirmed = false, finished = false, ended = false;
  let signedReceipt, outcome = 'failed', validatingGrant, closure;
  let inputChain = Promise.resolve(), outputChain = Promise.resolve(), queued = 0, outboundQueued = 0,queuedMessages=0,outboundMessages=0,consumedInput=0;
  const nativeChunks=[];let nativeQueued=0,nativeOutputWork,nativeInFlight=false,nativePaused=false;
  const sending=new AbortController();
  const queueState=()=>({inputBytes:queued,outputBytes:outboundQueued+nativeQueued,inputMessages:queuedMessages,
    outputMessages:outboundMessages+nativeChunks.length+Number(nativeInFlight),
    protocolBufferedBytes:protocol?.bufferedAmount??0,ciphertextBufferedBytes:ws.bufferedAmount});
  queueReaders.add(queueState);
  const rawSend = bytes => {check(ws.bufferedAmount + bytes.length <= WIRE_QUEUE_BYTES, 'WIRE_QUEUE');return sendSocket(ws,bytes,sending.signal);};
  const send = (type, bytes = new Uint8Array()) => {
    if(ended)return Promise.reject(Error('CLOSED'));
    if (outboundQueued+nativeQueued+bytes.length+128 > WIRE_QUEUE_BYTES || outboundMessages>=WIRE_QUEUE_MESSAGES) {void close('OUTPUT_QUEUE_LIMIT'); return Promise.reject(Error('WIRE_QUEUE'));}
    outboundQueued += bytes.length + 128;outboundMessages++;
    const promise = outputChain.then(async () => rawSend(await outgoing.frames.seal(type, bytes)))
      .finally(() => {outboundQueued -= bytes.length + 128;outboundMessages--;});
    outputChain = promise; void promise.catch(() => close('OUTPUT_SEND_REFUSED')); return promise;
  };
  const drainNative=()=>{
    if(nativeOutputWork||ended)return;
    nativeOutputWork=(async()=>{
      // TLSN is a byte stream. Coalesce tiny writes from one parser turn into
      // bounded DATA frames instead of allocating a promise for every write.
      await Promise.resolve();
      while(!ended&&nativeChunks.length){
        const part=nativeChunks.shift();nativeInFlight=true;
        try{await send(FRAME.DATA,part.bytes.subarray(0,part.length));}
        finally{part.bytes.fill(0);nativeQueued-=MAX_FRAME+128;nativeInFlight=false;}
        if(nativePaused&&!ended&&nativeQueued+outboundQueued<WIRE_QUEUE_BYTES/4){nativePaused=false;protocol.resume();}
      }
    })();
    void nativeOutputWork.catch(()=>{if(!ended)void close('OUTPUT_SEND_REFUSED');});
    void nativeOutputWork.finally(()=>{nativeOutputWork=undefined;if(!ended&&nativeChunks.length)drainNative();}).catch(()=>{});
  };
  const nativeData=bytes=>{
    if(ended)return;
    if(nativeQueued+outboundQueued+bytes.length+128>WIRE_QUEUE_BYTES){void close('OUTPUT_QUEUE_LIMIT');return;}
    for(let at=0;at<bytes.length;){
      let part=nativeChunks.at(-1);
      if(!part||part.length===MAX_FRAME){
        // Retain one frame of reserve for the active encrypted send. Count
        // allocated backing buffers, including partially filled chunks.
        if(nativeQueued+outboundQueued+2*(MAX_FRAME+128)>WIRE_QUEUE_BYTES){void close('OUTPUT_QUEUE_LIMIT');return;}
        part={bytes:new Uint8Array(MAX_FRAME),length:0};nativeChunks.push(part);nativeQueued+=MAX_FRAME+128;
      }
      const n=Math.min(MAX_FRAME-part.length,bytes.length-at);part.bytes.set(bytes.subarray(at,at+n),part.length);part.length+=n;at+=n;
    }
    if(!nativePaused&&nativeQueued+outboundQueued>=WIRE_QUEUE_BYTES/2){nativePaused=true;protocol.pause();}
    drainNative();
  };
  const flushNative=async()=>{while(!ended&&(nativeOutputWork||nativeChunks.length)){drainNative();await nativeOutputWork;}};
  const close = (cause='UNKNOWN_CLOSE') => {
    diagnosis.close(cause);
    if (closure) return closure; ended = true; clearTimeout(deadline);sending.abort();
    for(const part of nativeChunks){part.bytes.fill(0);nativeQueued-=MAX_FRAME+128;}nativeChunks.length=0;
    closure=(async()=>{
    if (state) {clearTimeout(state.timer);state.retiring=true;}
    // A close racing signature verification must not discard the receipt key
    // before a valid grant can receive its signed physical retirement.
    if(validatingGrant){try{await validatingGrant;}catch{}}
    // The per-session clock helper is also owned work. Its bounded timeout must
    // finish before slot reuse, even when cancellation wins before native spawn.
    if(preparing){try{await preparing;}catch{}}
    protocol?.terminate();
    // Wait for a racing start before attesting physical termination.
    if (starting) {try {const child = await starting; await child.stop();} catch {}}
    await native?.stop(); if (native) owned.delete(native);
    if (state && state.grantValid && (cfg.onTerminal || cfg.retainOutbox)) await terminalPacket(state,outcome,signedReceipt);
    })().finally(()=>{
      if (state) {if(!state.grantValid&&!state.nativeStarted)retain(state);else forget(state);}
      incoming?.destroy(); outgoing?.frames.destroy(); ws.close();closures.delete(closure);socketClosures.delete(ws);
      void Promise.allSettled([inputChain,outputChain,nativeOutputWork]).then(()=>queueReaders.delete(queueState));
    });
    closures.add(closure);void closure.catch(()=>{});return closure;
  };
  socketClosures.set(ws,close);
  ws.on('close', () => {void close('CLIENT_SOCKET_CLOSED');}); ws.on('error', () => {void close('CLIENT_SOCKET_ERROR');});
  deadline = setTimeout(() => {void close('HANDSHAKE_DEADLINE');}, 10000);
  ws.on('message', (bytes, binary) => {
    if(ended)return;
    // Every authenticated frame has at least 21 bytes; even the initial JSON
    // hello is larger. Bound message objects as well as their payload bytes.
    if(!binary||bytes.length<21){void close('INPUT_FRAME_REFUSED');return;}
    if (queued+bytes.length+128 > WIRE_QUEUE_BYTES || queuedMessages>=WIRE_QUEUE_MESSAGES) {void close('INPUT_QUEUE_LIMIT'); return;}
    queued += bytes.length+128;queuedMessages++;
    inputChain = inputChain.then(async () => {
      check(!ended, 'CLOSED');
      if (!state) {
        const hello = decode(bytes); exact(hello, ['session', 'grant', 'enc']);
        // A rejected duplicate/wrong-session socket never acquires ownership of
        // another channel's state or signs its terminal while it still runs.
        const candidate=sessions.get(hello.session);
        check(candidate && !candidate.used && !candidate.retiring && !candidate.cancelled, 'SESSION');
        state=candidate;
        state.used = true; clearTimeout(state.timer);
        state.close=(reason='cancelled')=>{if(outcome!=='completed')outcome=reason;return close('OPERATOR_CANCELLED');};
        validatingGrant=checkGrant(hello.grant,state.ticket,state.offer,cfg.apiKey).then(()=>{
          check(!state.grantValid||sameGrant(state.grant,hello.grant),'GRANT_CONTEXT');state.grant=hello.grant;state.grantValid=true;
        });
        await validatingGrant;check(!ended,'CLOSED');
        binding = await channelBinding(state.ticket, state.offer, state.grant);
        incoming = await receiver(state.channel, state.ticket.body.clientKey, hello.enc, binding, 'client-to-enclave');
        outgoing = await sender(state.channel, state.ticket.body.clientKey, binding, 'enclave-to-client');
        clearTimeout(deadline); deadline = setTimeout(() => {void close('SESSION_DEADLINE');}, Math.max(1, state.grant.body.deadline - Date.now()));
        await rawSend(encode({enc: outgoing.enc})); return;
      }
      const frame = await incoming.open(new Uint8Array(bytes));
      if (!confirmed) {
        check(frame.type === FRAME.CONFIRM && decode(frame.bytes).binding === binding, 'KEY_CONFIRMATION');
        confirmed = true;
        preparing=Promise.resolve().then(()=>{check(!ended,'CLOSED');return cfg.beforeNative?.();});
        try {await preparing;} catch(error) {void close('NATIVE_PREPARATION_REFUSED');throw error;}
        check(!ended,'CLOSED');
        state.nativeStarted=true;
        const nativeConfig={...cfg,resourcePolicy,onNativeSpawn:pid=>nativePids.add(pid),onNativeExit:pid=>nativePids.delete(pid),onNativePeaks:value=>metrics?.recordPeaks(value)};
        starting = startNative(cfg.hardware ? {...nativeConfig, provider: providerForTicket(state.ticket.body), wallet: state.ticket.body.wallet,
          deadline: state.grant.body.deadline, sessionBudgetMs: state.grant.body.sessionBudgetMs,resourcePolicy,disclosurePolicy:state.ticket.body.disclosurePolicy} : nativeConfig); pendingStarts.add(starting);
        let started;
        try {started = await starting;}
        catch(error) {diagnosis.nativeRefusal('NATIVE_START');void close('NATIVE_START_REFUSED');throw error;}
        finally {pendingStarts.delete(starting);}
        // Cancellation can win while spawn/readiness is awaited. Retire the new
        // child here; the earlier close callback could not yet see its handle.
        if (ended) {await started.stop(); return;}
        native = started; owned.add(native);
        // Ephemeral ports can be reused after a child crashes. Authenticate the
        // expected process before any TLSN bytes enter its private channel.
        protocol = new WebSocket('ws://127.0.0.1:' + native.port,
          {maxPayload:WIRE_QUEUE_BYTES,...(native.connectionToken?{headers:{'x-pines-native-session':native.connectionToken}}:{})});
        protocol.on('error', () => {void close('NATIVE_SOCKET_ERROR');});
        protocol.on('message', (b, binary) => {
          if (!binary) {void close('NATIVE_FRAME_REFUSED'); return;}
          nativeData(b);
        });
        await new Promise((resolve, reject) => {
          // A native peer can send DATA in the WebSocket upgrade packet. Queue
          // confirmation inside the open callback, before that parser turn can
          // deliver a message; both then use the same bounded output chain.
          protocol.once('open', () => {void send(FRAME.CONFIRM, encode({binding})).then(resolve, reject);});
          protocol.once('error', reject);
        });
        void native.result.then(async result => {if (result.type !== 'verified') {
          diagnosis.nativeRefusal(result.code);await close('NATIVE_REFUSED');return;
        } await flushNative();await send(FRAME.ACK);}).catch(() => close('NATIVE_RESULT_ERROR'));
      } else if (frame.type === FRAME.DATA) {
        check(!finished && frame.bytes.length>0 && protocol.readyState === WebSocket.OPEN && protocol.bufferedAmount + frame.bytes.length <= WIRE_QUEUE_BYTES, 'PROTOCOL_STATE');
        try {
          await sendSocket(protocol,frame.bytes,sending.signal);check(!ended,'CLOSED');
          // The bounded browser window advances only after this DATA frame
          // leaves the native socket queue. CREDIT never substitutes for ACK.
          await send(FRAME.CREDIT,encodeInputCredit(++consumedInput));
        } finally {frame.bytes.fill(0);}
      } else if (frame.type === FRAME.CANCEL) {outcome = 'cancelled'; await close('CLIENT_CANCELLED');}
      else if (frame.type === FRAME.FINISH) {
        check(frame.bytes.length === 0 && !finished, 'FINALIZATION'); finished = true;
        const result = await native.result; check(!ended && result.type === 'verified', 'NATIVE_REFUSED');
        // A successful receipt is signed only after the owned native process exits.
        await native.stop(); owned.delete(native);
        try {await cfg.beforeReceipt?.();} catch(error) {void close('RECEIPT_PREPARATION_REFUSED');throw error;}
        check(!ended,'CLOSED');
        if(Date.now()>=state.grant.body.deadline){void close('SESSION_DEADLINE');throw Error('SESSION_DEADLINE');}
        const receipt = await makeReceipt(state.ticket, state.offer, state.grant, result.facts, state.receipt.privateKey);
        signedReceipt = receipt; outcome = 'completed';
        let response=receipt;
        if(state.offer.body.identity){
          check(cfg.identityAdapter?.enabled===true&&typeof result.facts.accountId==='string','KEYED_IDENTITY_REQUIRED');
          // Use enclave-to-client exporter: client-to-enclave is already FINISHed.
          const accountConfirmation=await outgoing.frames.accountConfirmation(accountConfirmationMessage(
            state.offer.body.identity,providerForTicket(state.ticket.body),result.facts.accountId,result.facts.pseudonym));
          delete result.facts.accountId;
          response={receipt,accountConfirmation};
        }
        await send(FRAME.RESULT, encode(response)); await send(FRAME.FINISH); await close('COMPLETED');
      } else throw Error('FRAME_ORDER');
    }).catch(() => close('INPUT_PROTOCOL_REFUSED'))
      .finally(()=>{queued -= bytes.length+128;queuedMessages--;});
  });
});
await new Promise(resolve => http.listen(cfg.port ?? 0, '127.0.0.1', resolve));
if(control!==http)await new Promise(resolve=>control.listen(cfg.controlPort,'127.0.0.1',resolve));
async function shutdown() {draining = true;
  for(const s of [...sessions.values(),...retainedOffers.values()]){clearTimeout(s.timer);if(!s.used){if(s.grantValid)await retireUnstarted(s);else forget(s);}}
  for (const ws of wss.clients) {void socketClosures.get(ws)?.('SERVICE_SHUTDOWN');ws.terminate();}
  await Promise.allSettled([...pendingStarts].map(p => p.then(n => n.stop())));
  for (const n of owned) await n.stop();await Promise.allSettled([...closures]);
  const until=Date.now()+10000;while(outbox.size && Date.now()<until)await new Promise(r=>setTimeout(r,100));
  await metrics?.stop();
  for(const server of new Set([http,control])){server.closeAllConnections();await new Promise(r=>server.close(r));}}
return {port:http.address().port,controlPort:control.address().port,shutdown};
}
