import {createServer} from 'node:http';
import {WebSocket, WebSocketServer} from 'ws';
import {check, decode, encode, exact, verify, digest} from './wire.mjs';
import {channelBinding, checkGrant, makeReceipt, makeTerminal} from './protocol.mjs';
import {FRAME, MAX_FRAME, receiver, sender} from './channel.mjs';
import {startNative} from './native.mjs';
import {providerForTicket} from './profile.mjs';

// Called only by a fixed measured entrypoint or the explicit simulation launcher.
export async function startEnclave(cfg) {
const sessions = new Map(), owned = new Set(), pendingStarts = new Set(), closures = new Set(), cancellations = new Map(); let draining = false, preflights = 0;
const outbox = new Map();
const json = (res, code, value) => res.writeHead(code, {'content-type': 'application/json'}).end(JSON.stringify(value));
async function input(req) {const chunks = []; let size = 0; for await (const b of req) {size += b.length; check(size <= 32768, 'INPUT_LIMIT'); chunks.push(b);} return decode(Buffer.concat(chunks));}

const http = createServer(async (req, res) => {
  try {
    if (cfg.health && req.url === '/health' && req.method === 'GET') {json(res, 200, {...cfg.health, sessions: sessions.size, preflights, outbox: outbox.size, draining}); return;}
    if (cfg.retainOutbox && req.url === '/outbox' && req.method === 'GET') {json(res, 200, [...outbox.values()]); return;}
    if (cfg.retainOutbox && req.url === '/outbox/ack' && req.method === 'POST') {
      const ack = await verify('pines/tee/outbox-ack/v1', await input(req), cfg.apiKey);
      exact(ack, ['hash']); check(typeof ack.hash === 'string', 'ACK'); outbox.delete(ack.hash); json(res, 200, {ok:true}); return;
    }
    if (req.url === '/cancel' && req.method === 'POST') {
      const value=await verify('pines/tee/cancel/v1',await input(req),cfg.apiKey);
      exact(value,['attempt','issuedAt']);
      check(typeof value.attempt==='string' && Number.isSafeInteger(value.issuedAt) && Math.abs(Date.now()-value.issuedAt)<=10000,'CANCEL_CONTEXT');
      for(const [attempt,expires] of cancellations)if(expires<Date.now())cancellations.delete(attempt);
      check(cancellations.size<128,'CANCEL_LIMIT');cancellations.set(value.attempt,Date.now()+60000);
      for(const state of sessions.values())if(state.ticket.body.attempt===value.attempt){
        if(state.close)await state.close();else{clearTimeout(state.timer);sessions.delete(state.offer.body.session);}
      }
      json(res,200,{received:true});return;
    }
    check(!draining && req.method === 'POST', 'DRAINING');
    if (req.url === '/offer' || req.url === '/probe') {
      check(sessions.size + preflights < 1 && outbox.size < 4, 'CAPACITY'); preflights++;
      try {
        const {ticket} = await input(req);
        const state = await cfg.createOffer(ticket, {probe:req.url==='/probe'});
        check(!cancellations.has(ticket.body.attempt),'CANCELLED');
        if(req.url==='/probe'){json(res,200,state.offer);return;}
        state.ticket = ticket; state.used = false;
        state.timer = setTimeout(() => sessions.delete(state.offer.body.session), Math.max(1, ticket.body.expiresAt - Date.now()));
        sessions.set(state.offer.body.session, state); json(res, 200, state.offer);
      } finally {preflights--;}
    } else json(res, 404, {code: 'ROUTE'});
  } catch (error) {
    // Quote-only diagnostics need fixed failure codes to qualify actual hardware.
    // No dynamic exception text, transcript, key, account value or header escapes.
    const probeCodes=new Set(['SIGNATURE','TICKET_EXPIRED','PROFILE','TICKET_SCOPE','LIMITS','ATTEMPT','TIME','ENCODING',
      'DEPLOYMENT_CONTEXT','WORKER_CONTEXT','CLOCK_PROVENANCE','NSM_REFUSED','QUOTE_ENCODING','QUOTE_LIMIT','COSE','COSE_TAG',
      'COSE_ALGORITHM','QUOTE_FIELDS','PCRS','CERTIFICATE','DEBUG_MEASUREMENT','MEASUREMENT']);
    const quote=req.url==='/probe'&&error?.message==='QUOTE_ENCODING'&&typeof error.publicQuote==='string'
      &&error.publicQuote.length<=32768&&/^(?:[a-f0-9]{2})+$/.test(error.publicQuote)?error.publicQuote:undefined;
    json(res, 400, {code: req.url==='/probe' && probeCodes.has(error?.message) ? error.message : 'ENCLAVE_REFUSED',
      ...(quote?{publicQuote:quote}:{})});
  }
});
http.maxConnections = 8; http.requestTimeout = 10000; http.headersTimeout = 10000;
const wss = new WebSocketServer({server: http, maxPayload: 128 * 1024});
wss.on('connection', ws => {
  if (draining || wss.clients.size > 1) {ws.close(); return;}
  let state, native, starting, protocol, incoming, outgoing, binding, deadline, confirmed = false, finished = false, ended = false;
  let signedReceipt, outcome = 'failed', grantValid = false, closure;
  let inputChain = Promise.resolve(), outputChain = Promise.resolve(), queued = 0, outboundQueued = 0;
  const rawSend = bytes => new Promise((resolve, reject) => {check(ws.bufferedAmount + bytes.length <= 16 * 1024 * 1024, 'WIRE_QUEUE'); ws.send(bytes, {binary: true}, e => e ? reject(e) : resolve());});
  const send = (type, bytes = new Uint8Array()) => {
    outboundQueued += bytes.length + 21;
    if (outboundQueued > 16 * 1024 * 1024) {void close(); return Promise.reject(Error('WIRE_QUEUE'));}
    const promise = outputChain.then(async () => rawSend(await outgoing.frames.seal(type, bytes)))
      .finally(() => {outboundQueued -= bytes.length + 21;});
    outputChain = promise; void promise.catch(() => close()); return promise;
  };
  const close = () => {
    if (closure) return closure; ended = true; clearTimeout(deadline);
    closure=(async()=>{
    if (state) clearTimeout(state.timer);
    protocol?.terminate();
    // Wait for a racing start before attesting physical termination.
    if (starting) {try {const child = await starting; await child.stop();} catch {}}
    await native?.stop(); if (native) owned.delete(native);
    if (state && grantValid && (cfg.onTerminal || cfg.retainOutbox)) {
      const terminal = await makeTerminal(state.ticket, state.offer, state.grant, outcome, signedReceipt, state.receipt.privateKey);
      const packet = {terminal, receipt: signedReceipt ?? null, ticket: state.ticket, offer: state.offer, grant: state.grant};
      if (cfg.retainOutbox) outbox.set(await digest(encode(packet)), packet);
      // This callback may persist only the public signed envelopes, never IPC.
      try {await cfg.onTerminal?.(packet);}
      catch { /* Delivery failure does not undo termination; API retains occupancy. */ }
    }
    })().finally(()=>{
      if (state) {sessions.delete(state.offer.body.session);state.channel = undefined; state.receipt = undefined;}
      incoming?.destroy(); outgoing?.frames.destroy(); ws.close();closures.delete(closure);
    });
    closures.add(closure);void closure.catch(()=>{});return closure;
  };
  ws.on('close', () => {void close();}); ws.on('error', () => {void close();});
  deadline = setTimeout(() => {void close();}, 10000);
  ws.on('message', (bytes, binary) => {
    queued += bytes.length;
    if (!binary || queued > 16 * 1024 * 1024) {void close(); return;}
    inputChain = inputChain.then(async () => {
      queued -= bytes.length; check(!ended, 'CLOSED');
      if (!state) {
        const hello = decode(bytes); exact(hello, ['session', 'grant', 'enc']);
        state = sessions.get(hello.session); check(state && !state.used, 'SESSION');
        state.used = true; clearTimeout(state.timer);
        state.grant = hello.grant;
        await checkGrant(state.grant, state.ticket, state.offer, cfg.apiKey);
        grantValid = true;
        state.close=()=>{if(outcome!=='completed')outcome='cancelled';return close();};
        binding = await channelBinding(state.ticket, state.offer, state.grant);
        incoming = await receiver(state.channel, state.ticket.body.clientKey, hello.enc, binding, 'client-to-enclave');
        outgoing = await sender(state.channel, state.ticket.body.clientKey, binding, 'enclave-to-client');
        clearTimeout(deadline); deadline = setTimeout(() => {void close();}, Math.max(1, state.grant.body.deadline - Date.now()));
        await rawSend(encode({enc: outgoing.enc})); return;
      }
      const frame = await incoming.open(new Uint8Array(bytes));
      if (!confirmed) {
        check(frame.type === FRAME.CONFIRM && decode(frame.bytes).binding === binding, 'KEY_CONFIRMATION');
        confirmed = true;
        await cfg.beforeNative?.();check(!ended,'CLOSED');
        starting = startNative(cfg.hardware ? {...cfg, provider: providerForTicket(state.ticket.body), wallet: state.ticket.body.wallet} : cfg); pendingStarts.add(starting);
        let started;
        try {started = await starting;} finally {pendingStarts.delete(starting);}
        // Cancellation can win while spawn/readiness is awaited. Retire the new
        // child here; the earlier close callback could not yet see its handle.
        if (ended) {await started.stop(); return;}
        native = started; owned.add(native);
        protocol = new WebSocket('ws://127.0.0.1:' + native.port);
        protocol.on('error', () => {void close();});
        protocol.on('message', (b, binary) => {
          if (!binary) {void close(); return;}
          for (let i = 0; i < b.length; i += MAX_FRAME) void send(FRAME.DATA, new Uint8Array(b.subarray(i, i + MAX_FRAME))).catch(() => {});
        });
        await new Promise((resolve, reject) => {protocol.once('open', resolve); protocol.once('error', reject);});
        await send(FRAME.CONFIRM, encode({binding}));
        void native.result.then(async result => {if (result.type !== 'verified') {await close(); return;} await send(FRAME.ACK);}).catch(() => close());
      } else if (frame.type === FRAME.DATA) {
        check(!finished && protocol.readyState === WebSocket.OPEN && protocol.bufferedAmount + frame.bytes.length <= 16 * 1024 * 1024, 'PROTOCOL_STATE');
        protocol.send(frame.bytes);
      } else if (frame.type === FRAME.CANCEL) {outcome = 'cancelled'; await close();}
      else if (frame.type === FRAME.FINISH) {
        check(frame.bytes.length === 0 && !finished, 'FINALIZATION'); finished = true;
        const result = await native.result; check(!ended && result.type === 'verified', 'NATIVE_REFUSED');
        // A successful receipt is signed only after the owned native process exits.
        await native.stop(); owned.delete(native);
        await cfg.beforeReceipt?.();check(!ended,'CLOSED');
        const receipt = await makeReceipt(state.ticket, state.offer, state.grant, result.facts, state.receipt.privateKey);
        signedReceipt = receipt; outcome = 'completed';
        await send(FRAME.RESULT, encode(receipt)); await send(FRAME.FINISH); await close();
      } else throw Error('FRAME_ORDER');
    }).catch(() => close());
  });
});
await new Promise(resolve => http.listen(cfg.port ?? 0, '127.0.0.1', resolve));
async function shutdown() {draining = true; for (const s of sessions.values()) clearTimeout(s.timer); sessions.clear(); for (const ws of wss.clients) ws.terminate();
  await Promise.allSettled([...pendingStarts].map(p => p.then(n => n.stop())));
  for (const n of owned) await n.stop();await Promise.allSettled([...closures]);
  const until=Date.now()+10000;while(outbox.size && Date.now()<until)await new Promise(r=>setTimeout(r,100));
  http.closeAllConnections(); await new Promise(r => http.close(r));}
return {port: http.address().port, shutdown};
}
