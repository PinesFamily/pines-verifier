import {channelKey, exportChannelKey, FRAME, MAX_FRAME, receiver, sender} from './channel.mjs';
import {check, decode, encode, random} from './wire.mjs';
import {channelBinding, checkGrant, checkOffer, checkReceipt, checkTicket} from './protocol.mjs';
import {byteQueue, openRaw} from './transport.mjs';
import {isHardwareProfile, providerForSchema, providerForTicket} from './profile.mjs';

export async function encryptedClient(cfg) {
  const provider = isHardwareProfile(cfg.policy?.profile) ? providerForSchema(cfg.schema) : null;
  if (isHardwareProfile(cfg.policy?.profile)) check(provider && provider.profile === cfg.policy.profile && typeof cfg.attemptId === 'string', 'BROWSER_CONTEXT');
  const key = await channelKey(), clientKey = await exportChannelKey(key.publicKey), browserNonce = random();
  const headers = {'content-type': 'application/json', ...(cfg.authorization ? {authorization: 'Bearer ' + cfg.authorization} : {})};
  const response = await fetch(cfg.api + '/admission', {method: 'POST', headers, body: JSON.stringify({clientKey, browserNonce, ...(cfg.attemptId ? {attemptId: cfg.attemptId} : {})}), signal: AbortSignal.timeout(10000)});
  check(response.ok, 'ADMISSION_REFUSED');
  const {ticket, offer, grant} = await response.json();
  const t = await checkTicket(ticket, cfg.apiKey, cfg.policy.profile);
  check(t.clientKey === clientKey && t.browserNonce === browserNonce && t.wallet === cfg.wallet, 'BROWSER_CONTEXT');
  if (provider) check(providerForTicket(t) === provider && t.attempt === cfg.attemptId, 'BROWSER_CONTEXT');
  await checkOffer(offer, ticket, cfg.policy); await checkGrant(grant, ticket, offer, cfg.apiKey);
  const binding = await channelBinding(ticket, offer, grant);
  const outgoing = await sender(key, offer.body.channelKey, binding, 'client-to-enclave');
  const wire = await openRaw(cfg.relay);
  let incoming;
  const handshakeTimer = setTimeout(() => wire.abort(), Math.max(1, Math.min(10000, grant.body.deadline - Date.now())));
  try {
    await wire.write(encode({session: offer.body.session, grant, enc: outgoing.enc}));
    const hello = decode(await wire.read());
    incoming = await receiver(key, offer.body.channelKey, hello.enc, binding, 'enclave-to-client');
    await wire.write(await outgoing.frames.seal(FRAME.CONFIRM, encode({binding})));
    const confirmed = await incoming.open(await wire.read());
    check(confirmed.type === FRAME.CONFIRM && decode(confirmed.bytes).binding === binding, 'KEY_CONFIRMATION');
  } catch (e) {wire.abort(); outgoing.frames.destroy(); incoming?.destroy(); throw e;}
  finally {clearTimeout(handshakeTimer);}
  const queue = byteQueue(); let nativeResolve, resultResolve, resultReject, receipt, final = false, failed = false;
  const nativeDone = new Promise(r => {nativeResolve = r;});
  const terminal = new Promise((resolve, reject) => {resultResolve = resolve; resultReject = reject;});
  void terminal.catch(() => {});
  const stats = {sent: 0, received: 0};
  const fail = () => {failed = true; nativeResolve(); queue.fail(); resultReject(Error('CHANNEL_REFUSED')); wire.abort();};
  const timer = setTimeout(fail, Math.max(1, grant.body.deadline - Date.now()));
  const pump = (async () => {
    try {
      for (;;) {
        const encrypted = await wire.read(); check(encrypted, 'TRUNCATED');
        const frame = await incoming.open(encrypted);
        if (frame.type === FRAME.DATA) {check(!receipt, 'FRAME_ORDER'); stats.received += frame.bytes.length; queue.push(frame.bytes);}
        else if (frame.type === FRAME.ACK) {check(!receipt, 'FRAME_ORDER'); nativeResolve();}
        else if (frame.type === FRAME.RESULT) {check(!receipt, 'DUPLICATE_RESULT'); receipt = decode(frame.bytes);}
        else if (frame.type === FRAME.FINISH) {check(receipt && frame.bytes.length === 0, 'FINALIZATION'); final = true; queue.end(); resultResolve(receipt); return;}
        else throw Error('FRAME_ORDER');
      }
    } catch {fail();}
  })();
  return {
    stats,
    read: () => queue.read(),
    async write(bytes) {check(!failed, 'CHANNEL_REFUSED'); stats.sent += bytes.length;
      for (let i = 0; i < bytes.length; i += MAX_FRAME) await wire.write(await outgoing.frames.seal(FRAME.DATA, bytes.subarray(i, i + MAX_FRAME)));},
    async finish(facts) {
      await nativeDone; check(!failed, 'CHANNEL_REFUSED');
      await wire.write(await outgoing.frames.seal(FRAME.FINISH));
      const value = await terminal; check(final, 'TRUNCATED');
      await checkReceipt(value, ticket, offer, grant, cfg.apiKey, cfg.policy, facts);
      // Only delivery follows the independently validated hardware receipt here.
      // A lost HTTP response leaves acceptance unknown; durable outbox recovery and
      // the page's authenticated saved-record read decide success.
      let accepted;
      try { accepted = await fetch(cfg.api + '/result', {method: 'POST', headers, body: JSON.stringify({receipt: value, ticket, offer, grant}), signal: AbortSignal.timeout(10000)}); }
      catch { throw Error('API_REFUSED'); }
      check(accepted.ok, 'API_REFUSED');
      return {receipt: value, apiAccepted: true, clientAccepted: true};
    },
    async close() {clearTimeout(timer); if (!final) {try {await wire.write(await outgoing.frames.seal(FRAME.CANCEL));} catch {}} await wire.close(); await pump; outgoing.frames.destroy(); incoming.destroy();},
  };
}
