import {channelKey, exportChannelKey, FRAME, MAX_FRAME, receiver, sender} from './channel.mjs';
import {check, decode, encode, random} from './wire.mjs';
import {channelBinding, checkGrant, checkOffer, checkReceipt, checkTicket} from './protocol.mjs';
import {byteQueue} from './transport.mjs';
import {openChannel} from './entry-channel.mjs';
import {isHardwareProfile, providerForSchema, providerForTicket} from './profile.mjs';
import {SESSION_POLICY_FIELDS, validateSessionPolicySnapshot} from './session-policy.mjs';
import {inputCredits} from './input-flow-control.mjs';
import {disclosurePolicy} from './disclosure-policy.mjs';
import {accountConfirmationMessage} from './identity-binding.mjs';

export async function encryptedClient(cfg) {
  // The configured policy decides which schema versions this build can prove at all.
  // The ticket's own policy is checked against it below, so a server that selected the
  // other class is refused rather than silently resolving the other class's provider.
  const provider = isHardwareProfile(cfg.policy?.profile) ? providerForSchema(cfg.schema, cfg.disclosurePolicy) : null;
  if (isHardwareProfile(cfg.policy?.profile)) check(provider && provider.profile === cfg.policy.profile && typeof cfg.attemptId === 'string', 'BROWSER_CONTEXT');
  const key = await channelKey(), clientKey = await exportChannelKey(key.publicKey), browserNonce = random();
  const headers = {'content-type': 'application/json', ...(cfg.authorization ? {authorization: 'Bearer ' + cfg.authorization} : {})};
  const response = await fetch(cfg.api + '/admission', {method: 'POST', headers, body: JSON.stringify({clientKey, browserNonce, ...(cfg.attemptId ? {attemptId: cfg.attemptId} : {})}), signal: AbortSignal.timeout(10000)});
  check(response.ok, 'ADMISSION_REFUSED');
  const {ticket, offer, grant, route} = await response.json();
  const t = await checkTicket(ticket, cfg.apiKey, cfg.policy.profile);
  // The API selects the policy; the browser only confirms it is the one it prepared for.
  const selectedDisclosure = disclosurePolicy(t.disclosurePolicy);
  check(selectedDisclosure === disclosurePolicy(cfg.disclosurePolicy), 'DISCLOSURE_POLICY_BINDING');
  check(t.clientKey === clientKey && t.browserNonce === browserNonce && t.wallet === cfg.wallet, 'BROWSER_CONTEXT');
  if (provider) {
    // `providerForTicket` resolves under the ticket's own signed policy, which the check
    // above has already bound to the configured one.
    check(providerForTicket(t) === provider && t.attempt === cfg.attemptId, 'BROWSER_CONTEXT');
    const expected = cfg.sessionPolicySnapshot;
    validateSessionPolicySnapshot(expected, expected?.issuedAt);
    check(['issuedAt', ...SESSION_POLICY_FIELDS].every(field => t[field] === expected[field]), 'SESSION_POLICY_BINDING');
  }
  await checkOffer(offer, ticket, cfg.policy); await checkGrant(grant, ticket, offer, cfg.apiKey);
  const binding = await channelBinding(ticket, offer, grant);
  const outgoing = await sender(key, offer.body.channelKey, binding, 'client-to-enclave');
  const {wire, ...entry} = await openChannel({cfg, ticket, grant, route});
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
  const queue = byteQueue(), credits = inputCredits();
  let nativeResolve, resultResolve, resultReject, receipt, final = false, failed = false, writing = false, finishing = false, finalizing = false, closing = false, closePromise;
  let writeSettled = Promise.resolve();
  const nativeDone = new Promise(r => {nativeResolve = r;});
  const terminal = new Promise((resolve, reject) => {resultResolve = resolve; resultReject = reject;});
  void terminal.catch(() => {});
  const stats = {sent: 0, received: 0};
  const fail = () => {failed = true; credits.fail(); nativeResolve(); queue.fail(); resultReject(Error('CHANNEL_REFUSED')); wire.abort();};
  const timer = setTimeout(fail, Math.max(1, grant.body.deadline - Date.now()));
  const pump = (async () => {
    try {
      for (;;) {
        const encrypted = await wire.read(); check(encrypted, 'TRUNCATED');
        const frame = await incoming.open(encrypted);
        if (frame.type === FRAME.DATA) {check(!receipt, 'FRAME_ORDER'); stats.received += frame.bytes.length; queue.push(frame.bytes);}
        else if (frame.type === FRAME.CREDIT) {check(!receipt, 'FRAME_ORDER'); credits.acknowledge(frame.bytes);}
        else if (frame.type === FRAME.ACK) {check(!receipt, 'FRAME_ORDER'); finalizing = true; nativeResolve();}
        else if (frame.type === FRAME.RESULT) {check(!receipt, 'DUPLICATE_RESULT'); receipt = decode(frame.bytes);}
        else if (frame.type === FRAME.FINISH) {check(receipt && frame.bytes.length === 0, 'FINALIZATION'); final = true; queue.end(); resultResolve(receipt); return;}
        else throw Error('FRAME_ORDER');
      }
    } catch {fail();}
  })();
  return {
    entry,
    disclosurePolicy: selectedDisclosure,
    stats,
    read: () => queue.read(),
    async write(bytes) {
      check(!failed && !closing && !finalizing, 'CHANNEL_REFUSED'); check(!writing, 'CONCURRENT_WRITE');
      check(bytes instanceof Uint8Array, 'BINARY_REQUIRED'); writing = true;
      let written; writeSettled = new Promise(resolve => {written = resolve;});
      try {
        stats.sent += bytes.length;
        for (let i = 0; i < bytes.length; i += MAX_FRAME) {
          await credits.acquire(); check(!failed && !closing, 'CHANNEL_REFUSED');
          await wire.write(await outgoing.frames.seal(FRAME.DATA, bytes.subarray(i, i + MAX_FRAME)));
        }
      } catch (error) {fail(); throw error;} finally {writing = false; written();}
    },
    async finish(facts) {
      check(!failed && !closing && !finishing, 'CHANNEL_REFUSED'); finishing = true;
      // SDK reveal() requests mux shutdown without joining its background
      // driver. Keep accepting its bounded serial tail writes until the native
      // verifier has joined its driver and acknowledged the result.
      await nativeDone; check(!failed, 'CHANNEL_REFUSED');
      await writeSettled; check(!failed && !closing, 'CHANNEL_REFUSED');
      await wire.write(await outgoing.frames.seal(FRAME.FINISH));
      const result = await terminal; check(final, 'TRUNCATED');
      const value=offer.body.identity?result.receipt:result;
      await checkReceipt(value, ticket, offer, grant, cfg.apiKey, cfg.policy, facts);
      if(offer.body.identity){
        check(typeof facts.accountId==='string','LOCAL_FACTS');
        const confirmation=await incoming.accountConfirmation(accountConfirmationMessage(offer.body.identity,provider,facts.accountId,value.body.pseudonym));
        check(result.accountConfirmation===confirmation,'ACCOUNT_CONFIRMATION');
      }
      // Only delivery follows the independently validated hardware receipt here.
      // A lost HTTP response leaves acceptance unknown; durable outbox recovery and
      // the page's authenticated saved-record read decide success.
      let accepted;
      try { accepted = await fetch(cfg.api + '/result', {method: 'POST', headers, body: JSON.stringify({receipt: value, ticket, offer, grant}), signal: AbortSignal.timeout(10000)}); }
      catch { throw Error('API_REFUSED'); }
      check(accepted.ok, 'API_REFUSED');
      return {receipt: value, apiAccepted: true, clientAccepted: true};
    },
    close() {
      if (closePromise) return closePromise;
      closing = true; credits.fail(); clearTimeout(timer);
      closePromise = (async () => {
        if (!final) {try {await wire.write(await outgoing.frames.seal(FRAME.CANCEL));} catch {}}
        await wire.close(); await writeSettled; await pump; outgoing.frames.destroy(); incoming.destroy();
      })();
      return closePromise;
    },
  };
}
