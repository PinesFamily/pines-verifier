// Candidate application framing over maintained RFC 9180 Auth-mode contexts.
// Independent review and real Nitro qualification are still required.
import {Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256} from '@hpke/core';
import {check, hex, unhex, lp} from './wire.mjs';

export const SUITE = 'HPKE-Auth-P256-HKDFSHA256-AES128GCM/pines-stream-v1';
export const suite = new CipherSuite({kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm()});
export const channelKey = () => suite.kem.generateKeyPair();
export const exportChannelKey = async key => hex(await suite.kem.serializePublicKey(key));
export const importChannelKey = key => suite.kem.deserializePublicKey(unhex(key, 65));
export const FRAME = Object.freeze({CONFIRM: 1, DATA: 2, FINISH: 3, RESULT: 4, CANCEL: 5, ACK: 6});
export const MAX_FRAME = 64 * 1024;
const MAX_TOTAL = 64 * 1024 * 1024;

export async function sender(key, peer, binding, direction) {
  const info = lp([SUITE, binding, direction]);
  const context = await suite.createSenderContext({recipientPublicKey: await importChannelKey(peer), senderKey: key, info});
  return {enc: hex(context.enc), frames: new Frames(context, binding, direction, true)};
}
export async function receiver(key, peer, enc, binding, direction) {
  const context = await suite.createRecipientContext({recipientKey: key, senderPublicKey: await importChannelKey(peer), enc: unhex(enc, 65), info: lp([SUITE, binding, direction])});
  return new Frames(context, binding, direction, false);
}

class Frames {
  #context; #binding; #direction; #send; #sequence = 0; #total = 0; #closed = false; #chain = Promise.resolve();
  constructor(context, binding, direction, send) {this.#context = context; this.#binding = binding; this.#direction = direction; this.#send = send;}
  // Serialize seal/open even if the caller invokes them concurrently.
  #run(fn) {
    const result = this.#chain.then(async () => {check(!this.#closed, 'CHANNEL_CLOSED'); try {return await fn();} catch {this.#closed = true; throw Error('CHANNEL_REFUSED');}});
    this.#chain = result.catch(() => {}); return result;
  }
  #header(type, length) {
    check(Object.values(FRAME).includes(type) && this.#sequence < 0xffffffff && length <= MAX_FRAME, 'FRAME_LIMIT');
    this.#total += length; check(this.#total <= MAX_TOTAL, 'CHANNEL_LIMIT');
    const header = new Uint8Array(5); header[0] = type; new DataView(header.buffer).setUint32(1, this.#sequence++); return header;
  }
  seal(type, bytes = new Uint8Array()) {
    return this.#run(async () => {
      check(this.#send && bytes instanceof Uint8Array, 'CHANNEL_ROLE');
      const head = this.#header(type, bytes.length);
      const ciphertext = new Uint8Array(await this.#context.seal(bytes, lp([this.#binding, this.#direction, head])));
      const frame = new Uint8Array(5 + ciphertext.length); frame.set(head); frame.set(ciphertext, 5);
      if (type === FRAME.FINISH || type === FRAME.CANCEL) this.#closed = true;
      return frame;
    });
  }
  open(frame) {
    return this.#run(async () => {
      check(!this.#send && frame instanceof Uint8Array && frame.length >= 21 && frame.length <= MAX_FRAME + 21, 'FRAME_LIMIT');
      const head = frame.subarray(0, 5), type = head[0];
      check(new DataView(head.buffer, head.byteOffset, 5).getUint32(1) === this.#sequence, 'SEQUENCE');
      this.#header(type, frame.length - 21);
      const bytes = new Uint8Array(await this.#context.open(frame.subarray(5), lp([this.#binding, this.#direction, head])));
      if (type === FRAME.FINISH || type === FRAME.CANCEL) this.#closed = true;
      return {type, bytes};
    });
  }
  destroy() {this.#closed = true; this.#context = undefined;}
}
