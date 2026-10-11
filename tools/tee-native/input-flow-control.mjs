import {check} from './wire.mjs';

// At most 16 unacknowledged DATA frames: even maximum-size frames plus the
// existing queue overhead stay below 4 MiB and 256 messages. Credits acknowledge
// forwarding through the enclave's private native socket, never a proof result.
export const INPUT_FRAME_WINDOW = 16;
const MAX_COUNT = 0xffffffff;

export function encodeInputCredit(consumed) {
  check(Number.isSafeInteger(consumed) && consumed > 0 && consumed <= MAX_COUNT, 'INPUT_CREDIT');
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, consumed);
  return bytes;
}

export function inputCredits() {
  let sent = 0, consumed = 0, pending, failure;
  const reserve = () => {check(sent < MAX_COUNT, 'INPUT_CREDIT'); sent++;};
  return {
    acquire() {
      if (failure) return Promise.reject(failure);
      check(!pending, 'CONCURRENT_WRITE');
      if (sent - consumed < INPUT_FRAME_WINDOW) {reserve(); return Promise.resolve();}
      // The maintained writer is serial. Keep one waiter rather than moving
      // queued proof data into an unbounded collection of blocked writes.
      return new Promise((resolve, reject) => {pending = {resolve, reject};});
    },
    acknowledge(bytes) {
      check(!failure && bytes instanceof Uint8Array && bytes.length === 4, 'INPUT_CREDIT');
      const next = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0);
      check(next > consumed && next <= sent, 'INPUT_CREDIT');
      consumed = next;
      if (pending) {
        reserve(); const waiter = pending; pending = undefined; waiter.resolve();
      }
    },
    fail() {
      failure ??= Error('CHANNEL_REFUSED');
      pending?.reject(failure); pending = undefined;
    },
  };
}
