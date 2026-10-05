import {check} from './wire.mjs';

export function byteQueue(limit = 16 * 1024 * 1024) {
  let pending, failure, ended = false, size = 0; const chunks = [];
  return {
    push(bytes) {check(!ended && !failure, 'QUEUE_CLOSED'); if (pending) {pending.resolve(bytes); pending = undefined;}
      else {size += bytes.length; check(size <= limit, 'QUEUE_LIMIT'); chunks.push(bytes);}},
    read() {if (failure) return Promise.reject(failure); if (chunks.length) {const b = chunks.shift(); size -= b.length; return Promise.resolve(b);}
      if (ended) return Promise.resolve(null); check(!pending, 'CONCURRENT_READ'); return new Promise((resolve, reject) => {pending = {resolve, reject};});},
    end() {ended = true; pending?.resolve(null); pending = undefined;},
    fail() {failure = Error('TRANSPORT_REFUSED'); ended = true; chunks.length = 0; size = 0; pending?.reject(failure); pending = undefined;},
  };
}

export async function openRaw(url) {
  const socket = new WebSocket(url); socket.binaryType = 'arraybuffer';
  const queue = byteQueue(); let closed = false, total = 0;
  socket.onmessage = ({data}) => {try {check(data instanceof ArrayBuffer, 'BINARY_REQUIRED'); total += data.byteLength; check(total <= 70 * 1024 * 1024, 'WIRE_LIMIT'); queue.push(new Uint8Array(data));} catch {queue.fail(); socket.close();}};
  socket.onclose = () => {closed = true; queue.end();};
  socket.onerror = () => queue.fail();
  let timer;
  try {await Promise.race([new Promise((resolve, reject) => {socket.onopen = resolve; socket.addEventListener('error', reject, {once: true}); socket.addEventListener('close', reject, {once: true});}),
    new Promise((_, reject) => {timer = setTimeout(() => {socket.close(); reject(Error('CONNECT_DEADLINE'));}, 10000);})]);} finally {clearTimeout(timer);}
  return {read: () => queue.read(), async write(bytes) {check(!closed && socket.bufferedAmount + bytes.byteLength <= 16 * 1024 * 1024, 'WIRE_QUEUE'); socket.send(bytes);},
    async close() {closed = true; queue.end(); socket.close();}, abort() {queue.fail(); socket.close();}};
}
