// Bounded IoChannel transport adapted from the pinned fork's worker and the Pines
// protocol spike. The owning ProveManager terminates its dedicated worker on cancel.
export async function openSocket(url, binary = false) {
  const socket = new WebSocket(url);
  if (binary) socket.binaryType = 'arraybuffer';
  const stats = { sent: 0, received: 0 };
  const queue = [];
  let queuedBytes = 0;
  let pending;
  let closed = false;
  let failure;
  let opened = false;
  let resolveOpen;
  let rejectOpen;
  const ready = new Promise((resolve, reject) => {
    resolveOpen = resolve;
    rejectOpen = reject;
  });
  const size = (data) => typeof data === 'string' ? new TextEncoder().encode(data).length : data.byteLength;
  const fail = (error) => {
    failure = error;
    closed = true;
    rejectOpen(error);
    pending?.reject(error);
    pending = undefined;
    socket.close();
  };
  socket.onopen = () => { opened = true; resolveOpen(); };
  socket.onerror = () => fail(new Error(`WebSocket failed: ${new URL(url).pathname}`));
  socket.onclose = () => {
    closed = true;
    if (!opened) rejectOpen(new Error('WebSocket closed before opening'));
    pending?.resolve(null);
    pending = undefined;
  };
  socket.onmessage = ({ data }) => {
    if (closed) return;
    if ((binary && !(data instanceof ArrayBuffer)) || (!binary && typeof data !== 'string')) {
      fail(new Error('Unexpected WebSocket message type'));
      return;
    }
    const value = binary ? new Uint8Array(data) : data;
    stats.received += size(value);
    if (pending) {
      pending.resolve(value);
      pending = undefined;
    } else {
      queuedBytes += size(value);
      if (queuedBytes > 16 * 1024 * 1024) {
        fail(new Error('WebSocket read queue exceeded 16 MiB'));
        return;
      }
      queue.push(value);
    }
  };
  const connectTimer = setTimeout(() => fail(new Error('WebSocket connection timed out')), 10_000);
  try { await ready; } finally { clearTimeout(connectTimer); }
  return {
    stats,
    async read() {
      if (failure) throw failure;
      if (queue.length) {
        const value = queue.shift();
        queuedBytes -= size(value);
        return value;
      }
      if (closed) return null;
      if (pending) throw new Error('Concurrent reads are unsupported');
      return new Promise((resolve, reject) => { pending = { resolve, reject }; });
    },
    async write(data) {
      if (failure) throw failure;
      if (closed) throw new Error('WebSocket is closed');
      stats.sent += size(data);
      socket.send(data);
    },
    async close() {
      closed = true;
      pending?.resolve(null);
      pending = undefined;
      socket.close();
    },
  };
}
