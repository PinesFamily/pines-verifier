// Ciphertext relay candidate. Admission is disabled by default.
// Design: Grok assistance design. No provider TLS terminates here.
import https from 'node:https';
import net from 'node:net';
import {lookup as systemLookup} from 'node:dns/promises';
import {createHash, randomBytes, timingSafeEqual} from 'node:crypto';
import {Transform} from 'node:stream';

export const PROOF_HOSTS = Object.freeze(['chatgpt.com', 'claude.ai', 'grok.com']);
export const BROWSER_HOSTS = Object.freeze(['grok.com']);
export const LIMITS = Object.freeze({
  leaseMs: 120_000, browserConnections: 8, verifierConnections: 1,
  browserBytes: 8 * 1024 * 1024, leaseBytes: 32 * 1024 * 1024,
  verifierBytes: 131_072, lifetimeMs: 310_000, idleMs: 30_000,
  setupMs: 10_000, headerBytes: 8192, pendingConnections: 16,
  failuresPerMinute: 32,
});
const sha = value => createHash('sha256').update(value).digest();
const fail = code => {throw Error(code);};

export function publicAddress(address) {
  if (net.isIP(address) === 4) {
    const [a, b, c] = address.split('.').map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224
      || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)) || (b === 88 && c === 99)))
      || (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100)))
      || (a === 203 && b === 0 && c === 113));
  }
  if (net.isIP(address) !== 6 || address.includes('%')) return false;
  const words = address.toLowerCase().split(':');
  const first = Number.parseInt(words[0], 16), second = Number.parseInt(words[1] || '0', 16);
  return first >= 0x2000 && first < 0x4000 && first !== 0x2002 && first !== 0x3ffe && first !== 0x3fff
    && !(first === 0x2001 && (second <= 0x01ff || second === 0x0db8));
}

export function destination(authority, kind) {
  const allowed = kind === 'browser' ? BROWSER_HOSTS : kind === 'verifier' ? PROOF_HOSTS : [];
  const host = allowed.find(host => authority === `${host}:443`);
  if (!host) fail('DESTINATION_REFUSED');
  return host;
}

async function bounded(promise, milliseconds) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(Error('SETUP_TIMEOUT')), milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}

export async function resolveDestination(host, lookup = systemLookup) {
  if (!PROOF_HOSTS.includes(host)) fail('DESTINATION_REFUSED');
  const addresses = await bounded(lookup(host, {all: true, verbatim: true}), LIMITS.setupMs);
  if (!Array.isArray(addresses) || addresses.length < 1 || addresses.length > 16
    || addresses.some(row => !publicAddress(row.address) || net.isIP(row.address) !== row.family)) fail('DNS_REFUSED');
  // Both sides must leave the reserved IPv4. An AAAA answer must never choose a
  // second egress identity, even when its address is otherwise public.
  const selected = addresses.find(row => row.family === 4);
  if (!selected) fail('IPV4_REQUIRED');
  return Object.freeze({address: selected.address, family: 4, port: 443});
}

const connect = (address, {signal} = {}) => new Promise((resolve, reject) => {
  const socket = net.connect({host: address.address, family: address.family, port: 443, signal});
  socket.setTimeout(LIMITS.setupMs, () => socket.destroy(Error('CONNECT_TIMEOUT')));
  socket.once('connect', () => {socket.setTimeout(0); resolve(socket);});
  socket.once('error', reject);
});

export class AddressAdmission {
  #ip; #group; #now; #enabled = false; #lease; #timer;
  #verifiers = 0; #sockets = new Set(); #browserCount = 0; #counter = 0;
  constructor({egressIpv4, group, now = Date.now}) {
    if (net.isIP(egressIpv4) !== 4 || !publicAddress(egressIpv4)
      || !/^[a-z0-9-]{1,48}$/.test(group)) fail('ADDRESS_CONFIGURATION');
    this.#ip = egressIpv4; this.#group = group; this.#now = now;
  }
  setEnabled(value) {
    if (typeof value !== 'boolean') fail('ADMISSION_CONFIGURATION');
    this.#enabled = value;
    if (!value) {this.revoke(); for (const socket of this.#sockets) socket.destroy();}
  }
  #expire() {if (this.#lease && this.#now() >= this.#lease.expiresAt) this.revoke();}
  admit({group, egressIpv4, deadline}) {
    this.#expire();
    if (!this.#enabled) fail('ASSISTANCE_DISABLED');
    if (group !== this.#group || egressIpv4 !== this.#ip) fail('ADDRESS_PIN');
    if (this.#lease || this.#verifiers || this.#browserCount) fail('ADDRESS_BUSY');
    const credential = randomBytes(32).toString('hex');
    const now = this.#now();
    if (deadline !== undefined && (!Number.isSafeInteger(deadline) || deadline <= now || deadline > now + LIMITS.leaseMs)) fail('LEASE_DEADLINE');
    const expiresAt = deadline ?? now + LIMITS.leaseMs;
    this.#lease = {hash: sha(credential), expiresAt, bytes: 0, sockets: new Set(), generation: ++this.#counter};
    this.#timer = setTimeout(() => this.revoke(), expiresAt - now); this.#timer.unref();
    return Object.freeze({credential, expiresAt, group: this.#group, egressIpv4: this.#ip});
  }
  authenticate(authorization) {
    this.#expire();
    if (!this.#enabled || !this.#lease || typeof authorization !== 'string' || authorization.length > 256) return false;
    const encoded = /^Basic ([A-Za-z0-9+/]+={0,2})$/.exec(authorization)?.[1];
    if (!encoded) return false;
    const bytes = Buffer.from(encoded, 'base64');
    if (bytes.toString('base64') !== encoded) return false;
    const decoded = bytes.toString('utf8');
    if (!/^pines:[a-f0-9]{64}$/.test(decoded)) return false;
    return timingSafeEqual(sha(decoded.slice(6)), this.#lease.hash);
  }
  browser(socket) {
    this.#expire();
    if (!this.#enabled || !this.#lease) fail('LEASE_EXPIRED');
    if (this.#browserCount >= LIMITS.browserConnections) fail('CONNECTION_LIMIT');
    const lease = this.#lease;
    this.#browserCount++; this.#sockets.add(socket); lease.sockets.add(socket);
    let released = false;
    const release = () => {
      if (released) return; released = true;
      this.#browserCount--; this.#sockets.delete(socket); lease.sockets.delete(socket);
    };
    socket.once('close', release);
    return {expiresAt: lease.expiresAt, release,
      consume: bytes => {
        this.#expire();
        if (this.#lease !== lease || !this.#enabled) fail('LEASE_EXPIRED');
        if (!Number.isSafeInteger(bytes) || bytes < 0 || lease.bytes + bytes > LIMITS.leaseBytes) fail('LEASE_BYTE_LIMIT');
        lease.bytes += bytes;
      }};
  }
  verifier(socket) {
    this.#expire();
    if (!this.#enabled || !this.#lease) fail('ASSISTANCE_DISABLED');
    if (this.#verifiers >= LIMITS.verifierConnections) fail('CONNECTION_LIMIT');
    // Count at worker-group level only. The raw stream is never attributed to
    // an attempt, visitor or lease; no inferred stream-to-attempt mapping.
    this.#verifiers++; this.#sockets.add(socket);
    let released = false;
    const release = () => {if (!released) {released = true; this.#verifiers--; this.#sockets.delete(socket);}};
    socket.once('close', release);
    return {release, expiresAt: Math.min(this.#lease.expiresAt, this.#now() + LIMITS.lifetimeMs), consume: () => {}};
  }
  revoke() {
    clearTimeout(this.#timer);
    const lease = this.#lease; this.#lease = undefined;
    // The address's whole admission window ends together. Retire every group
    // stream before allowing another visitor; there is still no attempt mapping.
    if (lease) {lease.hash.fill(0); for (const socket of this.#sockets) socket.destroy();}
  }
  status() {
    this.#expire();
    return Object.freeze({enabled: this.#enabled, group: this.#group, egressIpv4: this.#ip,
      occupied: Boolean(this.#lease || this.#verifiers || this.#browserCount),
      browserConnections: this.#browserCount, verifierConnections: this.#verifiers,
      leaseBytes: this.#lease?.bytes ?? 0, leaseActive: Boolean(this.#lease)});
  }
}

function bridge(client, peer, reservation, kind, now, inspectCiphertext) {
  let closed = false;
  const stop = () => {
    if (closed) return; closed = true; clearTimeout(timer);
    client.destroy(); peer.destroy(); reservation.release();
  };
  const duration = Math.max(0, Math.min(LIMITS.lifetimeMs, reservation.expiresAt - now()));
  const timer = setTimeout(stop, duration); timer.unref();
  const cap = kind === 'browser' ? LIMITS.browserBytes : LIMITS.verifierBytes;
  let combined = 0;
  const meter = direction => {
    let total = 0; const context = {kind, direction, stream: Symbol(direction)};
    const stream = new Transform({transform(chunk, _, callback) {
      try {
        if (total + chunk.length > cap || (kind === 'browser' && combined + chunk.length > cap)) fail('CONNECTION_BYTE_LIMIT');
        reservation.consume(chunk.length); total += chunk.length; combined += chunk.length;
        inspectCiphertext?.(chunk, context); callback(null, chunk);
      } catch { callback(Error('RELAY_LIMIT')); }
    }});
    stream.on('error', stop); return stream;
  };
  for (const socket of [client, peer]) {
    socket.setTimeout(LIMITS.idleMs, stop);
    socket.on('error', stop); socket.on('close', stop); socket.on('end', stop);
  }
  client.pipe(meter('client-to-provider')).pipe(peer); peer.pipe(meter('provider-to-client')).pipe(client);
}

const refuse = (socket, status) => {
  const auth = status === 407 ? 'Proxy-Authenticate: Basic realm="Pines verification"\r\n' : '';
  socket.end(`HTTP/1.1 ${status} Refused\r\n${auth}Content-Length: 0\r\nConnection: close\r\n\r\n`);
};

/** Operator-supplied TLS configuration; no HTTP management API is exposed.
 * lookup/dial injection is for synthetic qualification, never browser input.
 */
export function createRelay({egressIpv4, group, browserTls, verifierTls, parentFingerprint,
  control, inspectCiphertext, now = Date.now, lookup = systemLookup, dial = connect}) {
  if (!/^[A-F0-9]{64}$/.test(parentFingerprint ?? '')) fail('PARENT_CERTIFICATE_PIN');
  if (!browserTls?.key || !browserTls?.cert || !verifierTls?.key || !verifierTls?.cert || !verifierTls?.ca) fail('TLS_CONFIGURATION');
  const admission = new AddressAdmission({egressIpv4, group, now});
  const counters = {acceptedBrowser: 0, acceptedVerifier: 0, refused: 0, failedDial: 0};
  let failures = 0, failureWindow = now();
  const servers = [], allSockets = new Set(), headerTimers = new WeakMap();
  const make = kind => {
    const server = https.createServer({...kind === 'browser' ? browserTls : verifierTls,
      minVersion: 'TLSv1.2', maxHeaderSize: LIMITS.headerBytes,
      handshakeTimeout: LIMITS.setupMs,
      requestCert: kind === 'verifier', rejectUnauthorized: kind === 'verifier'}, (request, response) => {
      // Management uses the trusted parent's separate mTLS authority. Browser
      // credentials can never reach it, even on a valid browser CONNECT lease.
      if (control && kind === 'verifier' && request.socket.authorized
        && request.socket.getPeerCertificate()?.fingerprint256?.replaceAll(':', '') === parentFingerprint
        && request.headers['proxy-authorization'] === undefined) {
        clearTimeout(headerTimers.get(request.socket));
        void Promise.resolve(control(request, response, admission)).catch(() => request.socket.destroy()); return;
      }
      response.writeHead(405, {'content-length': '0', connection: 'close'}); response.end();
    });
    server.headersTimeout = LIMITS.setupMs;
    server.requestTimeout = LIMITS.setupMs;
    server.timeout = LIMITS.setupMs;
    server.maxConnections = LIMITS.pendingConnections;
    server.on('connection', socket => {
      allSockets.add(socket); socket.once('close', () => allSockets.delete(socket));
      socket.setTimeout(LIMITS.setupMs, () => socket.destroy());
    });
    server.on('clientError', (_, socket) => socket.destroy());
    server.on('tlsClientError', () => {});
    server.on('secureConnection', socket => {
      const timer = setTimeout(() => socket.destroy(), LIMITS.setupMs); timer.unref();
      headerTimers.set(socket, timer); socket.once('close', () => clearTimeout(timer));
    });
    server.on('connect', async (request, client, head) => {
      let reservation, peer;
      clearTimeout(headerTimers.get(client));
      const controller = new AbortController();
      client.once('close', () => controller.abort());
      try {
        if (now() - failureWindow >= 60_000) {failureWindow = now(); failures = 0;}
        if (failures >= LIMITS.failuresPerMinute) {refuse(client, 429); return;}
        const host = destination(request.url, kind);
        if (head.length !== 0) fail('EARLY_DATA_REFUSED');
        const authHeaders = request.rawHeaders.filter((_, index) => index % 2 === 0)
          .filter(name => name.toLowerCase() === 'proxy-authorization');
        if (authHeaders.length > 1 || request.headers['transfer-encoding'] !== undefined
          || (request.headers['content-length'] !== undefined && request.headers['content-length'] !== '0')) fail('CONNECT_FRAMING');
        if (kind === 'browser') {
          if (!admission.authenticate(request.headers['proxy-authorization'])) {
            failures++; counters.refused++; refuse(client, 407); return;
          }
          reservation = admission.browser(client);
        } else {
          const fingerprint = client.getPeerCertificate()?.fingerprint256?.replaceAll(':', '');
          if (!client.authorized || fingerprint !== parentFingerprint) fail('PARENT_CERTIFICATE_REFUSED');
          // A browser token is invalid on this listener, even with an otherwise
          // authorized client certificate. Verifier authorization is mTLS only.
          if (request.headers['proxy-authorization'] !== undefined) fail('AUTHORIZATION_DOMAIN');
          reservation = admission.verifier(client);
        }
        client.pause();
        const address = await resolveDestination(host, lookup);
        if (client.destroyed || now() >= reservation.expiresAt) fail('CLIENT_RETIRED');
        peer = await bounded(Promise.resolve().then(() => dial(address, {signal: controller.signal})).then(socket => {
          if (controller.signal.aborted) {socket.destroy(); fail('CLIENT_RETIRED');}
          return socket;
        }), LIMITS.setupMs);
        if (client.destroyed || now() >= reservation.expiresAt || !admission.status().enabled) fail('CLIENT_RETIRED');
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        counters[kind === 'browser' ? 'acceptedBrowser' : 'acceptedVerifier']++;
        bridge(client, peer, reservation, kind, now, inspectCiphertext); client.resume();
      } catch {
        controller.abort();
        failures++; counters.refused++;
        if (reservation) counters.failedDial++;
        peer?.destroy(); reservation?.release();
        if (!client.destroyed) refuse(client, 403);
      }
    });
    servers.push(server); return server;
  };
  const browser = make('browser'), verifier = make('verifier');
  return Object.freeze({browser, verifier, admission,
    metrics: () => Object.freeze({...counters, ...admission.status()}),
    close: async () => {
      admission.setEnabled(false); for (const socket of allSockets) socket.destroy();
      await Promise.all(servers.map(server => new Promise(resolve => server.close(resolve))));
    }});
}
