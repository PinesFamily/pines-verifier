import {mkdir, writeFile} from 'node:fs/promises';
import {createHash, randomBytes} from 'node:crypto';
import {request} from 'node:https';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {chromium} from 'playwright';

// Claude plan qualification probe.
//
// Read-only. It answers the questions a `pines.claude.plan` schema cannot be written without:
// which fixed route carries a stable identity and the plan, which paid tier values exist, how large
// the response is, and which cookies a non-browser HTTP/1.1 client needs. It produces no proof,
// receipt or claim and loads no extension.
//
// Same rule as the ChatGPT qualification: values
// stay in memory. The report carries JSON key names, sizes, plan enums, and salted equality tags
// whose salt is random per run and never written, so a tag says "same value as" and nothing else.

const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
const ORIGIN = 'https://claude.ai';
// Fixed routes only: a TLSN schema pins one path (schema.ts), so a route that needs an ID in its
// path is measured as the fallback, not the goal.
export const FIXED_ROUTES = ['/api/organizations', '/api/account', '/api/bootstrap'];
const STATUS_ONLY = new Set(['/api/bootstrap']);

// Runs inside the signed-in claude.ai tab. Self-contained: `page.evaluate` serializes it.
// `env` exists for the unit test; in the page it is the page's own global scope.
export async function pageProbe({salt, routes, statusOnly}, env = globalThis) {
  const ENUM_KEYS = new Set(['rate_limit_tier', 'billing_type', 'raven_type', 'capabilities', 'role', 'seat_tier',
    'subscription_status', 'plan', 'plan_type', 'tier', 'type']);
  const ID_KEYS = new Set(['uuid', 'id', 'account_uuid', 'organization_uuid', 'user_id', 'userId']);
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const enumLike = v => typeof v === 'string' && /^[a-z][a-z0-9_.:-]{0,63}$/i.test(v) && !/[0-9a-f]{8}-/i.test(v);
  const hex = async value => [...new Uint8Array(await env.crypto.subtle.digest('SHA-256',
    new env.TextEncoder().encode(salt + ':' + value)))].map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 12);
  const safeKey = k => /^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(k) && !/[0-9a-f]{8}/i.test(k) ? k : '<key>';
  async function shape(value, key, depth) {
    if (value === null) return 'null';
    if (typeof value === 'boolean' || typeof value === 'number') return typeof value;
    if (typeof value === 'string') {
      if (ENUM_KEYS.has(key) && enumLike(value)) return {enum: value};
      if (uuid.test(value)) return ID_KEYS.has(key) ? {uuid: true, tag: await hex(value.toLowerCase())} : {uuid: true};
      return {string: value.length};
    }
    if (Array.isArray(value)) {
      if (ENUM_KEYS.has(key) && value.every(enumLike)) return {enums: [...value]};
      const items = [];
      if (depth > 0) for (const item of value.slice(0, 10)) items.push(await shape(item, key, depth - 1));
      return {length: value.length, items};
    }
    if (typeof value === 'object') {
      if (depth <= 0) return {object: Object.keys(value).length};
      const out = {}, keys = Object.keys(value);
      for (const k of keys.slice(0, 80)) out[safeKey(k)] = await shape(value[k], k, depth - 1);
      if (keys.length > 80) out['<more>'] = keys.length - 80;
      return out;
    }
    return 'other';
  }
  async function read(path, depth) {
    try {
      const response = await env.fetch(path, {credentials: 'same-origin', redirect: 'manual', headers: {accept: 'application/json'}});
      const text = await response.text();
      const entry = {status: response.status, contentType: (response.headers.get('content-type') || '').split(';')[0],
        bytes: new env.TextEncoder().encode(text).length};
      if (response.ok && !statusOnly.includes(path)) {try {entry.shape = await shape(JSON.parse(text), '', depth);} catch {entry.json = false;}}
      return {entry, body: response.ok ? text : null};
    } catch {return {entry: {status: 0}, body: null};}
  }

  const report = {routes: {}, organizations: [], client: null}, targets = [];
  for (const path of routes) {
    const {entry, body} = await read(path, 4);
    report.routes[path] = entry;
    if (path === '/api/organizations' && body) {
      let list = [];
      try {list = JSON.parse(body);} catch {}
      if (Array.isArray(list)) for (const org of list.slice(0, 10)) {
        if (!org || typeof org.uuid !== 'string' || !uuid.test(org.uuid)) continue;
        const one = `/api/organizations/${org.uuid.toLowerCase()}`;
        const {entry: detail} = await read(one, 3);
        report.organizations.push({tag: await hex(org.uuid.toLowerCase()), detail});
        targets.push(one);
      }
    }
  }

  // The tier vocabulary from Claude's own public client code — so the paid allowlist is not just
  // whatever the one qualifying account happens to be on. Code, not user data.
  const scripts = new Set();
  for (const s of env.document?.scripts ?? []) if (s.src) scripts.add(s.src);
  for (const r of env.performance?.getEntriesByType?.('resource') ?? []) if (/\.m?js(\?|$)/.test(r.name)) scripts.add(r.name);
  const tiers = new Set(), caps = new Set(), paths = new Set();
  let scanned = 0, scannedBytes = 0;
  for (const src of [...scripts].slice(0, 120)) {
    try {
      const response = await env.fetch(src, {credentials: 'omit'});
      if (!response.ok) continue;
      const code = await response.text(); scanned++; scannedBytes += code.length;
      for (const m of code.matchAll(/\bdefault_claude_[a-z0-9_]{1,40}\b/g)) tiers.add(m[0]);
      for (const m of code.matchAll(/["'`]((?:claude_(?:pro|max|team|enterprise)|raven)[a-z0-9_]{0,40})["'`]/g)) caps.add(m[1]);
      for (const m of code.matchAll(/["'`](\/api\/(?:account|organizations|bootstrap|auth)[A-Za-z0-9_/${}.-]{0,100})["'`]/g))
        if (!/[0-9a-f]{8}-/i.test(m[1])) paths.add(m[1]);
    } catch {}
  }
  report.client = {scripts: scripts.size, scanned, scannedBytes,
    rateLimitTiers: [...tiers].sort().slice(0, 100), capabilityNames: [...caps].sort().slice(0, 100),
    routes: [...paths].sort().slice(0, 200)};
  report.userAgent = env.navigator?.userAgent ?? '';
  return {report, targets};
}

// The only fields that leave this process. Everything is re-projected, then the serialized
// result is scanned: one UUID, e-mail address or token-shaped string anywhere and nothing is written.
export function claudeProbeReport(raw, cookies, replays, browserVersion) {
  const report = {
    measuredAt: new Date().toISOString(), browser: String(browserVersion).replace(/[^\w./ -]/g, '').slice(0, 64),
    kind: 'claude-plan-qualification-probe', claimable: false,
    routes: raw.routes, organizations: raw.organizations, client: raw.client,
    cookies: cookies.map(c => ({name: c.name, httpOnly: Boolean(c.httpOnly), bytes: c.value.length})),
    replays,
  };
  const text = JSON.stringify(report, null, 2);
  if (UUID.test(text) || /[^\s"@]+@[^\s"@]+\.[a-z]{2,}/i.test(text) || /[A-Za-z0-9_+=-]{48,}/.test(text))
    throw Error('PROBE_REPORT_LEAK');
  return text + '\n';
}

// A non-browser HTTP/1.1 client with the TLSN request's fixed headers (src/prove-worker.js)
// and a chosen cookie set. Answers "which cookies are needed" — the schema's allowlist.
function replay(path, headers) {
  return new Promise(done => {
    const req = request({host: 'claude.ai', servername: 'claude.ai', path, method: 'GET', agent: false,
      ALPNProtocols: ['http/1.1'], headers, timeout: 15000}, res => {
      const chunks = []; let size = 0;
      res.on('data', c => {size += c.length; if (size <= 1 << 20) chunks.push(c);});
      res.on('end', () => done({status: res.statusCode, bytes: size, mitigated: Boolean(res.headers['cf-mitigated']),
        encoding: res.headers['content-encoding'] ?? 'identity', body: Buffer.concat(chunks).toString('utf8')}));
    });
    req.on('timeout', () => req.destroy(Error('timeout')));
    req.on('error', () => done({status: 0, bytes: 0, mitigated: false, encoding: null, body: ''}));
    req.end();
  });
}

async function probe() {
  const endpoint = process.env.TLSN_BROWSER_CDP ?? 'http://127.0.0.1:9222';
  if (!/^http:\/\/(127\.0\.0\.1|localhost):\d{1,5}$/.test(endpoint)) throw Error('LOOPBACK_CDP_REQUIRED');
  const salt = randomBytes(32).toString('hex');
  const tag = value => createHash('sha256').update(salt + ':' + value).digest('hex').slice(0, 12);
  const browser = await chromium.connectOverCDP(endpoint, {timeout: 10000});
  try {
    const context = browser.contexts()[0];
    const tabs = context.pages().filter(page => {try {return new URL(page.url()).origin === ORIGIN;} catch {return false;}});
    if (tabs.length !== 1) throw Error('OPEN_ONE_CLAUDE_TAB');
    const {report, targets} = await tabs[0].evaluate(pageProbe, {salt, routes: FIXED_ROUTES, statusOnly: [...STATUS_ONLY]});
    const cookies = await context.cookies(ORIGIN);
    const jar = names => cookies.filter(c => names === null || names.includes(c.name)).map(c => `${c.name}=${c.value}`).join('; ');
    const variants = {all: null, sessionKey: ['sessionKey'], sessionKeyLastActiveOrg: ['sessionKey', 'lastActiveOrg'], none: []};
    const replays = {};
    for (const path of [...FIXED_ROUTES.filter(p => report.routes[p]?.status === 200), ...targets.slice(0, 3)]) {
      const label = path.replace(UUID, m => `<org:${tag(m.toLowerCase())}>`);
      replays[label] = {};
      for (const [name, names] of Object.entries(variants)) {
        const cookie = jar(names);
        const r = await replay(path, {host: 'claude.ai', accept: 'application/json', 'user-agent': report.userAgent,
          'accept-encoding': 'identity', connection: 'close', ...(cookie ? {cookie} : {})});
        let sameIdentity = null;
        if (r.status === 200) try {
          const json = JSON.parse(r.body);
          const ids = (Array.isArray(json) ? json : [json]).map(o => o?.uuid).filter(v => typeof v === 'string');
          sameIdentity = ids.length ? ids.map(v => tag(v.toLowerCase())) : null;
        } catch {}
        replays[label][name] = {status: r.status, bytes: r.bytes, cloudflareMitigated: r.mitigated, encoding: r.encoding, identityTags: sameIdentity};
      }
    }
    delete report.userAgent;
    const text = claudeProbeReport(report, cookies, replays, browser.version());
    const reports = fileURLToPath(new URL('../reports/', import.meta.url)); await mkdir(reports, {recursive: true});
    await writeFile(join(reports, 'claude-probe.json'), text, {mode: 0o600});
    console.log(text);
  } finally {
    // connectOverCDP: close() disconnects and leaves your browser and tabs running.
    await browser.close();
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  probe().catch(error => {
    const code = /^[A-Z_]+$/.test(error?.message) ? error.message : 'CLAUDE_PROBE_FAILED';
    console.error(`${code}: keep exactly one signed-in claude.ai tab open in the hosted browser (ops/tlsn-browser.sh).`);
    process.exitCode = 1;
  });
}
