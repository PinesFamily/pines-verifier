import {mkdir, writeFile} from 'node:fs/promises';
import {createHash, randomBytes} from 'node:crypto';
import {request} from 'node:https';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {chromium} from 'playwright';

// Grok subscription qualification probe.
//
// Read-only, and GET only. It answers the questions a `pines.grok.plan` schema cannot be written without:
// which fixed grok.com route carries both a stable account identity and the subscription tier, which
// tier values exist, how large the response is, and which cookies a non-browser HTTP/1.1 client needs.
// grok.com sits behind Cloudflare bot management, so the last question is also whether a
// non-browser TLS client gets an answer at all. It produces no proof, receipt or claim and loads no extension.
//
// Same rule as the Claude and ChatGPT probes: values stay in memory. The report carries JSON key names,
// sizes, enum values and salted equality tags whose salt is random per run and never written.

const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
const ORIGIN = 'https://grok.com';
// Candidates named after grok.com's REST surface. Whatever the client code references is added to them
// (`pageProbe`), so a wrong guess costs one 404 and a missed route is still found.
export const CANDIDATE_ROUTES = ['/rest/subscriptions', '/rest/user-settings', '/rest/auth/get-user',
  '/rest/app-chat/settings', '/rest/models'];
// A discovered route is read only when it sounds like account or plan data, and never when it sounds
// like it changes something. Everything is a GET, so this is belt and braces.
export const READ_WORTHY = /subscri|user|account|setting|billing|entitle|tier|plan|profile|feature|limit|auth|\/me$/i;
export const NEVER_READ = /logout|sign-?out|delete|remove|revoke|cancel|upload|share|create|\/new\b|update|\/set|reset|stream|voice|upsert|restore|clone/i;
export const CLOUDFLARE_COOKIES = ['cf_clearance', '__cf_bm', '_cfuvid'];

// Runs inside the signed-in grok.com tab. Self-contained: `page.evaluate` serializes it.
// `env` exists for the unit test; in the page it is the page's own global scope.
export async function pageProbe({salt, candidates, readWorthy, neverRead, maxRoutes = 30}, env = globalThis) {
  const ENUM_KEYS = new Set(['tier', 'status', 'plan', 'planType', 'plan_type', 'subscriptionTier', 'subscription_tier',
    'subscriptionStatus', 'subscription_status', 'productId', 'product_id', 'billingPeriod', 'billing_period', 'interval',
    'provider', 'source', 'platform', 'store', 'role', 'kind', 'type', 'entitlements', 'features', 'sku']);
  const ID_KEYS = new Set(['id', 'uuid', 'userId', 'user_id', 'xaiUserId', 'xUserId', 'x_user_id', 'accountId', 'account_id',
    'subscriptionId', 'subscription_id', 'teamId', 'team_id', 'customerId', 'customer_id']);
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const SCREAMING = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+){1,8}$/;
  const enumLike = v => typeof v === 'string' && v.length <= 64 && /^[a-z][a-z0-9_.:-]{0,63}$/i.test(v) && !/[0-9a-f]{8}/i.test(v);
  const worthy = new RegExp(readWorthy, 'i'), never = new RegExp(neverRead, 'i');
  const hex = async value => [...new Uint8Array(await env.crypto.subtle.digest('SHA-256',
    new env.TextEncoder().encode(salt + ':' + value)))].map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 12);
  const safeKey = k => /^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(k) && !/[0-9a-f]{8}/i.test(k) ? k : '<key>';
  // Path segments that look like IDs are masked, so an observed route never carries one.
  const maskPath = p => p.split('/').map(s => /[0-9a-f]{8}|^\d{6,}$|[A-Za-z0-9_-]{24,}/i.test(s) ? '<id>' : s).join('/');
  async function shape(value, key, depth) {
    if (value === null) return 'null';
    if (typeof value === 'boolean') return {bool: value};
    if (typeof value === 'number') return ENUM_KEYS.has(key) && Number.isInteger(value) && Math.abs(value) < 1000 ? {enum: value} : 'number';
    if (typeof value === 'string') {
      if (ID_KEYS.has(key)) return {id: uuid.test(value) ? 'uuid' : /^\d+$/.test(value) ? 'digits' : 'string', tag: await hex(value)};
      if (SCREAMING.test(value) && value.length <= 64) return {enum: value};
      if (ENUM_KEYS.has(key) && enumLike(value)) return {enum: value};
      if (uuid.test(value)) return {uuid: true};
      return {string: value.length};
    }
    if (Array.isArray(value)) {
      if (value.length && value.every(v => typeof v === 'string' && (SCREAMING.test(v) || (ENUM_KEYS.has(key) && enumLike(v)))))
        return {enums: [...value].slice(0, 50)};
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
  async function read(path) {
    try {
      const response = await env.fetch(path, {credentials: 'same-origin', redirect: 'manual', headers: {accept: 'application/json'}});
      const text = await response.text();
      const entry = {status: response.status, contentType: (response.headers.get('content-type') || '').split(';')[0],
        bytes: new env.TextEncoder().encode(text).length};
      if (response.ok) {try {entry.shape = await shape(JSON.parse(text), '', 6);} catch {entry.json = false;}}
      return entry;
    } catch {return {status: 0};}
  }

  // The client code: route literals and the subscription vocabulary. Code, not user data, so the tier
  // allowlist rests on more than whatever the one qualifying account happens to be on.
  const scripts = new Set();
  for (const s of env.document?.scripts ?? []) if (s.src) scripts.add(s.src);
  const resources = env.performance?.getEntriesByType?.('resource') ?? [];
  for (const r of resources) if (/\.m?js(\?|$)/.test(r.name)) scripts.add(r.name);
  const routeLiterals = new Set(), templated = new Set(), tiers = new Set(), statuses = new Set(), words = new Set();
  let scanned = 0, scannedBytes = 0;
  for (const src of [...scripts].slice(0, 250)) {
    try {
      const response = await env.fetch(src, {credentials: 'omit'});
      if (!response.ok) continue;
      const code = await response.text(); scanned++; scannedBytes += code.length;
      for (const m of code.matchAll(/["'`](\/rest\/[A-Za-z0-9_/${}.:-]{1,120})["'`]/g)) {
        if (/[0-9a-f]{8}/i.test(m[1])) continue;
        (/\$\{|\/:/.test(m[1]) ? templated : routeLiterals).add(m[1]);
      }
      for (const m of code.matchAll(/\bSUBSCRIPTION_TIER_[A-Z0-9_]{1,48}\b/g)) tiers.add(m[0]);
      for (const m of code.matchAll(/\bSUBSCRIPTION_STATUS_[A-Z0-9_]{1,48}\b/g)) statuses.add(m[0]);
      for (const m of code.matchAll(/["'`]((?:super_?grok|grok_?(?:pro|heavy|plus|premium|basic|free)|x_?premium|premium_?plus)[A-Za-z0-9_]{0,32})["'`]/gi))
        words.add(m[1]);
    } catch {}
  }
  // What the client itself requested before the probe ran: the evidence for a capture trigger.
  const observed = new Set();
  for (const r of resources) {
    try {
      const url = new URL(r.name);
      if (url.origin === env.location?.origin && url.pathname.startsWith('/rest/')) observed.add(`${r.initiatorType}:${maskPath(url.pathname)}`);
    } catch {}
  }

  const report = {routes: {}, observedRequests: [...observed].sort().slice(0, 100), client: null};
  const toRead = [...new Set([...candidates, ...[...routeLiterals].filter(p => worthy.test(p))])]
    .filter(p => !never.test(p)).slice(0, maxRoutes);
  for (const path of toRead) report.routes[path] = await read(path);
  report.client = {scripts: scripts.size, scanned, scannedBytes,
    subscriptionTiers: [...tiers].sort().slice(0, 100), subscriptionStatuses: [...statuses].sort().slice(0, 50),
    planWords: [...words].sort().slice(0, 100), routes: [...routeLiterals].sort().slice(0, 300),
    templatedRoutes: [...templated].sort().slice(0, 200)};
  report.userAgent = env.navigator?.userAgent ?? '';
  return report;
}

// Every string or number under an identity key, as salted tags: the replay's answer to "same account?".
export function identityTags(json, tag) {
  const ID_KEYS = new Set(['id', 'uuid', 'userId', 'user_id', 'xaiUserId', 'xUserId', 'x_user_id', 'accountId', 'account_id',
    'subscriptionId', 'subscription_id', 'teamId', 'team_id', 'customerId', 'customer_id']);
  const out = new Set();
  const walk = (value, key, depth) => {
    if (depth > 8 || value === null) return;
    if ((typeof value === 'string' || typeof value === 'number') && ID_KEYS.has(key)) out.add(`${key}:${tag(String(value))}`);
    else if (Array.isArray(value)) value.slice(0, 20).forEach(v => walk(v, key, depth + 1));
    else if (typeof value === 'object') for (const [k, v] of Object.entries(value)) walk(v, k, depth + 1);
  };
  walk(json, '', 0);
  return [...out].sort();
}

// The only fields that leave this process. Everything is re-projected, then the serialized result is
// scanned: one UUID, e-mail address, token-shaped string or long digit run (an X user id) and nothing is written.
export function grokProbeReport(raw, cookies, replays, browserVersion) {
  const report = {
    measuredAt: new Date().toISOString(), browser: String(browserVersion).replace(/[^\w./ -]/g, '').slice(0, 64),
    kind: 'grok-plan-qualification-probe', claimable: false,
    routes: raw.routes, observedRequests: raw.observedRequests, client: raw.client,
    cookies: cookies.map(c => ({name: String(c.name).slice(0, 64), httpOnly: Boolean(c.httpOnly), bytes: c.value.length})),
    replays,
  };
  const text = JSON.stringify(report, null, 2);
  if (UUID.test(text) || /[^\s"@]+@[^\s"@]+\.[a-z]{2,}/i.test(text) || /[A-Za-z0-9_+=-]{48,}/.test(text) || /\d{15,}/.test(text))
    throw Error('PROBE_REPORT_LEAK');
  return text + '\n';
}

// Cookie sets to replay: the whole jar, none, the jar without Cloudflare's own cookies, and each
// session-looking cookie alone. The first 200 among the narrow sets is the capture allowlist candidate.
export function cookieVariants(cookies) {
  const names = cookies.map(c => c.name);
  const variants = {all: null, none: [], withoutCloudflare: names.filter(n => !CLOUDFLARE_COOKIES.includes(n))};
  const session = names.filter(n => /sso|sess|auth|token|user/i.test(n) && !CLOUDFLARE_COOKIES.includes(n));
  for (const n of session.slice(0, 8)) variants[`only:${n}`] = [n];
  if (session.length > 1) variants.sessionCookies = session;
  // Once the whole jar is known to pass and every jar without the clearance cookie to fail, this is the
  // allowlist question: the clearance cookie plus which session cookie.
  if (names.includes('cf_clearance')) {
    variants['only:cf_clearance'] = ['cf_clearance'];
    for (const n of session.slice(0, 8)) variants[`cf_clearance+${n}`] = ['cf_clearance', n];
    if (session.length > 1) variants['cf_clearance+sessionCookies'] = ['cf_clearance', ...session];
    variants['withoutCfBm'] = names.filter(n => n !== '__cf_bm');
  }
  return variants;
}

// A non-browser HTTP/1.1 client with the TLSN request's fixed headers (src/prove-worker.js)
// and a chosen cookie set. From a server it also stands in for the verifier's datacenter egress, which is
// what grok.com's Cloudflare sees in Proxy mode.
function replay(path, headers) {
  return new Promise(done => {
    const req = request({host: 'grok.com', servername: 'grok.com', path, method: 'GET', agent: false,
      ALPNProtocols: ['http/1.1'], headers, timeout: 15000}, res => {
      const chunks = []; let size = 0;
      res.on('data', c => {size += c.length; if (size <= 1 << 20) chunks.push(c);});
      res.on('end', () => done({status: res.statusCode, bytes: size, mitigated: res.headers['cf-mitigated'] ?? null,
        encoding: res.headers['content-encoding'] ?? 'identity', transfer: res.headers['transfer-encoding'] ?? null,
        body: Buffer.concat(chunks).toString('utf8')}));
    });
    req.on('timeout', () => req.destroy(Error('timeout')));
    req.on('error', () => done({status: 0, bytes: 0, mitigated: null, encoding: null, transfer: null, body: ''}));
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
    if (tabs.length !== 1) throw Error('OPEN_ONE_GROK_TAB');
    const report = await tabs[0].evaluate(pageProbe, {salt, candidates: CANDIDATE_ROUTES,
      readWorthy: READ_WORTHY.source, neverRead: NEVER_READ.source});
    const cookies = await context.cookies(ORIGIN);
    const jar = names => cookies.filter(c => names === null || names.includes(c.name)).map(c => `${c.name}=${c.value}`).join('; ');
    const variants = cookieVariants(cookies);
    const replays = {};
    const ok = Object.entries(report.routes).filter(([, e]) => e.status === 200 && e.shape).map(([p]) => p);
    for (const path of ok.slice(0, 6)) {
      replays[path] = {};
      for (const [name, names] of Object.entries(variants)) {
        const cookie = jar(names);
        const r = await replay(path, {host: 'grok.com', accept: 'application/json', 'user-agent': report.userAgent,
          'accept-encoding': 'identity', connection: 'close', ...(cookie ? {cookie} : {})});
        let ids = null;
        if (r.status === 200) try {ids = identityTags(JSON.parse(r.body), tag);} catch {}
        replays[path][name] = {status: r.status, bytes: r.bytes, cloudflareMitigated: r.mitigated,
          encoding: r.encoding, transfer: r.transfer, identityTags: ids};
      }
      // Is the clearance bound to the user-agent it was issued with? The same jar, another browser's UA.
      const other = await replay(path, {host: 'grok.com', accept: 'application/json', 'accept-encoding': 'identity',
        connection: 'close', 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Safari/605.1.15',
        cookie: jar(null)});
      replays[path].allOtherUserAgent = {status: other.status, bytes: other.bytes, cloudflareMitigated: other.mitigated};
    }
    delete report.userAgent;
    const text = grokProbeReport(report, cookies, replays, browser.version());
    const reports = fileURLToPath(new URL('../reports/', import.meta.url)); await mkdir(reports, {recursive: true});
    await writeFile(join(reports, 'grok-probe.json'), text, {mode: 0o600});
    console.log(text);
  } finally {
    // connectOverCDP: close() disconnects and leaves your browser and tabs running.
    await browser.close();
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  probe().catch(error => {
    const code = /^[A-Z_]+$/.test(error?.message) ? error.message : 'GROK_PROBE_FAILED';
    console.error(`${code}: keep exactly one signed-in grok.com tab open in the hosted browser (ops/tlsn-browser.sh).`);
    process.exitCode = 1;
  });
}
