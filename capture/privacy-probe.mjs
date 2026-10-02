import {mkdir, writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';

// A read-only shape audit of your own signed-in account. All response values and the ChatGPT bearer stay inside the tab.
// Self-contained because Playwright serializes this function into the page.
export async function privacyPageProbe(provider, env = globalThis) {
  const routes = {chatgpt: '/backend-api/wham/usage', claude: '/api/organizations', grok: '/rest/subscriptions'};
  if (!Object.hasOwn(routes, provider)) throw Error('INVALID_PROVIDER');
  const report = {provider, status: 0, error: null, responseBytes: 0, itemCount: 0,
    selectorFieldsComplete: false, identityFieldsPresent: false, planFieldsPresent: false,
    emailFieldPresent: false, nameFieldPresent: false, billingIdFieldPresent: false,
    commerceBillingMarkerPresent: false, legacyBillingMarkerPresent: false,
    unapprovedProperties: 0, privateStringValues: 0, stringValues: 0,
    fullyU00EscapedStrings: 0, rawAsciiStrings: 0, stringsWithEscapes: 0};
  async function get(path, headers = {}) {
    const controller = new env.AbortController();
    const timeout = env.setTimeout(() => controller.abort(), 15000);
    try {
      const r = await env.fetch(path, {method: 'GET', credentials: 'same-origin',
        redirect: 'error', cache: 'no-store', signal: controller.signal,
        headers: {accept: 'application/json', ...headers}});
      if (!r.ok) {await r.body?.cancel(); return {status: r.status, text: null};}
      if (!/^application\/json(?:\s*;|$)/i.test(r.headers.get('content-type') ?? '')) {
        await r.body?.cancel(); throw Error('UNEXPECTED_CONTENT_TYPE');
      }
      const reader = r.body.getReader(), chunks = [];
      let size = 0;
      try {
        for (;;) {
          const {value, done} = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > 65536) throw Error('BODY_TOO_LARGE');
          chunks.push(value);
        }
      } finally {await reader.cancel().catch(() => {}); reader.releaseLock();}
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) {bytes.set(chunk, offset); offset += chunk.length;}
      return {status: r.status, text: new env.TextDecoder('utf-8', {fatal: true}).decode(bytes), bytes: size};
    } finally {env.clearTimeout(timeout);}
  }
  try {
    let headers = {};
    if (provider === 'chatgpt') {
      // Authentication prerequisite only; this response is never exported.
      const session = await get('/api/auth/session');
      let token;
      try {token = session.text && JSON.parse(session.text).accessToken;} catch {}
      if (typeof token !== 'string' || !token || token.length > 16384 || /[\r\n]/.test(token)) {
        report.error = 'AUTH_REQUIRED'; return report;
      }
      headers = {authorization: `Bearer ${token}`};
    }
    const r = await get(routes[provider], headers);
    report.status = r.status;
    if (r.text === null) {report.error = [401, 403].includes(r.status) ? 'AUTH_REQUIRED' : 'HTTP_ERROR'; return report;}
    report.responseBytes = r.bytes;
    let json;
    try {json = JSON.parse(r.text);} catch {report.error = 'INVALID_JSON'; return report;}
    const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
    const fields = provider === 'chatgpt' ? ['user_id', 'plan_type'] : provider === 'claude'
      ? ['uuid', 'capabilities', 'rate_limit_tier', 'raven_type', 'parent_organization_uuid']
      : ['xaiUserId', 'tier', 'status'];
    const items = provider === 'chatgpt' ? (object(json) ? [json] : null)
      : provider === 'claude' ? json : object(json) ? json.subscriptions : null;
    if (!Array.isArray(items) || items.length > 64 || !items.every(object)) {
      report.error = 'UNEXPECTED_SHAPE'; return report;
    }
    report.itemCount = items.length;
    report.selectorFieldsComplete = items.length > 0 && items.every(item => fields.every(key => Object.hasOwn(item, key)));
    const identity = fields[0], plan = provider === 'claude' ? 'rate_limit_tier' : fields[1];
    report.identityFieldsPresent = items.length > 0 && items.every(item => typeof item[identity] === 'string' && item[identity].length > 0);
    report.planFieldsPresent = items.length > 0 && items.every(item => typeof item[plan] === 'string' && item[plan].length > 0);
    function approved(path) {
      if (provider === 'chatgpt') return path.length === 1 && fields.includes(path[0]);
      if (provider === 'grok') return path.length === 1 && path[0] === 'subscriptions'
        || path.length === 2 && path[0] === 'subscriptions' && Number.isInteger(path[1])
        || path.length === 3 && path[0] === 'subscriptions' && Number.isInteger(path[1]) && fields.includes(path[2]);
      return path.length === 1 && Number.isInteger(path[0])
        || path.length === 2 && Number.isInteger(path[0]) && fields.includes(path[1])
        || path.length === 3 && Number.isInteger(path[0]) && path[1] === 'capabilities' && Number.isInteger(path[2]);
    }
    let nodes = 0;
    function walk(value, path = []) {
      if (++nodes > 100000 || path.length > 32) throw Error('SHAPE_LIMIT');
      if (typeof value === 'string' && !approved(path)) report.privateStringValues++;
      if (Array.isArray(value)) value.forEach((child, i) => walk(child, [...path, i]));
      else if (object(value)) for (const [key, child] of Object.entries(value)) {
        const next = [...path, key], normalized = key.toLowerCase().replace(/[^a-z]/g, '');
        if (!approved(next)) report.unapprovedProperties++;
        if (['email', 'emailaddress'].includes(normalized)) report.emailFieldPresent = true;
        if (['name', 'fullname', 'givenname', 'familyname', 'displayname'].includes(normalized)) report.nameFieldPresent = true;
        const lineage = next.filter(v => typeof v === 'string').join('.').toLowerCase();
        if (/^(?:stripe)?(?:subscription|invoice|product|price|customer)ids?$/.test(normalized)
          || normalized === 'id' && /stripe|invoice|product|price|customer/.test(lineage)) report.billingIdFieldPresent = true;
        if (provider === 'grok' && key === 'billingSystem') {
          if (child === 'BILLING_SYSTEM_COMMERCE') report.commerceBillingMarkerPresent = true;
          if (child === 'BILLING_SYSTEM_LEGACY') report.legacyBillingMarkerPresent = true;
        }
        walk(child, next);
      }
    }
    walk(json);
    // Lexical metrics cover all string values, not just private fields. JSON.parse
    // above establishes syntax for this diagnostic; no verification facts are issued.
    const tokens = /"(?:[^"\\]|\\[\s\S])*"/g;
    for (const match of r.text.matchAll(tokens)) {
      if (/^\s*:/.test(r.text.slice(match.index + match[0].length))) continue;
      const raw = match[0].slice(1, -1);
      report.stringValues++;
      if (raw.length > 0 && /^(?:\\u00[0-9a-f]{2})+$/i.test(raw)) report.fullyU00EscapedStrings++;
      if (/[\x20-\x21\x23-\x5b\x5d-\x7e]/.test(raw.replace(/\\(?:u[0-9a-f]{4}|[\s\S])/gi, ''))) report.rawAsciiStrings++;
      if (raw.includes('\\')) report.stringsWithEscapes++;
    }
    return report;
  } catch (error) {
    report.error = ['BODY_TOO_LARGE', 'UNEXPECTED_CONTENT_TYPE', 'SHAPE_LIMIT'].includes(error?.message)
      ? error.message : 'REQUEST_FAILED';
    return report;
  }
}

const counts = ['status', 'responseBytes', 'itemCount', 'unapprovedProperties', 'privateStringValues',
  'stringValues', 'fullyU00EscapedStrings', 'rawAsciiStrings', 'stringsWithEscapes'];
const flags = ['selectorFieldsComplete', 'identityFieldsPresent', 'planFieldsPresent', 'emailFieldPresent',
  'nameFieldPresent', 'billingIdFieldPresent', 'commerceBillingMarkerPresent', 'legacyBillingMarkerPresent'];
const errors = [null, 'AUTH_REQUIRED', 'HTTP_ERROR', 'BODY_TOO_LARGE', 'UNEXPECTED_CONTENT_TYPE',
  'INVALID_JSON', 'UNEXPECTED_SHAPE', 'SHAPE_LIMIT', 'REQUEST_FAILED'];
export function privacyProbeReport(value, provider) {
  const fail = () => {throw Error('INVALID_PRIVACY_REPORT');};
  if (!['chatgpt', 'claude', 'grok'].includes(provider) || value?.provider !== provider || !errors.includes(value.error)) fail();
  const keys = ['provider', 'error', ...counts, ...flags];
  if (Object.keys(value).length !== keys.length || Object.keys(value).some(key => !keys.includes(key))) fail();
  const clean = {provider, error: value.error};
  for (const key of counts) {
    const max = key === 'status' ? 599 : key === 'itemCount' ? 64 : key === 'responseBytes' ? 65536 : 100000;
    if (!Number.isSafeInteger(value[key]) || value[key] < 0 || value[key] > max) fail();
    clean[key] = value[key];
  }
  for (const key of flags) {if (typeof value[key] !== 'boolean') fail(); clean[key] = value[key];}
  return JSON.stringify(clean, null, 2) + '\n';
}

async function main(provider) {
  if (!['chatgpt', 'claude', 'grok'].includes(provider) || process.argv.length !== 3) throw Error('INVALID_PROVIDER');
  const endpoint = process.env.TLSN_BROWSER_CDP ?? 'http://127.0.0.1:9222';
  if (!/^http:\/\/(127\.0\.0\.1|localhost):\d{1,5}$/.test(endpoint)) throw Error('LOOPBACK_CDP_REQUIRED');
  const {chromium} = await import('playwright');
  const browser = await chromium.connectOverCDP(endpoint, {timeout: 10000});
  try {
    const origin = {chatgpt: 'https://chatgpt.com', claude: 'https://claude.ai', grok: 'https://grok.com'}[provider];
    const tabs = browser.contexts().flatMap(c => c.pages()).filter(p => {try {return new URL(p.url()).origin === origin;} catch {return false;}});
    if (tabs.length !== 1) throw Error('OPEN_ONE_PROVIDER_TAB');
    const text = privacyProbeReport(await tabs[0].evaluate(privacyPageProbe, provider), provider);
    const directory = fileURLToPath(new URL('../reports/', import.meta.url));
    await mkdir(directory, {recursive: true, mode: 0o700});
    // Create once: accidental reruns cannot overwrite an earlier audit.
    await writeFile(resolve(directory, `privacy-${provider}-${Date.now()}.json`), text, {mode: 0o600, flag: 'wx'});
    process.stdout.write(text);
  } finally {await browser.close();} // Disconnect from CDP; preserve your browser.
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv[2]).catch(() => {console.error('PRIVACY_PROBE_FAILED'); process.exitCode = 1;});
}
