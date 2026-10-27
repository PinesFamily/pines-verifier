import {check, exact} from './wire.mjs';
import {parseJson} from '../../packages/verification-schemas/src/json.ts';
import {headerValue, utf8} from '../../packages/verification-schemas/src/http.ts';

// Measured inventory: selective disclosure refuses unknown response header names and
// credential-looking body fields before reveal. The private-headers policy hides header
// values and sends the bounded body only to the measured enclave, under explicit consent.
//
// The body is no longer held to an observed per-field shape. That refused every account whose provider
// added a field or filled a null one, while the fields a decision reads are judged by the schema's
// selector and checks regardless. In selective and complete modes, a non-empty string
// under a credential-named key or in a known credential format still refuses. Size and
// depth remain bounded by the schema and `parseJson`.
const CREDENTIAL_NOUNS = new Set(['token', 'tokens', 'secret', 'secrets', 'password', 'passwords', 'passwd', 'passphrase',
  'cookie', 'cookies', 'credential', 'credentials', 'authorization', 'apikey', 'accesstoken', 'refreshtoken', 'idtoken',
  'authtoken', 'sessionkey', 'sessionid', 'sessiontoken', 'privatekey', 'secretkey', 'accesskey']);
const CREDENTIAL_PAIRS = new Set(['api key', 'session key', 'session id', 'private key', 'secret key', 'access key', 'signing key']);
// Grok's session cookies by name. No `jwt`, `bearer` or `sso` noun: Grok's observed
// `surfaceNames.SURFACE_JWT` is a display name, and those credentials are caught by format.
const CREDENTIAL_KEYS = new Set(['sso', 'sso-rw']);
// The providers' credentials as presented: ChatGPT's bearer and session token and Grok's `sso` (JWT or
// JWE), claude.ai's `sessionKey` and Anthropic's keys, OpenAI and xAI API keys, and any Bearer value.
const CREDENTIAL_FORMATS = [/eyJ[\w-]{10,}\.[\w-]*\.[\w-]{10,}/, /\bsk-ant-[a-z]+\d*-/, /\bsk-(?:proj|svcacct|admin)-[\w-]{20,}/,
  /\bxai-[A-Za-z0-9]{40,}/, /\bbearer\s+[\w.~+\/=-]{16,}/i];
// A key names a credential when its last word does (`access_token`, `sessionKey`, `client_secret`), never
// for a word elsewhere in it (`api_key_creation_enabled`, `account_session_duration_seconds`).
const words = key => key.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
  .toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
export function credentialName(key) {
  if (CREDENTIAL_KEYS.has(key.toLowerCase())) return true;
  const named = words(key);
  return named.length > 0 && (CREDENTIAL_NOUNS.has(named.at(-1)) || CREDENTIAL_PAIRS.has(named.slice(-2).join(' ')));
}
const credentialFormat = text => CREDENTIAL_FORMATS.some(format => format.test(text));
// Everything under a credential-named key is the credential's, through arrays and objects alike.
function refuseCredentials(value, credentialKey = false) {
  if (typeof value === 'string') check(!credentialFormat(value) && !(credentialKey && value.length > 0), 'UNQUALIFIED_FIELD');
  else if (Array.isArray(value)) for (const item of value) refuseCredentials(item, credentialKey);
  else if (value !== null && typeof value === 'object') for (const [key, child] of Object.entries(value)) {
    check(!credentialFormat(key), 'UNQUALIFIED_FIELD');
    refuseCredentials(child, credentialKey || credentialName(key));
  }
}
// `responseDisclosure` is the selected policy's mode, never a local choice.
export function inspectProviderShape(message, inventory, responseDisclosure = 'selective') {
  check(['selective', 'complete', 'private-headers'].includes(responseDisclosure), 'DISCLOSURE_POLICY');
  check(inventory?.qualified === true && inventory.version === 2, 'PROVIDER_INVENTORY_UNQUALIFIED');
  check(message.startLine === 'HTTP/1.1 200 OK', 'RESPONSE_STATUS');
  check(['application/json', 'application/json; charset=utf-8', 'application/json;charset=utf-8']
    .includes(headerValue(message, 'content-type')?.toLowerCase()), 'CONTENT_TYPE');
  // A content coding is admitted only under the policy whose inventories were written
  // for it, and only as exactly gzip. The body reaching here is already decoded by the
  // schema package's single decode point, which bounded the decoded size first.
  const encoding = headerValue(message, 'content-encoding');
  check(encoding === undefined || (responseDisclosure === 'private-headers' && encoding.toLowerCase() === 'gzip'), 'CONTENT_ENCODING');
  // In complete-response mode the owner consents to every bounded HTTP header,
  // including opaque values. HTTP/framing and body-schema validation still apply.
  // Private headers hides all non-framing values; header names remain visible in framing.
  // Selective mode still refuses unknown names because it may reveal their values.
  if (responseDisclosure === 'selective') for (const h of message.headers) check(inventory.responseHeaders.includes(h.name), 'UNQUALIFIED_HEADER');
  const root = parseJson(utf8(message.body), 32);
  if (responseDisclosure !== 'private-headers') refuseCredentials(root);
  return root;
}
export function inspectProvider(message, inventory) {
  const root = inspectProviderShape(message, inventory);
  check(typeof root.user_id === 'string' && /^user-[A-Za-z\d]{24}$/.test(root.user_id), 'ACCOUNT_ID');
  check(['plus', 'pro', 'prolite', 'promax'].includes(root.plan_type), 'INELIGIBLE_PLAN');
  return {id: root.user_id, plan: root.plan_type};
}

// Values never leave this diagnostic. Dynamic property names can themselves be
// identifiers: retain only known vocabulary, hash every other name locally.
const vocabulary = new Set(['user_id', 'plan_type', 'email', 'rate_limit', 'primary_window', 'secondary_window',
  'used_percent', 'limit_window_seconds', 'reset_after_seconds', 'reset_at', 'allowed', 'limit_reached',
  'credits', 'has_credits', 'unlimited', 'balance', 'code_review_rate_limit', 'additional_rate_limits']);
const headerVocabulary=new Set(['content-type','content-length','transfer-encoding','content-encoding','connection','date','server','set-cookie','cache-control','vary','pragma','expires','cf-ray','cf-cache-status','strict-transport-security','x-content-type-options','x-frame-options','referrer-policy','alt-svc','content-security-policy','permissions-policy','x-request-id']);
const safeName=async(name,known)=>known.has(name)?name:'unknown-'+Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(name)))).map(b=>b.toString(16).padStart(2,'0')).join('');
export async function structuralDiagnostic(message) {
  const root = parseJson(utf8(message.body), 32), fields = [];
  async function walk(value, path, depth) {
    check(depth <= 32 && fields.length < 256, 'DIAGNOSTIC_LIMIT');
    const type = value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
    fields.push({path, type, ...(type === 'string' ? {bytes: new TextEncoder().encode(value).length} : {}),
      ...(type === 'array' ? {length: value.length} : {})});
    if (type === 'object') for (const key of Object.keys(value)) {
      const safe = await safeName(key,vocabulary);
      await walk(value[key], path + '/' + safe, depth + 1);
    }
    if (type === 'array') for (const item of value.slice(0, 8)) await walk(item, path + '/*', depth + 1);
  }
  await walk(root, '', 0);
  return {version: 1, bodyBytes: message.body.length, status200: message.startLine === 'HTTP/1.1 200 OK',
    headers: await Promise.all(message.headers.map(async h => ({name: await safeName(h.name,headerVocabulary), valueBytes: h.valueEnd - h.valueStart, hidden: h.name === 'set-cookie'}))), fields,
    accountIdSupported: typeof root?.user_id === 'string' && /^user-[A-Za-z\d]{24}$/.test(root.user_id),
    paidPlanSupported: ['plus', 'pro', 'prolite', 'promax'].includes(root?.plan_type)};
}

export function validateDiagnostic(d){
  exact(d,['version','bodyBytes','status200','headers','fields','accountIdSupported','paidPlanSupported','source','headersComplete','verified']);
  check(d.version===1&&d.source==='browser-fetch'&&d.headersComplete===false&&d.verified===false,'DIAGNOSTIC_SCOPE');
  const number=(n,max)=>check(Number.isSafeInteger(n)&&n>=0&&n<=max,'DIAGNOSTIC_LIMIT');
  number(d.bodyBytes,49152);for(const key of['status200','accountIdSupported','paidPlanSupported'])check(typeof d[key]==='boolean','DIAGNOSTIC_SHAPE');
  check(Array.isArray(d.headers)&&d.headers.length<=128&&Array.isArray(d.fields)&&d.fields.length<=256,'DIAGNOSTIC_LIMIT');
  const known=(s,set)=>set.has(s)||/^unknown-[a-f0-9]{64}$/.test(s);
  for(const h of d.headers){exact(h,['name','valueBytes','hidden']);check(known(h.name,headerVocabulary)&&typeof h.hidden==='boolean','DIAGNOSTIC_SHAPE');number(h.valueBytes,8192);}
  for(const f of d.fields){
    check(['null','array','object','string','number','boolean'].includes(f.type),'DIAGNOSTIC_SHAPE');
    exact(f,['path','type',...(f.type==='string'?['bytes']:[]),...(f.type==='array'?['length']:[])]);
    check(typeof f.path==='string'&&f.path.length<=2400&&(f.path===''||f.path.startsWith('/')&&f.path.split('/').slice(1).every(s=>s==='*'||known(s,vocabulary))),'DIAGNOSTIC_SHAPE');
    if(f.type==='string')number(f.bytes,49152);if(f.type==='array')number(f.length,49152);
  }
  return d;
}
