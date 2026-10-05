import {check, exact} from './wire.mjs';
import {parseJson} from '../../packages/verification-schemas/src/json.ts';
import {headerValue, utf8} from '../../packages/verification-schemas/src/http.ts';

// Declarative, measured inventory. Unknown keys/headers refuse BEFORE reveal.
// Describing a field locally does not authorize disclosing it to the enclave.
function shape(value, spec, depth = 0) {
  check(spec && depth <= 32, 'UNQUALIFIED_FIELD');
  if (value === null) {check(spec.nullable === true, 'UNQUALIFIED_FIELD'); return;}
  if (spec.type === 'object') {
    check(typeof value === 'object' && !Array.isArray(value), 'UNQUALIFIED_FIELD');
    for (const key of Object.keys(value)) {
      check(Object.hasOwn(spec.properties, key), 'UNQUALIFIED_FIELD');
      shape(value[key], spec.properties[key], depth + 1);
    }
    for (const key of spec.required ?? []) check(Object.hasOwn(value, key), 'UNQUALIFIED_FIELD');
  } else if (spec.type === 'array') {
    check(Array.isArray(value) && value.length <= spec.maxItems, 'UNQUALIFIED_FIELD');
    for (const item of value) shape(item, spec.items, depth + 1);
  } else {
    check(['string', 'number', 'boolean'].includes(spec.type) && typeof value === spec.type, 'UNQUALIFIED_FIELD');
    if (typeof value === 'string') check(new TextEncoder().encode(value).length <= spec.maxBytes, 'UNQUALIFIED_FIELD');
    if (typeof value === 'number') check(Number.isFinite(value), 'UNQUALIFIED_FIELD');
  }
}
export function inspectProviderShape(message, inventory) {
  check(inventory?.qualified === true && inventory.version === 1, 'PROVIDER_INVENTORY_UNQUALIFIED');
  check(message.startLine === 'HTTP/1.1 200 OK', 'RESPONSE_STATUS');
  check(['application/json', 'application/json; charset=utf-8', 'application/json;charset=utf-8']
    .includes(headerValue(message, 'content-type')?.toLowerCase()), 'CONTENT_TYPE');
  check(headerValue(message, 'content-encoding') === undefined, 'CONTENT_ENCODING');
  for (const h of message.headers) check(inventory.responseHeaders.includes(h.name), 'UNQUALIFIED_HEADER');
  const root = parseJson(utf8(message.body), 32); shape(root, inventory.body);
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
