// Client side of the private-headers-gzip-v1 class (the client design record; plan D1–D14).
// Pure and import-free: the bundled capture controller and proof worker share it. Nothing here persists,
// logs or sends a value; a path parameter lives only inside the one in-memory replay.
export const PRIVATE_HEADERS_POLICY_ID = 'private-headers-gzip-v1';
export const FULL_RESPONSE_POLICY_ID = 'full-response-v1';
export const isPrivateHeadersSchema = schema => schema?.response?.privacy?.mode === 'private-headers-v1';
export const policyIdOf = value => typeof value === 'string' ? value : typeof value?.id === 'string' ? value.id : null;

// D3: `request.pathParams` declares each `{name}` once in `request.path`. Only Claude's org uuid exists.
const KINDS = Object.freeze({'lowercase-uuid-v1': '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'});
const PARAMS = Object.freeze({org_uuid: 'CLAUDE_ORG_UNAVAILABLE'});
const escape = text => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
export const requiresPathParams = schema => Boolean(schema?.request?.pathParams);
function template(schema) {
  const params = schema.request.pathParams, names = Object.keys(params ?? {});
  if (!names.length || !names.every(name => Object.hasOwn(PARAMS, name) && Object.hasOwn(KINDS, params[name]?.kind))) throw Error('UNSUPPORTED_CAPTURE');
  const parts = schema.request.path.split(/\{([a-z_]+)\}/);
  // Odd indexes are parameter names; every declared name appears exactly once and nothing else is templated.
  const used = parts.filter((_, index) => index % 2 === 1);
  if (used.length !== names.length || new Set(used).size !== used.length || !used.every(name => names.includes(name))) throw Error('UNSUPPORTED_CAPTURE');
  return {names: used, source: parts.map((part, index) => index % 2 ? `(${KINDS[params[part].kind]})` : escape(part)).join('')};
}
// The code a run fails with when the page never names the parameter (closed vocabulary, failure-code.js).
export function pathParamUnavailableCode(schema) {
  template(schema);
  return PARAMS[Object.keys(schema.request.pathParams)[0]];
}
// `scope`: a request the provider page itself made to the template's route or beneath it (the run-owned tab's own
// traffic, read from webRequest URL metadata; never a response body). `exact`: the one-time replay's own URL.
// Owner, 2026-10-07: the org is the one claude.ai's page is using; the enclave judges it (selector + /uuid binding).
export function pathParamsFrom(schema, url, {exact = false} = {}) {
  if (!requiresPathParams(schema) || typeof url !== 'string') return null;
  const {names, source} = template(schema);
  let parsed;
  try { parsed = new URL(url); } catch { return null; }
  if (parsed.origin !== schema.request.origin || parsed.username || parsed.password || parsed.hash) return null;
  const match = new RegExp(`^${source}${exact ? '$' : '(?:/|$)'}`).exec(parsed.pathname);
  if (!match) return null;
  const values = Object.freeze(Object.fromEntries(names.map((name, index) => [name, match[index + 1]])));
  if (exact && parsed.search !== instantiate(schema, values).search) return null;
  return values;
}
// The instantiated target, used here only to check a replay URL exactly. The request itself is built by the schema
// package (requestTarget/prepareReplay through capture/schema-adapter.mjs); a test pins that the two agree.
export function instantiate(schema, pathParams) {
  const {names} = template(schema);
  if (!pathParams || Object.keys(pathParams).length !== names.length) throw Error('INVALID_CAPTURE');
  const path = schema.request.path.replace(/\{([a-z_]+)\}/g, (_, name) => {
    const value = pathParams[name];
    if (typeof value !== 'string' || !new RegExp(`^${KINDS[schema.request.pathParams[name].kind]}$`).test(value)) throw Error('INVALID_CAPTURE');
    return value;
  });
  const query = new URLSearchParams(Object.entries(schema.request.query ?? {}).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)).toString();
  return {path, search: query ? `?${query}` : '', target: path + (query ? `?${query}` : '')};
}

// D14 and the policy's own refusals, mapped to fixed extension codes. Anything else keeps the phase's code.
export const SCHEMA_FAILURES = Object.freeze({
  RESPONSE_ENCODING_UNSUPPORTED: 'RESPONSE_ENCODING_UNSUPPORTED',
  REVEALED_LIMIT_EXCEEDED: 'RESPONSE_REVEAL_LIMIT',
  ENCODED_BODY_INVALID: 'RESPONSE_ENCODED_INVALID',
  PATH_PARAM_MISMATCH: 'CLAUDE_ORG_MISMATCH',
  // B's fifth code, required by the owner's org decision: the page's active org is not a paid personal org.
  SELECTED_SUBJECT_INELIGIBLE: 'CLAUDE_ORG_INELIGIBLE',
});
export const PRIVATE_HEADERS_FAILURES = Object.freeze([...new Set([...Object.values(SCHEMA_FAILURES), 'CLAUDE_ORG_UNAVAILABLE'])]);
export function schemaFailureCode(error) {
  const code = error?.name === 'SchemaError' ? error.code : error?.message;
  return typeof code === 'string' && Object.hasOwn(SCHEMA_FAILURES, code) ? SCHEMA_FAILURES[code]
    : PRIVATE_HEADERS_FAILURES.includes(code) ? code : null;
}
