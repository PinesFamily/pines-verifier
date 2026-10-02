export const PROTOCOL = 'pines-tlsn-bridge-v1';
export const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
export const terminal = phase => ['completed', 'cancelled', 'failed'].includes(phase);
export function check(condition, code = 'INVALID_REQUEST') { if (!condition) throw Error(code); }
export function object(value, keys) { check(value && typeof value === 'object' && !Array.isArray(value)); check(Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key))); return value; }
export function ownerOf(sender, origins) {
  check(sender && sender.id === undefined && origins.includes(sender.origin) && sender.frameId === 0 && typeof sender.documentId === 'string' && sender.documentId.length > 0 && sender.documentId.length <= 128, 'UNAUTHORIZED');
  check(Number.isInteger(sender.tab?.id) && Number.isInteger(sender.tab?.windowId) && !sender.tab.incognito, 'UNAUTHORIZED');
  check(new URL(sender.url).origin === sender.origin && (!sender.tab.url || new URL(sender.tab.url).origin === sender.origin)
    && (!sender.documentLifecycle || sender.documentLifecycle === 'active'), 'UNAUTHORIZED');
  return {tabId: sender.tab.id, windowId: sender.tab.windowId, documentId: sender.documentId, origin: sender.origin};
}
// Provider schemas a capture build may prove. Anything else must be a fixture.
export const PROVIDER_SCHEMAS = Object.freeze(['pines.chatgpt.plan', 'pines.claude.plan', 'pines.grok.plan']);
// One build carries a list of schemas (one extension ID serves every provider).
// Each is still resolved from the packaged registry, so its digest stays pinned.
export function supported(schema, config) {
  return config.schemas.some(({schemaId, version}) => schema?.schemaId === schemaId && schema.version === version)
    && (schema.lifecycle === 'fixture' || (config.captureProvider === true && PROVIDER_SCHEMAS.includes(schema.schemaId)));
}
export function buildEntries(registry, config) {
  check(Array.isArray(config.schemas) && config.schemas.length > 0, 'SCHEMA_UNAVAILABLE');
  const entries = config.schemas.map(({schemaId, version}) => registry.list().find(entry => entry.schema.schemaId === schemaId && entry.schema.version === version));
  check(entries.every(entry => entry && supported(entry.schema, config)), 'SCHEMA_UNAVAILABLE');
  return entries;
}
export function entryOf(entries, reference) {
  const entry = entries.find(entry => ['schemaId', 'version', 'digest'].every(key => entry.reference[key] === reference?.[key]));
  check(entry, 'SCHEMA_UNAVAILABLE');
  return entry;
}
export function owns(owner, other) { return owner && other && ['tabId', 'windowId', 'documentId', 'origin'].every(key => owner[key] === other[key]); }
export function recipientOf(value) { check(typeof value === 'string' && /^0x[\da-fA-F]{40}$/.test(value) && value !== '0x' + '0'.repeat(40), 'INVALID_RECIPIENT'); return value.toLowerCase(); }
// The API assigns each attempt's verifier; the extension accepts it only under this
// packaged policy: a canonical HTTPS origin directly beneath verifier.pines.family on the default port, or one of the
// build's explicit legacy (and, in test builds only, loopback test) origins. No userinfo, path, query or fragment.
export const VERIFIER_HOST = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.verifier\.pines\.family$/;
export function verifierOriginAllowed(value, config) {
  if (typeof value !== 'string' || value.length > 256) return false;
  let url;
  try { url = new URL(value); } catch { return false; }
  if (url.origin !== value || url.username || url.password) return false;
  const listed = [...(config.verifierPolicy?.legacy ?? []), ...(config.testBuild ? config.verifierPolicy?.test ?? [] : [])];
  if (listed.includes(value)) return true;
  return url.protocol === 'https:' && url.port === '' && VERIFIER_HOST.test(url.hostname);
}
/** The verifier an attempt was assigned: its origin, the revision its ticket names, and its registry instance. */
export function assignmentOf(attempt, ticket) {
  return {origin: attempt.verifierOrigin, revision: ticket.verifierRevision, instanceId: attempt.verifier?.instanceId ?? null};
}
export function validateAttempt(attempt, recipient, reference, schema, config, now = Date.now()) {
  // A pinned (pre-assignment) attempt has exactly the seven v1 keys; an assigned one adds `verifier`.
  const assigned = attempt && typeof attempt === 'object' && Object.hasOwn(attempt, 'verifier');
  object(attempt, ['attemptId', 'ticket', 'schema', 'expiresAt', 'resultExpiresAt', 'claimable', 'verifierOrigin', ...(assigned ? ['verifier'] : [])]);
  check(UUID.test(attempt.attemptId) && attempt.claimable === false, 'ATTEMPT_MISMATCH');
  check(verifierOriginAllowed(attempt.verifierOrigin, config), 'VERIFIER_ORIGIN_REFUSED');
  object(attempt.schema, ['schemaId', 'version', 'digest']);
  check(['schemaId', 'version', 'digest'].every(key => attempt.schema[key] === reference[key]), 'SCHEMA_UNAVAILABLE');
  check(typeof attempt.ticket === 'string' && attempt.ticket.length <= 8192 && /^[\w-]+\.[a-f0-9]{64}$/.test(attempt.ticket), 'INVALID_TICKET');
  let ticket;
  try { ticket = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(Uint8Array.from(atob(attempt.ticket.split('.')[0].replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)))); } catch { throw Error('INVALID_TICKET'); }
  // This is a client consistency check. Only the verifier authenticates the HMAC.
  check(ticket.format === 'pines-tlsn-ticket-v1' && ticket.mode === 'Proxy' && ticket.attemptId === attempt.attemptId && ticket.recipient === recipient && ticket.application === config.application && ticket.chainId === config.chainId && typeof ticket.verifierRevision === 'string' && /^[a-zA-Z0-9._-]{1,80}$/.test(ticket.verifierRevision) && ticket.serverName === new URL(schema.request.origin).hostname, 'ATTEMPT_MISMATCH');
  if (assigned) {
    object(attempt.verifier, ['instanceId', 'origin', 'revision']);
    check(typeof attempt.verifier.instanceId === 'string' && /^[a-z0-9][a-z0-9-]{0,31}$/.test(attempt.verifier.instanceId)
      && attempt.verifier.origin === attempt.verifierOrigin && attempt.verifier.revision === ticket.verifierRevision, 'ATTEMPT_MISMATCH');
  } else {
    // Pinned attempts keep this build's pin, exactly as extension 0.4.x did.
    check(attempt.verifierOrigin === config.verifierOrigin && ticket.verifierRevision === config.verifierRevision, 'ATTEMPT_MISMATCH');
  }
  check(ticket.schema && ['schemaId', 'version', 'digest'].every(key => ticket.schema[key] === reference[key]), 'SCHEMA_UNAVAILABLE');
  check(Number.isSafeInteger(ticket.issuedAt) && ticket.issuedAt <= now + 5000 && Number.isSafeInteger(ticket.expiresAt) && ticket.expiresAt > now && ticket.expiresAt - ticket.issuedAt <= 60_000 && attempt.expiresAt === ticket.expiresAt && Number.isSafeInteger(ticket.resultExpiresAt) && ticket.resultExpiresAt === attempt.resultExpiresAt && ticket.resultExpiresAt > ticket.expiresAt && ticket.resultExpiresAt - ticket.issuedAt <= 1_800_000, 'TICKET_EXPIRED');
  check(['maxSentBytes', 'maxRecvBytes', 'maxRecvRecords', 'sessionTimeoutMs'].every(key => ticket[key] === schema.limits[key]), 'ATTEMPT_MISMATCH');
  return ticket;
}
export function publicState(job) {
  return job ? {runId: job.runId, attemptId: job.attemptId, recipient: job.recipient, schema: job.schema, phase: job.permissionPending && job.phase === 'awaiting-capture' ? 'awaiting-permission' : job.phase, error: job.error ?? null, claimable: false, ...(job.preparing ? {preparationReady: !job.permissionPending && !terminal(job.phase)} : {}), ...(job.retryAt != null ? {retryAt: job.retryAt} : {})} : null;
}
