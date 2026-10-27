// Signed browser authorization only. This is never a native ticket or receipt.
import {check, exact, sign, verify} from '../tee-native/wire.mjs';
export const LEASE_DOMAIN = 'pines/grok-assistance-lease/v1';
export const EGRESS_PATH = 'pines-grok-relay-v1';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const HASH = /^[a-f0-9]{64}$/;
export function validateLease(body, {attemptId, pin, now = Date.now()}) {
  exact(body, ['version', 'attemptId', 'group', 'nodeId', 'workerId', 'bootId', 'egressIpv4', 'egressPath',
    'schemaDigest', 'issuedAt', 'expiresAt', 'credential']);
  check(body.version === 1 && UUID.test(attemptId) && body.attemptId === attemptId
    && body.egressPath === EGRESS_PATH && pin.egressPath === EGRESS_PATH
    && ['group', 'nodeId', 'egressIpv4', 'schemaDigest'].every(key => body[key] === pin[key]), 'ASSISTANCE_PIN');
  check(/^[a-z0-9][a-z0-9-]{1,63}$/.test(body.workerId) && HASH.test(body.bootId)
    && HASH.test(body.credential), 'ASSISTANCE_LEASE');
  check(Number.isSafeInteger(now) && Number.isSafeInteger(body.issuedAt) && Number.isSafeInteger(body.expiresAt)
    && body.issuedAt <= now + 2000 && body.issuedAt > now - 120_000 && body.expiresAt > now
    && body.expiresAt > body.issuedAt && body.expiresAt - body.issuedAt <= 120_000, 'ASSISTANCE_EXPIRED');
  return body;
}
export const signLease = (body, key) => sign(LEASE_DOMAIN, body, key);
export async function verifyLease(envelope, {apiKey, ...context}) {
  await verify(LEASE_DOMAIN, envelope, apiKey);
  return validateLease(envelope.body, context);
}
