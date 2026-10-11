// Total setup/capture/review/proof budget, pinned independently of discovery.
// Attempt creation is the immutable start.
import {SESSION_POLICY_VERSION, SESSION_BUDGET_MIN_MS, SESSION_BUDGET_MAX_MS, sessionPolicy, validateSessionPolicySnapshot} from '../../../tools/tee-native/session-policy.mjs';

export const SESSION_POLICY_SUPPORT = Object.freeze({sessionPolicyVersion: SESSION_POLICY_VERSION,
  minSessionBudgetMs: SESSION_BUDGET_MIN_MS, maxSessionBudgetMs: SESSION_BUDGET_MAX_MS});
export const SESSION_SNAPSHOT_KEYS = Object.freeze(['sessionPolicyVersion', 'sessionPolicyRevision', 'sessionBudgetMs', 'sessionExpiresAt']);

export function supportedSessionPolicy(value) {
  if (value?.sessionPolicyVersion !== SESSION_POLICY_VERSION) throw Error('SESSION_POLICY_UNSUPPORTED');
  if (typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== 3
    || !['sessionPolicyVersion', 'sessionPolicyRevision', 'sessionBudgetMs'].every(key => Object.hasOwn(value, key))) throw Error('SESSION_POLICY_INVALID');
  try { return sessionPolicy(value); } catch { throw Error('SESSION_POLICY_INVALID'); }
}
export function sessionSnapshot(value, now = Date.now()) {
  if (value?.sessionPolicyVersion !== SESSION_POLICY_VERSION) throw Error('SESSION_POLICY_UNSUPPORTED');
  let snapshot;
  try { snapshot = validateSessionPolicySnapshot(value, value.issuedAt); } catch { throw Error('SESSION_POLICY_INVALID'); }
  if (value.issuedAt > now + 5000 || value.sessionExpiresAt <= now) throw Error('PROOF_TIMEOUT');
  if (!Number.isSafeInteger(value.resultExpiresAt) || value.sessionExpiresAt > value.resultExpiresAt) throw Error('SESSION_POLICY_INVALID');
  return snapshot;
}
export function supportsSessionPolicy(support, policy) {
  supportedSessionPolicy(policy);
  return support?.sessionPolicyVersion === SESSION_POLICY_VERSION
    && support.minSessionBudgetMs === SESSION_BUDGET_MIN_MS && support.maxSessionBudgetMs === SESSION_BUDGET_MAX_MS;
}
