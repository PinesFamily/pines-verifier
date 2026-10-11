// Total time starts at attempt creation, never admission or browser reload.
// The ceiling is a candidate qualification bound; the operating default
// remains the accepted two-minute budget.
import {check} from './wire.mjs';

export const SESSION_POLICY_VERSION = 1;
export const SESSION_BUDGET_DEFAULT_MS = 120000;
export const SESSION_BUDGET_MIN_MS = 120000;
export const SESSION_BUDGET_MAX_MS = 300000;
export const SESSION_POLICY_FIELDS = Object.freeze(['sessionPolicyVersion', 'sessionPolicyRevision', 'sessionBudgetMs', 'sessionExpiresAt']);
export const DEFAULT_SESSION_POLICY = Object.freeze({sessionPolicyVersion: SESSION_POLICY_VERSION, sessionPolicyRevision: 1, sessionBudgetMs: SESSION_BUDGET_DEFAULT_MS});

export function sessionPolicy(value) {
  check(value && typeof value === 'object' && !Array.isArray(value), 'SESSION_POLICY');
  check(value.sessionPolicyVersion === SESSION_POLICY_VERSION, 'SESSION_POLICY_VERSION');
  check(Number.isSafeInteger(value.sessionPolicyRevision) && value.sessionPolicyRevision > 0, 'SESSION_POLICY_REVISION');
  check(Number.isSafeInteger(value.sessionBudgetMs) && value.sessionBudgetMs >= SESSION_BUDGET_MIN_MS
    && value.sessionBudgetMs <= SESSION_BUDGET_MAX_MS, 'SESSION_BUDGET');
  return {sessionPolicyVersion: value.sessionPolicyVersion, sessionPolicyRevision: value.sessionPolicyRevision, sessionBudgetMs: value.sessionBudgetMs};
}

export function snapshotSessionPolicy(value, issuedAt) {
  const policy = sessionPolicy(value);
  check(Number.isSafeInteger(issuedAt) && issuedAt >= 0 && Number.isSafeInteger(issuedAt + policy.sessionBudgetMs), 'SESSION_DEADLINE');
  return {...policy, sessionExpiresAt: issuedAt + policy.sessionBudgetMs};
}

export function validateSessionPolicySnapshot(value, issuedAt, {allowLegacy = false} = {}) {
  check(value && typeof value === 'object' && !Array.isArray(value), 'SESSION_POLICY');
  if (allowLegacy && SESSION_POLICY_FIELDS.every(key => !Object.hasOwn(value, key))) return null;
  const expected = snapshotSessionPolicy(value, issuedAt);
  check(value.sessionExpiresAt === expected.sessionExpiresAt, 'SESSION_DEADLINE');
  return expected;
}
