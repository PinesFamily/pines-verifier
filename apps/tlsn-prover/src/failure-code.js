// Closed vocabulary from the owned proof worker. Never preserve or render a
// raw exception, provider value, or an arbitrary string that merely looks like a code.
const localFailures = new Set([
  'PROOF_FAILED', 'WORKER_FAILED', 'ISOLATION_REQUIRED', 'INELIGIBLE_PLAN',
  'TEE_ATTESTATION_INIT_FAILED', 'TEE_CHANNEL_FAILED', 'TEE_NATIVE_INIT_FAILED',
  'TEE_NATIVE_CONFIG_FAILED', 'TEE_NATIVE_SETUP_FAILED', 'TEE_PROVIDER_REQUEST_FAILED',
  'TEE_DISCLOSURE_FAILED', 'TEE_PROOF_FAILED',
  'HARDWARE_PROFILE_UNQUALIFIED', 'PROVIDER_INVENTORY_UNQUALIFIED',
  'UNQUALIFIED_FIELD', 'UNQUALIFIED_HEADER', 'PROVIDER_HTTP_401', 'PROVIDER_HTTP_403',
  'PROVIDER_HTTP_429', 'PROVIDER_RESPONSE_UNSUPPORTED', 'ADMISSION_REFUSED',
  'CHANNEL_REFUSED', 'TICKET_EXPIRED', 'PROOF_TIMEOUT', 'WORKER_RESTARTED',
]);
export const localFailureCode = value => typeof value === 'string' && localFailures.has(value) ? value : null;
