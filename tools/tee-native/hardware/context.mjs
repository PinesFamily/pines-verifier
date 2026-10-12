// Immutable v5 audience: Pines on Base. The identity signs the deployment into each ticket;
// contract redeploys do not change this image.
export const CONTEXT = Object.freeze({application: 'pines', chain: 8453,
  revision: 'tee-v5-20261012', verificationEpoch: 'pines-tee-v5-20261012',
  protocolVersion: 'pines-tee-native-v2', trustPolicyVersion: 3});
export const WORKER_ID = 'nitro-local-1';
export const TIMES = Object.freeze({admissionMs: 60000, sessionMs: 120000, deliveryMs: 900000, quoteFreshnessMs: 60000});
export const CAPABILITY = 'pines-tee-native-v2';
