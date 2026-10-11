// Immutable v3 audience: the Base (8453) v1 world, keyed by the existing Sydney identity key.
// Labels name no host region. Any change requires a new measured image.
export const CONTEXT = Object.freeze({application: 'pines', chain: 8453,
  revision: 'tee-v3-20261012', verificationEpoch: 'pines-tee-v3-20261012',
  protocolVersion: 'pines-tee-native-v2', trustPolicyVersion: 2,
  deploymentHash: 'bd755354bbcf69b5832af648114c079c8784b899d38d723e55547541bbe2a8ae'});
export const WORKER_ID = 'nitro-local-1';
export const TIMES = Object.freeze({admissionMs: 60000, sessionMs: 120000, deliveryMs: 900000, quoteFreshnessMs: 60000});
export const CAPABILITY = 'pines-tee-native-v2';
