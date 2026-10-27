// The provider generations of the private-headers class (tools/tee-native/profile.mjs): the live one, and the
// sybil-facts one whose policy set is the unmeasured fixture until its image exists. Omitted is the live one, so
// every build made before the option is byte-identical.
export const LIVE_GENERATION = 'v5-20261012';
export const FACTS_GENERATION = 'sybil-facts-20261020';
export const CLEARANCE_GENERATION = 'grok-clearance-20261025';
export const GROK_EMAIL_GENERATION = 'grok-email-20261026';
export const GENERATIONS = Object.freeze([LIVE_GENERATION, FACTS_GENERATION, CLEARANCE_GENERATION, GROK_EMAIL_GENERATION]);
export function teePolicyFile(disclosurePolicyId, generation = LIVE_GENERATION) {
  if (!GENERATIONS.includes(generation)) throw Error('TEE_PROVIDER_GENERATION');
  if (disclosurePolicyId === 'grok-email-complete-v1') {if (generation !== GROK_EMAIL_GENERATION) throw Error('TEE_PROVIDER_GENERATION'); return 'tools/tee-native/hardware/policy.grok-email.unmeasured.json';}
  if (disclosurePolicyId === 'grok-clearance-private-v1') {if (generation !== CLEARANCE_GENERATION) throw Error('TEE_PROVIDER_GENERATION'); return 'tools/tee-native/hardware/policy.grok-clearance.unmeasured.json';}
  if (disclosurePolicyId === 'full-response-v1') {if (generation !== LIVE_GENERATION) throw Error('TEE_PROVIDER_GENERATION'); return 'tools/tee-native/hardware/policy.json';}
  // The facts generation is the facts-complete class's (multi-exchange protocol §2.6): one names the other.
  if (disclosurePolicyId === 'private-headers-gzip-v1') {if (generation !== LIVE_GENERATION) throw Error('TEE_PROVIDER_GENERATION'); return 'tools/tee-native/hardware/policy.private-headers-public.json';}
  if (disclosurePolicyId === 'facts-complete-v1') {if (generation !== FACTS_GENERATION) throw Error('TEE_PROVIDER_GENERATION'); return 'tools/tee-native/hardware/policy.sybil-facts-20261020.unmeasured.json';}
  throw Error('TEE_DISCLOSURE_POLICY');
}
/** The pinned capability file a package of this class and generation is held to (`TEE_PUBLIC_PIN_DRIFT`). */
export function teeCapabilityPin(disclosurePolicyId, generation = LIVE_GENERATION) {
  if (!GENERATIONS.includes(generation)) throw Error('TEE_PROVIDER_GENERATION');
  if (disclosurePolicyId === 'grok-email-complete-v1') {if (generation !== GROK_EMAIL_GENERATION) throw Error('TEE_PROVIDER_GENERATION'); return 'config/tee-capability-grok-email.json';}
  if (disclosurePolicyId === 'grok-clearance-private-v1') {if (generation !== CLEARANCE_GENERATION) throw Error('TEE_PROVIDER_GENERATION'); return 'config/tee-capability-grok-clearance.json';}
  if (disclosurePolicyId === 'full-response-v1') return 'config/tee-capability.json';
  if (disclosurePolicyId === 'facts-complete-v1') {if (generation !== FACTS_GENERATION) throw Error('TEE_PROVIDER_GENERATION'); return 'config/tee-capability-sybil-facts.json';}
  if (generation !== LIVE_GENERATION) throw Error('TEE_PROVIDER_GENERATION');
  return 'config/tee-capability-private-headers.json';
}
