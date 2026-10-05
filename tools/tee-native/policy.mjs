// Policy selection never accepts a browser-supplied host, profile or inventory.
import {providerForSchema, HARDWARE_PROVIDERS, LIMITS} from './profile.mjs';
import {CONTEXT} from './hardware/context.mjs';
import {check, encode, digest, exact} from './wire.mjs';

export async function policyForSchema(set, reference) {
  const provider = providerForSchema(reference);
  check(provider, 'SCHEMA_UNAVAILABLE');
  exact(set, ['format', 'context', 'providers']);
  check(set.format === 'pines-tee-native-policy-set-v1' && set.context && Object.keys(set.context).length === Object.keys(CONTEXT).length
    && Object.entries(CONTEXT).every(([k, v]) => set.context[k] === v), 'POLICY_CONTEXT');
  check(Array.isArray(set.providers) && set.providers.length <= HARDWARE_PROVIDERS.length, 'POLICY_PROVIDERS');
  const ids = new Set();
  for (const entry of set.providers) {
    exact(entry, ['id', 'schema', 'inventorySha256', 'policy']);
    const known = providerForSchema(entry.schema);
    check(known && entry.id === known.id && !ids.has(entry.id), 'POLICY_PROVIDERS'); ids.add(entry.id);
    check(entry.inventorySha256 === await digest(encode(known.inventory)), 'POLICY_INVENTORY');
    const p = entry.policy;
    exact(p, ['profile','admissionEnabled','providerQualified','clockQualified','lifecycleQualified','measurements','pcrTuples',
      'simulationAllowed','debugAllowed','providerHost','providerPort','channelVsockPort','providerEgressVsockPort','parentCid','limits',
      'verificationEpoch','trustPolicyVersion','revokedBootIds','revokedWorkerIds','revokedMeasurements']);
    check(p && p.profile === known.profile && p.providerHost === known.host && p.providerPort === 443
      && p.providerEgressVsockPort === known.egressPort && p.parentCid === 3 && p.channelVsockPort === 8000
      && p.verificationEpoch === CONTEXT.verificationEpoch && p.trustPolicyVersion === CONTEXT.trustPolicyVersion
      && p.simulationAllowed === false && p.debugAllowed === false, 'POLICY_CONTEXT');
    for (const flag of ['admissionEnabled', 'providerQualified', 'clockQualified', 'lifecycleQualified']) check(typeof p[flag] === 'boolean', 'POLICY_QUALIFICATION');
    check(!p.providerQualified || known.inventory.qualified === true, 'POLICY_INVENTORY');
    check(!p.admissionEnabled || p.providerQualified && p.clockQualified && p.lifecycleQualified, 'POLICY_QUALIFICATION');
    const expectedLimits = {...known.schema.limits}; delete expectedLimits.concurrency;
    expectedLimits.protocolBytesPerDirection = LIMITS.protocolBytes;
    check(new TextDecoder().decode(encode(p.limits)) === new TextDecoder().decode(encode(expectedLimits)), 'POLICY_LIMITS');
    check(Array.isArray(p.pcrTuples) && p.pcrTuples.length === 1 && Array.isArray(p.pcrTuples[0]) && p.pcrTuples[0].length === 3
      && p.pcrTuples[0].every(x => typeof x === 'string' && /^[a-f0-9]{96}$/.test(x) && !/^0+$/.test(x))
      && Array.isArray(p.measurements) && p.measurements.length === 1 && p.measurements[0] === p.pcrTuples[0][0], 'POLICY_MEASUREMENTS');
    for (const [field, pattern] of [['revokedBootIds', /^[a-f0-9]{64}$/], ['revokedMeasurements', /^[a-f0-9]{96}$/], ['revokedWorkerIds', /^[a-z0-9][a-z0-9-]{1,63}$/]]) {
      check(Array.isArray(p[field]) && p[field].length <= 256 && p[field].every(value => typeof value === 'string' && pattern.test(value))
        && new Set(p[field]).size === p[field].length, 'POLICY_REVOCATIONS');
    }
  }
  return set.providers.find(entry => entry.id === provider.id)?.policy ?? null;
}
