// Measured capacity envelope; see the capacity selection design.
import {check, exact, verify, digest, encode} from './wire.mjs';
import {disclosurePolicy} from './disclosure-policy.mjs';

export const MAX_PROOF_SLOTS = 8;
export const CAPACITY_ENVELOPE = 'pines-tee-capacity-envelope-v2';
export const CAPACITY_SELECTION_DOMAIN = 'pines/tee/capacity-selection/v1';
export const CAPACITY_SELECTION_LIFETIME_MS = 60000;
// Accounting bounds derived from code limits, not measurements; hardware must confirm them.
// Guest kernel tolerance between the Nitro allocation and MemTotal.
export const GUEST_ALLOWANCE_MIB = 256;
// Root filesystem in RAM, Node (heap capped at 384 MiB), the identity helper
// (128 MiB RLIMIT_AS), runtime bridges and metrics. Hardware must verify RSS.
export const SHARED_SERVICE_MIB = 960;
// Each session's four 4-MiB wire queues, outbox packets, native IPC buffer, kernel socket
// buffers, page tables and its clock helper. At one slot the sum is the qualified 1024 MiB.
export const SESSION_SERVICE_MIB = 64;
export const serviceHeadroomMiB = proofSlots => SHARED_SERVICE_MIB + SESSION_SERVICE_MIB * proofSlots;
// nativeMemoryMiB is the hard RLIMIT_AS the measured launcher installs on each native proof
// process. A class floor comes from evidence: 2048 aborted on a maximum redacted body, 3072 is
// the hardware-qualified C1 value, 4096 is the launcher's parser ceiling. A cheaper class needs
// native refusal of the expensive path before expensive work, then its own hardware floor.
export const RESOURCE_CLASSES = Object.freeze({
  'redacted-max-v1': Object.freeze({minNativeMemoryMiB: 3072, maxNativeMemoryMiB: 4096}),
  // Experimental envelope only: a deployment needs measured capacity evidence.
  // Full authenticated response coverage is enforced before native accept().
  'full-response-v1': Object.freeze({minNativeMemoryMiB: 512, maxNativeMemoryMiB: 4096}),
  // Response header values hidden, body gzipped, revealed bytes capped at 4096 and
  // refused before accept() allocates any circuit. The floor is
  // ceil(max VmPeak at <= 4096 revealed bytes x 1.25) rounded up to 64 MiB: the matrix
  // measured 311.7 MiB at the cap over 120 verified runs, so 390 -> 448. Local
  // generated-data evidence (report.json sha256 cda69478…, docs/
  // tee-private-headers-cost-2026-10-07.md, commit 7d16a07d); HARDWARE MUST CONFIRM IT
  // before any deployment. The same evidence holds a 512 MiB slot locally (12/12
  // RLIMIT_AS probes); an 8 KiB revealed cap would need 576 MiB.
  'private-headers-gzip-v1': Object.freeze({minNativeMemoryMiB: 448, maxNativeMemoryMiB: 4096}),
  // Same enforced limits; this new profile still requires its own hardware evidence.
  'grok-clearance-private-v1': Object.freeze({minNativeMemoryMiB: 448, maxNativeMemoryMiB: 4096}),
  // The sybil-facts class (disclosure-policy.mjs FACTS_COMPLETE): the reveal-all response path of full-response-v1
  // with the facts sessions' sizes, so the same experimental floor; UNMEASURED on hardware, like full-response-v1.
  'facts-complete-v1': Object.freeze({minNativeMemoryMiB: 512, maxNativeMemoryMiB: 4096}),
  // Same enforced complete-response bounds; one-slot hardware qualification is
  // required for the combined email and clearance profile before admission.
  'grok-email-complete-v1': Object.freeze({minNativeMemoryMiB: 512, maxNativeMemoryMiB: 4096}),
});
const ALLOCATION = Object.freeze({minCpu: 2, maxCpu: 64, minMemoryMiB: 2048, maxMemoryMiB: 262144});
export const CAPACITY_SELECTION_FIELDS = Object.freeze(['resourceClass', 'proofSlots', 'nativeMemoryMiB', 'enclaveCpu', 'enclaveMemoryMiB']);
export const RESOURCE_POLICY_FIELDS = Object.freeze(['version', 'proofSlots', 'enclaveCpu', 'enclaveMemoryMiB', 'resourceClass', 'nativeMemoryMiB', 'serviceHeadroomMiB']);
export const DEFAULT_CAPACITY_SELECTION = Object.freeze({resourceClass: 'redacted-max-v1', proofSlots: 1, nativeMemoryMiB: 3072,
  enclaveCpu: 2, enclaveMemoryMiB: 6144});
const within = (value, min, max) => Number.isSafeInteger(value) && value >= min && value <= max;

export function validateCapacitySelection(value) {
  exact(value, CAPACITY_SELECTION_FIELDS);
  check(typeof value.resourceClass === 'string' && Object.hasOwn(RESOURCE_CLASSES, value.resourceClass), 'RESOURCE_CLASS');
  const resourceClass = RESOURCE_CLASSES[value.resourceClass];
  check(within(value.proofSlots, 1, MAX_PROOF_SLOTS) && within(value.enclaveCpu, ALLOCATION.minCpu, ALLOCATION.maxCpu)
    && within(value.enclaveMemoryMiB, ALLOCATION.minMemoryMiB, ALLOCATION.maxMemoryMiB), 'RESOURCE_POLICY');
  check(within(value.nativeMemoryMiB, resourceClass.minNativeMemoryMiB, resourceClass.maxNativeMemoryMiB), 'RESOURCE_CLASS_FLOOR');
  check(value.proofSlots * value.nativeMemoryMiB + serviceHeadroomMiB(value.proofSlots)
    <= value.enclaveMemoryMiB - GUEST_ALLOWANCE_MIB, 'RESOURCE_HEADROOM');
  return Object.freeze({resourceClass: value.resourceClass, proofSlots: value.proofSlots, nativeMemoryMiB: value.nativeMemoryMiB,
    enclaveCpu: value.enclaveCpu, enclaveMemoryMiB: value.enclaveMemoryMiB});
}

/** The one mapping: every accounting value is derived, so no attested field can understate a process. */
export function resourcePolicyFor(selection) {
  const s = validateCapacitySelection(selection);
  return Object.freeze({version: 1, proofSlots: s.proofSlots, enclaveCpu: s.enclaveCpu, enclaveMemoryMiB: s.enclaveMemoryMiB,
    resourceClass: s.resourceClass, nativeMemoryMiB: s.nativeMemoryMiB, serviceHeadroomMiB: serviceHeadroomMiB(s.proofSlots)});
}
// The qualified C1 policy, byte-identical to the earlier sealed default.
export const DEFAULT_RESOURCE_POLICY = resourcePolicyFor(DEFAULT_CAPACITY_SELECTION);

/** Attested shape, unchanged since resource policy 1. Earlier sealed images attest the default. */
export function validateResourcePolicy(value) {
  exact(value, RESOURCE_POLICY_FIELDS);
  check(value.version === 1, 'RESOURCE_POLICY');
  const policy = resourcePolicyFor(Object.fromEntries(CAPACITY_SELECTION_FIELDS.map(key => [key, value[key]])));
  check(value.serviceHeadroomMiB === policy.serviceHeadroomMiB, 'RESOURCE_HEADROOM');
  return policy;
}
export const capacitySelectionOf = policy => {
  const p = validateResourcePolicy(policy);
  return Object.freeze(Object.fromEntries(CAPACITY_SELECTION_FIELDS.map(key => [key, p[key]])));
};
export function membershipContext(context, resourcePolicy) {
  return resourcePolicy ? {...context, resourcePolicy: validateResourcePolicy(resourcePolicy)} : context;
}

/** Actual guest resources, parsed by measured code from /proc. Independent of any selection. */
export function observeAllocation({stat, meminfo}) {
  check(typeof stat === 'string' && typeof meminfo === 'string', 'RESOURCE_ALLOCATION');
  const cpuCount = (stat.match(/^cpu\d+ /gm) ?? []).length, memoryKiB = Number(meminfo.match(/^MemTotal:\s+(\d+) kB$/m)?.[1]);
  check(within(cpuCount, ALLOCATION.minCpu, ALLOCATION.maxCpu) && within(memoryKiB, 1, ALLOCATION.maxMemoryMiB * 1024), 'RESOURCE_ALLOCATION');
  return Object.freeze({cpuCount, memoryKiB});
}
export function checkRuntimeAllocation(resourcePolicy, {cpuCount, memoryKiB}) {
  const p = validateResourcePolicy(resourcePolicy);
  check(cpuCount === p.enclaveCpu && Number.isSafeInteger(memoryKiB)
    && memoryKiB <= p.enclaveMemoryMiB * 1024 && memoryKiB >= (p.enclaveMemoryMiB - GUEST_ALLOWANCE_MIB) * 1024, 'RESOURCE_ALLOCATION');
  check(memoryKiB >= (p.nativeMemoryMiB * p.proofSlots + p.serviceHeadroomMiB) * 1024, 'RESOURCE_HEADROOM');
  return Object.freeze({cpuCount, memoryKiB});
}

/** Verify one controller-signed selection for THIS boot. The caller freezes the result once. */
export async function checkCapacitySelection(document, {authorityKey, workerId, bootId, observed, now}) {
  check(typeof authorityKey === 'string' && /^[a-f0-9]{64}$/.test(authorityKey), 'CAPACITY_AUTHORITY');
  const body = await verify(CAPACITY_SELECTION_DOMAIN, document, authorityKey);
  exact(body, ['kind', 'envelope', 'workerId', 'bootId', 'selection', 'issuedAt', 'expiresAt']);
  check(body.kind === 'capacity-selection' && body.envelope === CAPACITY_ENVELOPE, 'CAPACITY_SELECTION');
  check(typeof bootId === 'string' && body.workerId === workerId && body.bootId === bootId, 'CAPACITY_SELECTION_BOOT');
  check(Number.isSafeInteger(now) && Number.isSafeInteger(body.issuedAt) && Number.isSafeInteger(body.expiresAt)
    && body.issuedAt <= now + 2000 && body.issuedAt >= now - CAPACITY_SELECTION_LIFETIME_MS
    && body.expiresAt > now && body.expiresAt > body.issuedAt
    && body.expiresAt - body.issuedAt <= CAPACITY_SELECTION_LIFETIME_MS, 'CAPACITY_SELECTION_STALE');
  const resourcePolicy = resourcePolicyFor(body.selection);
  const runtimeAllocation = checkRuntimeAllocation(resourcePolicy, observed);
  return Object.freeze({resourcePolicy, runtimeAllocation, selectionHash: await digest(encode(document))});
}

// One mapping, at API placement, enclave offer and native launch. No ticket can
// change the frozen boot's class or budget, even when a larger budget would fit.
export function nativeAllocation(resourcePolicy,selectedDisclosure) {
  const resource=validateResourcePolicy(resourcePolicy),disclosure=disclosurePolicy(selectedDisclosure);
  check(resource.resourceClass===disclosure.resourceClass,'DISCLOSURE_RESOURCE_MISMATCH');
  return Object.freeze({disclosurePolicy:disclosure.id,nativeMemoryMiB:resource.nativeMemoryMiB,
    reservedNativeMemoryMiB:resource.nativeMemoryMiB,reservedProofSlots:1});
}
