// pines-trust-manifest-v1 as the enclave policy set and the published capability: the one derivation the signing
// tool, the identity and the extension share. The manifest FORMAT (schema, canonical bytes, signatures, rollback) is
// packages/verification-schemas/src/sybil/manifest.ts; this module says what a manifest MEANS for one disclosure
// class: the policy set `policyForSchema` checks, the capability `/verification-config` publishes and the clients
// compare, and the consistency rules between the manifest's top-level `images`/`revocations` (what a client reads)
// and each provider's `policy` (what the enclave and the identity check). A manifest that passes `admittedSet` for a
// class is byte-for-byte the policy set the identity served from `TLSN_TEE_POLICY_FILE` before the manifest existed.
//
// Not measured into the enclave image: the enclave receives the policy set, never the manifest.
import {CONTEXT} from './hardware/context.mjs';
import {FACTS_GENERATION, LIVE_GENERATION, CLEARANCE_GENERATION, GROK_EMAIL_GENERATION, hardwareCapability, providersFor} from './profile.mjs';
import {policyForSchema} from './policy.mjs';
import {check} from './wire.mjs';
import {canonicalJson} from '../../packages/verification-schemas/src/json.ts';
import {parseManifestBody, parseTrustManifest} from '../../packages/verification-schemas/src/sybil/manifest.ts';

export const POLICY_SET_FORMAT = 'pines-tee-native-policy-set-v1';
/** The provider generations a manifest can be read for (profile.mjs); the live one unless a consumer names the other. */
export const GENERATIONS = Object.freeze([LIVE_GENERATION, FACTS_GENERATION, CLEARANCE_GENERATION, GROK_EMAIL_GENERATION]);
export function checkGeneration(generation = LIVE_GENERATION) {
  check(GENERATIONS.includes(generation), 'TRUST_MANIFEST_GENERATION');
  return generation;
}
/** The audience every manifest for this image must name: the measured context's own values. */
export const MANIFEST_AUDIENCE = Object.freeze({application: CONTEXT.application, chain: CONTEXT.chain,
  protocolVersion: CONTEXT.protocolVersion, trustPolicyVersion: CONTEXT.trustPolicyVersion});
const sameTuple = (a, b) => Array.isArray(a) && Array.isArray(b) && a.length === 3 && b.length === 3 && a.every((v, i) => v === b[i]);
const sortedStrings = list => canonicalJson([...list].sort());

/** The policy set the identity loads and the enclave checks, derived from the manifest alone. */
export function policySetFromManifest(manifest) {
  const body = parseManifestBody(stripSignatures(manifest));
  return {format: POLICY_SET_FORMAT, context: {...CONTEXT},
    providers: body.providers.map(entry => ({id: entry.id, schema: {...entry.schema}, inventorySha256: entry.inventorySha256, policy: structuredClone(entry.policy)}))};
}
/** The capability the identity publishes under `tee` and the clients compare, derived from the manifest alone. */
export function capabilityFromManifest(manifest, claimSigningAvailable = false) {
  const body = parseManifestBody(stripSignatures(manifest));
  return {...CONTEXT, protocol: CONTEXT.protocolVersion, capabilityVersion: 2, claimSigningAvailable: claimSigningAvailable === true,
    providers: body.providers.map(entry => ({id: entry.id, profile: entry.profile, schema: {...entry.schema}, savedSchemas: entry.savedSchemas.map(ref => ({...ref}))}))};
}
function stripSignatures(manifest) {
  const {signatures, ...body} = manifest ?? {};
  void signatures; return body;
}
/**
 * The rules that tie the client-facing fields to the enclave-facing policies. Every image tuple is some provider
 * policy's tuple and every policy tuple is an image; every policy's revocation lists equal the manifest's; every
 * policy names its provider's profile and the audience's trust policy version. Structural validity is the parser's.
 */
export function checkManifestConsistency(manifest) {
  const body = parseManifestBody(stripSignatures(manifest));
  check(body.audience.application === MANIFEST_AUDIENCE.application && body.audience.chain === MANIFEST_AUDIENCE.chain
    && body.audience.protocolVersion === MANIFEST_AUDIENCE.protocolVersion && body.audience.trustPolicyVersion === MANIFEST_AUDIENCE.trustPolicyVersion, 'TRUST_MANIFEST_AUDIENCE');
  const imageTuples = body.images.map(entry => entry.pcrTuple);
  for (const entry of body.providers) {
    const policy = entry.policy;
    check(policy.profile === entry.profile, 'TRUST_MANIFEST_PROFILE');
    check(policy.trustPolicyVersion === body.audience.trustPolicyVersion && policy.verificationEpoch === CONTEXT.verificationEpoch, 'TRUST_MANIFEST_CONTEXT');
    check(Array.isArray(policy.pcrTuples) && policy.pcrTuples.length >= 1 && policy.pcrTuples.every(tuple => imageTuples.some(image => sameTuple(image, tuple))), 'TRUST_MANIFEST_IMAGES');
    for (const field of ['revokedMeasurements', 'revokedBootIds', 'revokedWorkerIds'])
      check(Array.isArray(policy[field]) && sortedStrings(policy[field]) === sortedStrings(body.revocations[field]), 'TRUST_MANIFEST_REVOCATIONS');
  }
  check(imageTuples.every(image => body.providers.some(entry => entry.policy.pcrTuples.some(tuple => sameTuple(tuple, image)))), 'TRUST_MANIFEST_IMAGES');
  return body;
}
const sameRef = (a, b) => a && b && a.schemaId === b.schemaId && a.version === b.version && a.digest === b.digest;
/**
 * What a consumer (the identity, the extension's worker, the signing tool's self-check) accepts a manifest AS, for
 * one disclosure class: after the consistency rules, every provider's policy passes `policyForSchema` exactly as a
 * served policy set does (so each schema reference resolves to this build's own definition and digest, the inventory
 * digest matches, the limits match), and the derived capability names exactly this class's providers, profiles and
 * live schema references. A manifest for a schema this build does not carry is refused here, never served or proven.
 */
export async function admittedSet(manifest, disclosurePolicy, {claimSigningAvailable = false, generation = LIVE_GENERATION} = {}) {
  // `generation` (profile.mjs): which schema set of the class this consumer was built or released for. A manifest for
  // the other generation names schemas this consumer does not admit and is refused as TRUST_MANIFEST_CAPABILITY.
  checkGeneration(generation);
  const body = checkManifestConsistency(manifest);
  const policySet = policySetFromManifest(body);
  const providers = providersFor(disclosurePolicy, generation);
  check(body.providers.length === providers.length && providers.every(provider => body.providers.some(entry => entry.id === provider.id
    && entry.profile === provider.profile && sameRef(entry.schema, provider.reference))), 'TRUST_MANIFEST_CAPABILITY');
  const policies = new Map();
  for (const provider of providers) {
    const policy = await policyForSchema(policySet, provider.reference, disclosurePolicy);
    check(policy, 'TRUST_MANIFEST_POLICY');
    policies.set(provider.id, policy);
  }
  const capability = capabilityFromManifest(body, claimSigningAvailable);
  const bundled = hardwareCapability(disclosurePolicy, generation);
  check(canonicalJson(capability.providers.map(({id, profile, schema}) => ({id, profile, schema}))) === canonicalJson(bundled.providers.map(({id, profile, schema}) => ({id, profile, schema}))), 'TRUST_MANIFEST_CAPABILITY');
  return {body, policySet, capability, policies};
}
/**
 * The signing tool's half: an unsigned body from a policy set of one class plus the images' public provenance
 * (`{label, pcr0, buildCommit, imageLabel, admittedFrom, admittedUntil?}` per admitted tuple). The set is validated
 * with `policyForSchema` first, every provider of the class must have an entry, every policy tuple must have an
 * image row and no image row may name a tuple no policy admits.
 */
export async function manifestBodyFromPolicySet({policySet, disclosurePolicy, version, issuedAt, images, generation = LIVE_GENERATION}) {
  checkGeneration(generation);
  check(policySet && policySet.format === POLICY_SET_FORMAT && Array.isArray(policySet.providers), 'TRUST_MANIFEST_POLICY_SET');
  check(Number.isSafeInteger(version) && version >= 1 && Number.isSafeInteger(issuedAt) && issuedAt > 0, 'TRUST_MANIFEST_VERSION');
  const providers = providersFor(disclosurePolicy, generation);
  check(policySet.providers.length === providers.length, 'TRUST_MANIFEST_POLICY_SET');
  const entries = [];
  for (const provider of providers) {
    const policy = await policyForSchema(policySet, provider.reference, disclosurePolicy);
    check(policy, 'TRUST_MANIFEST_POLICY_SET');
    const row = policySet.providers.find(entry => entry.id === provider.id);
    entries.push({id: provider.id, profile: provider.profile, schema: {...provider.reference}, savedSchemas: provider.savedSchemas.map(ref => ({...ref})),
      inventorySha256: row.inventorySha256, policy: structuredClone(policy)});
  }
  const tuples = [];
  for (const entry of entries) for (const tuple of entry.policy.pcrTuples) if (!tuples.some(known => sameTuple(known, tuple))) tuples.push(tuple);
  check(Array.isArray(images) && images.length === tuples.length, 'TRUST_MANIFEST_IMAGES');
  const imageRows = tuples.map(tuple => {
    const row = images.find(image => image.pcr0 === tuple[0]);
    check(row, 'TRUST_MANIFEST_IMAGES');
    const {pcr0, ...rest} = row; void pcr0;
    return {...rest, pcrTuple: [...tuple]};
  });
  const first = entries[0].policy;
  const revocations = {revokedMeasurements: [...first.revokedMeasurements], revokedBootIds: [...first.revokedBootIds], revokedWorkerIds: [...first.revokedWorkerIds]};
  const body = {format: 'pines-trust-manifest-v1', version, issuedAt, audience: {...MANIFEST_AUDIENCE}, images: imageRows, providers: entries, revocations};
  checkManifestConsistency(body);
  return parseManifestBody(body);
}
/** The monotonic rule a producer applies before signing: strictly above the previous manifest or the last known version. */
export function checkVersionAdvances(version, {previous, lastVersion} = {}) {
  const floor = previous !== undefined ? parseTrustManifest(previous).version : lastVersion;
  check(floor === undefined || (Number.isSafeInteger(floor) && floor >= 0), 'TRUST_MANIFEST_VERSION');
  check(floor === undefined || version > floor, 'TRUST_MANIFEST_ROLLBACK');
}
