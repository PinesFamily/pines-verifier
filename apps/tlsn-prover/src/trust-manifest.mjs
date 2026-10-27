// The extension's reader of pines-trust-manifest-v1: the owner-signed admitted set that replaces this package's
// bundled enclave and schema pins. Fetched from the identity at start and before each verification, verified with
// the two owner keys pinned in the package, held to a monotonic version persisted in extension storage, cached, and
// turned into the view of `config` every other module consumes (`admittedView`). What stays pinned in the package:
// the two owner keys, the protocol version and audience, the Nitro root, the verifier module, the host permissions,
// and the schema DEFINITIONS the package was built with (a manifest naming a schema this package lacks leaves that
// provider out of the view, so the site asks for an update). The verify function and the keys are injected so the
// same module runs in the service worker (against the compiled schemas package) and in Node tests.
export const MANIFEST_STORAGE_KEY = 'pines-trust-manifest';
/** A cached manifest older than this is not used when a fresh fetch fails. */
export const MANIFEST_MAX_AGE_MS = 24 * 60 * 60 * 1000;
/** Before a verification the manifest is refetched unless the cached one is younger than this. */
export const MANIFEST_FRESH_MS = 10 * 60 * 1000;
export const MANIFEST_MAX_BYTES = 262_144;
export const MANIFEST_ERRORS = Object.freeze(['MANIFEST_REQUIRED', 'MANIFEST_UNAVAILABLE', 'MANIFEST_INVALID', 'MANIFEST_FIELDS', 'MANIFEST_FORMAT', 'MANIFEST_SIGNATURE', 'MANIFEST_UNSIGNED',
  'MANIFEST_KEY_UNKNOWN', 'MANIFEST_KEYS', 'MANIFEST_AUDIENCE', 'MANIFEST_ROLLBACK', 'MANIFEST_VERSION_REUSED', 'MANIFEST_DUPLICATE', 'MANIFEST_WINDOW', 'MANIFEST_SAVED_SCHEMAS', 'MANIFEST_POLICY_SIZE']);
const sameRef = (a, b) => a && b && ['schemaId', 'version', 'digest'].every(key => a[key] === b[key]);
function check(condition, code) {if (!condition) throw Error(code);}
/** The audience this package was built for: what a manifest must name to be accepted at all. */
export function manifestAudienceOf(config) {
  const capability = config.tee?.capability;
  check(capability && typeof capability.protocolVersion === 'string' && Number.isSafeInteger(capability.trustPolicyVersion), 'MANIFEST_REQUIRED');
  return {application: config.application, chain: config.chainId, protocolVersion: capability.protocolVersion, trustPolicyVersion: capability.trustPolicyVersion};
}
/** `/trust-manifest` on the identity origin the package's `tee.api` names (`<origin>/tee`). */
export function manifestUrlOf(config) {
  const api = new URL(config.tee.api);
  return api.origin + (config.grokAssistanceView === true ? '/tee/grok-assistance/trust-manifest' : '/trust-manifest');
}
/**
 * Whether this package requires the manifest. build.mjs writes `tee.manifest.required` into every TEE package: true,
 * or false only for the qualification, fixture and local-qualification harnesses (PINES_TEE_MANIFEST=0, refused for a
 * public package). A config without the field is a package built before the manifest and keeps its bundled policy.
 */
export const manifestRequired = config => config?.tee?.manifest?.required === true;
/**
 * The owner keys a package verifies with: the pins, unless this is a TEST build (`config.testBuild`) that was built
 * with an injected test pair (`tee.manifest.testKeys`, the public pins of the committed fixture). A public package has
 * neither flag, so the injected set is unreachable from it; the pins are never swapped, only replaced for that build.
 */
export function manifestKeysOf(config, pins) {
  const injected = config?.tee?.manifest?.testKeys;
  if (injected === undefined) return pins;
  check(config.testBuild === true && Array.isArray(injected) && injected.length >= 1 && injected.length <= 4, 'MANIFEST_KEYS');
  return injected;
}
/**
 * The package's `config`, re-read through a verified manifest: `tee.providers` carry the manifest's policies and saved
 * schemas (bundled definitions only), `tee.capability` is the manifest's provider list restricted to those, `schemas`
 * are the admitted references, `tee.manifest` is the raw signed document for the worker to verify again, and
 * `tee.policySet` is dropped: the worker derives it from the manifest.
 */
export function admittedView(config, verified) {
  const manifest = verified.manifest;
  const providers = [], listed = [];
  for (const entry of manifest.providers) {
    const bundled = config.tee.providers.find(provider => sameRef(provider.reference, entry.schema));
    if (!bundled || bundled.profile !== entry.profile) continue;
    const savedSchemas = entry.savedSchemas.map(ref => ({...ref}));
    providers.push({...bundled, policy: entry.policy, savedSchemas});
    listed.push({id: entry.id, profile: entry.profile, schema: {...entry.schema}, savedSchemas});
  }
  const capability = {...config.tee.capability, providers: listed};
  const {policySet, ...tee} = config.tee; void policySet;
  return {...config, tee: {...tee, providers, capability, manifest: verified.raw, manifestVersion: manifest.version, manifestDigest: verified.digest},
    schemas: providers.filter(provider => provider.policy?.admissionEnabled === true).map(provider => ({...provider.reference}))};
}
/**
 * The reader. `browser.storage.local` persists the last accepted version (anti-rollback) and the last accepted
 * document (so a start without network still has the set it last trusted, re-verified). `verify` is
 * `verifyTrustManifest` from the schemas package; `keys` the pinned owner keys; `extensionVersion` rides every
 * request as `x-pines-extension-version`.
 */
export function createManifestReader({config, browser, fetch: fetchImpl = globalThis.fetch, verify, keys, extensionVersion, now = Date.now, timeoutMs = 8000}) {
  check(typeof verify === 'function' && Array.isArray(keys) && keys.length >= 1, 'MANIFEST_KEYS');
  const audience = manifestAudienceOf(config);
  const url = manifestUrlOf(config);
  const storageKey = config.grokAssistanceView === true ? MANIFEST_STORAGE_KEY + '-grok-assistance' : MANIFEST_STORAGE_KEY;
  let cached;
  let inflight;
  const saved = async () => {
    try {const value = (await browser.storage.local.get(storageKey))?.[storageKey]; return value && Number.isSafeInteger(value.version) && typeof value.digest === 'string' ? value : undefined;}
    catch {return undefined;}
  };
  async function accept(raw, {fetched}) {
    const last = await saved();
    let verified;
    try {verified = await verify(raw, {keys, audience, lastAcceptedVersion: last ? last.version - 1 : undefined});}
    catch (error) {throw Error(MANIFEST_ERRORS.includes(error?.code) ? error.code : 'MANIFEST_INVALID');}
    check(!last || verified.manifest.version !== last.version || verified.digest === last.digest, 'MANIFEST_VERSION_REUSED');
    const canonical = JSON.parse(JSON.stringify(verified.manifest));
    const entry = {version: verified.manifest.version, digest: verified.digest, manifest: canonical, acceptedAt: now()};
    if (!last || verified.manifest.version > last.version || !last.manifest) {
      try {await browser.storage.local.set({[storageKey]: entry});} catch {/* The in-memory cache still holds it; the next start refetches. */}
    }
    cached = {manifest: verified.manifest, raw: canonical, digest: verified.digest, signedBy: verified.signedBy, at: fetched ? now() : 0};
    return cached;
  }
  async function refresh() {
    let response;
    try {
      response = await fetchImpl(url, {credentials: 'omit', redirect: 'error', cache: 'no-store', headers: {'x-pines-extension-version': extensionVersion}, signal: AbortSignal.timeout(timeoutMs)});
    } catch {throw Error('MANIFEST_UNAVAILABLE');}
    check(response.ok && Number(response.headers.get('content-length') ?? 0) <= MANIFEST_MAX_BYTES, 'MANIFEST_UNAVAILABLE');
    const text = await response.text();
    check(text.length <= MANIFEST_MAX_BYTES, 'MANIFEST_UNAVAILABLE');
    let raw;
    try {raw = JSON.parse(text);} catch {throw Error('MANIFEST_INVALID');}
    return accept(raw, {fetched: true});
  }
  async function hydrate() {
    if (cached) return cached;
    const last = await saved();
    if (!last?.manifest) return undefined;
    try {return await accept(last.manifest, {fetched: false});} catch {return undefined;}
  }
  return {
    url,
    /** The verified manifest, fetched unless the cached one is younger than `maxAgeMs`. A failed fetch falls back to a cached manifest younger than a day; a refused manifest never does. */
    async current({maxAgeMs = MANIFEST_FRESH_MS} = {}) {
      await hydrate();
      if (cached && cached.at && now() - cached.at < maxAgeMs) return cached;
      if (!inflight) inflight = refresh().finally(() => {inflight = undefined;});
      try {return await inflight;}
      catch (error) {
        if (error?.message === 'MANIFEST_UNAVAILABLE' && cached && (cached.at === 0 ? (await saved())?.acceptedAt ?? 0 : cached.at) > now() - MANIFEST_MAX_AGE_MS) return cached;
        throw error;
      }
    },
    refresh,
    cached: () => cached,
  };
}
