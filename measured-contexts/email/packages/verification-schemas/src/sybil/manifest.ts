/**
 * `pines-trust-manifest-v1`: the owner-signed admitted set that replaces the extension's bundled enclave and schema pins
 * (provider-fact specification §1; owner S4: clients trust the set because the owner signed it, two owner keys,
 * active and standby). This module is the **format**: schema, canonical bytes, signature verification and the
 * anti-rollback rule. The signing tool (`tools/tee-native/sign-manifest.mjs`), the identity's `/trust-manifest`, the
 * extension's and the web's use of it are track A's.
 *
 * Signing: ECDSA P-256 over SHA-256 through WebCrypto (Node 22 and every Chrome the extension supports), raw
 * `r ‖ s` signatures, over `MANIFEST_DOMAIN ‖ "\n" ‖ canonicalJson(body)` where `body` is the manifest without its
 * `signatures`. Public keys are pinned as JWK `{kty: "EC", crv: "P-256", x, y}` so the same object works in all three
 * parties. One valid owner signature is sufficient.
 */
import {canonicalJson} from "../json.ts";

export const MANIFEST_FORMAT = "pines-trust-manifest-v1";
export const MANIFEST_DOMAIN = "pines-trust-manifest-v1";
export const MANIFEST_ALGORITHM = "ECDSA-P256-SHA256";
export type SchemaRef = Readonly<{schemaId: string; version: number; digest: string}>;
export type ManifestAudience = Readonly<{application: string; chain: number; protocolVersion: string; trustPolicyVersion: number}>;
/** One admitted verifier image: its complete PCR tuple and the public build that reproduces it. */
export type ManifestImage = Readonly<{
  label: string;
  /** `[pcr0, pcr1, pcr2]`, 96 hex each, as the policy set's `pcrTuples` entries. */
  pcrTuple: readonly [string, string, string];
  /** The commit of the public repository that reproduces this image. */
  buildCommit: string;
  imageLabel: string;
  /** Unix seconds. A receipt verified before `admittedFrom` or after `admittedUntil` is not covered by this entry. */
  admittedFrom: number;
  admittedUntil?: number;
}>;
/** Exactly the policy-set entries `tools/tee-native/policy.mjs` `policyForSchema` checks, plus the saved schemas. */
export type ManifestProvider = Readonly<{
  id: string; profile: string; schema: SchemaRef; savedSchemas: readonly SchemaRef[]; inventorySha256: string;
  /** The per-provider enclave policy object, opaque here and validated by `policyForSchema` against the measured context. */
  policy: Readonly<Record<string, unknown>>;
}>;
export type ManifestRevocations = Readonly<{revokedMeasurements: readonly string[]; revokedBootIds: readonly string[]; revokedWorkerIds: readonly string[]}>;
export type ManifestSignature = Readonly<{keyId: string; algorithm: typeof MANIFEST_ALGORITHM; signature: string}>;
export type TrustManifestBody = Readonly<{
  format: typeof MANIFEST_FORMAT;
  /** Monotonic. A client refuses a manifest whose version is not above the last one it accepted. */
  version: number;
  /** Unix seconds; informational, no expiry (owner: no timelocks, no dead-man). */
  issuedAt: number;
  audience: ManifestAudience;
  images: readonly ManifestImage[];
  providers: readonly ManifestProvider[];
  revocations: ManifestRevocations;
}>;
export type TrustManifest = TrustManifestBody & Readonly<{signatures: readonly ManifestSignature[]}>;
export type OwnerKey = Readonly<{keyId: string; role: "active" | "standby"; jwk: Readonly<{kty: "EC"; crv: "P-256"; x: string; y: string}>}>;

export class TrustManifestError extends Error {
  readonly code: string;
  constructor(code: string) {super(code); this.code = code;}
}
function fail(condition: unknown, code = "MANIFEST_INVALID"): asserts condition {if (!condition) throw new TrustManifestError(code);}
const record = (value: unknown): Record<string, unknown> => {fail(value && typeof value === "object" && !Array.isArray(value)); return value as Record<string, unknown>;};
const exact = (value: Record<string, unknown>, keys: readonly string[]) => fail(Object.keys(value).length === keys.length && keys.every(key => Object.prototype.hasOwnProperty.call(value, key)), "MANIFEST_FIELDS");
const HEX96 = /^[a-f0-9]{96}$/, HEX64 = /^[a-f0-9]{64}$/, HEX40 = /^[a-f0-9]{40}$/, LABEL = /^[a-z0-9][a-z0-9._-]{0,63}$/, DIGEST = /^sha256:[a-f0-9]{64}$/, BASE64URL = /^[A-Za-z0-9_-]{86}$/;
const seconds = (value: unknown): number => {fail(typeof value === "number" && Number.isSafeInteger(value) && value > 0 && value < 4_102_444_800); return value;};
function schemaRef(raw: unknown): SchemaRef {
  const value = record(raw); exact(value, ["schemaId", "version", "digest"]);
  fail(typeof value.schemaId === "string" && /^[a-z0-9._-]{1,128}$/.test(value.schemaId) && typeof value.version === "number" && Number.isSafeInteger(value.version) && value.version >= 1 && typeof value.digest === "string" && DIGEST.test(value.digest));
  return Object.freeze({schemaId: value.schemaId, version: value.version, digest: value.digest});
}
const sameRef = (a: SchemaRef, b: SchemaRef) => a.schemaId === b.schemaId && a.version === b.version && a.digest === b.digest;
function strings(value: unknown, pattern: RegExp, max: number): readonly string[] {
  fail(Array.isArray(value) && value.length <= max && value.every(item => typeof item === "string" && pattern.test(item)));
  fail(new Set(value).size === value.length, "MANIFEST_DUPLICATE"); return Object.freeze([...value as string[]]);
}
function image(raw: unknown): ManifestImage {
  const value = record(raw); exact(value, ["label", "pcrTuple", "buildCommit", "imageLabel", "admittedFrom", ...(Object.prototype.hasOwnProperty.call(value, "admittedUntil") ? ["admittedUntil"] : [])]);
  fail(typeof value.label === "string" && LABEL.test(value.label) && typeof value.imageLabel === "string" && LABEL.test(value.imageLabel));
  fail(Array.isArray(value.pcrTuple) && value.pcrTuple.length === 3 && value.pcrTuple.every(pcr => typeof pcr === "string" && HEX96.test(pcr) && !/^0+$/.test(pcr)));
  fail(typeof value.buildCommit === "string" && HEX40.test(value.buildCommit));
  const admittedFrom = seconds(value.admittedFrom);
  const admittedUntil = value.admittedUntil === undefined ? undefined : seconds(value.admittedUntil);
  fail(admittedUntil === undefined || admittedUntil >= admittedFrom, "MANIFEST_WINDOW");
  const tuple = value.pcrTuple as string[];
  return Object.freeze({label: value.label, pcrTuple: Object.freeze([tuple[0]!, tuple[1]!, tuple[2]!] as const), buildCommit: value.buildCommit, imageLabel: value.imageLabel, admittedFrom, ...(admittedUntil === undefined ? {} : {admittedUntil})});
}
function provider(raw: unknown): ManifestProvider {
  const value = record(raw); exact(value, ["id", "profile", "schema", "savedSchemas", "inventorySha256", "policy"]);
  fail(typeof value.id === "string" && LABEL.test(value.id) && typeof value.profile === "string" && /^[a-z0-9.]{1,128}$/.test(value.profile));
  fail(typeof value.inventorySha256 === "string" && HEX64.test(value.inventorySha256));
  const schema = schemaRef(value.schema);
  fail(Array.isArray(value.savedSchemas) && value.savedSchemas.length >= 1 && value.savedSchemas.length <= 16);
  const saved = Object.freeze((value.savedSchemas as unknown[]).map(schemaRef));
  fail(saved.some(ref => sameRef(ref, schema)), "MANIFEST_SAVED_SCHEMAS");
  fail(new Set(saved.map(ref => canonicalJson(ref))).size === saved.length, "MANIFEST_DUPLICATE");
  const policy = record(value.policy); fail(canonicalJson(policy).length <= 65_536, "MANIFEST_POLICY_SIZE");
  return Object.freeze({id: value.id, profile: value.profile, schema, savedSchemas: saved, inventorySha256: value.inventorySha256, policy: Object.freeze(JSON.parse(JSON.stringify(policy)) as Record<string, unknown>)});
}
export function parseManifestBody(raw: unknown): TrustManifestBody {
  const value = record(raw); exact(value, ["format", "version", "issuedAt", "audience", "images", "providers", "revocations"]);
  fail(value.format === MANIFEST_FORMAT, "MANIFEST_FORMAT");
  fail(typeof value.version === "number" && Number.isSafeInteger(value.version) && value.version >= 1);
  const audience = record(value.audience); exact(audience, ["application", "chain", "protocolVersion", "trustPolicyVersion"]);
  fail(typeof audience.application === "string" && /^[a-zA-Z0-9._-]{1,64}$/.test(audience.application) && typeof audience.chain === "number" && Number.isSafeInteger(audience.chain) && audience.chain >= 1
    && typeof audience.protocolVersion === "string" && /^[a-z0-9.-]{1,64}$/.test(audience.protocolVersion) && typeof audience.trustPolicyVersion === "number" && Number.isSafeInteger(audience.trustPolicyVersion) && audience.trustPolicyVersion >= 1);
  fail(Array.isArray(value.images) && value.images.length >= 1 && value.images.length <= 64 && Array.isArray(value.providers) && value.providers.length >= 1 && value.providers.length <= 16);
  const images = Object.freeze((value.images as unknown[]).map(image));
  fail(new Set(images.map(entry => entry.pcrTuple[0])).size === images.length && new Set(images.map(entry => entry.label)).size === images.length, "MANIFEST_DUPLICATE");
  const providers = Object.freeze((value.providers as unknown[]).map(provider));
  fail(new Set(providers.map(entry => entry.id)).size === providers.length, "MANIFEST_DUPLICATE");
  const revocations = record(value.revocations); exact(revocations, ["revokedMeasurements", "revokedBootIds", "revokedWorkerIds"]);
  return Object.freeze({format: MANIFEST_FORMAT, version: value.version, issuedAt: seconds(value.issuedAt),
    audience: Object.freeze({application: audience.application, chain: audience.chain, protocolVersion: audience.protocolVersion, trustPolicyVersion: audience.trustPolicyVersion}),
    images, providers, revocations: Object.freeze({revokedMeasurements: strings(revocations.revokedMeasurements, HEX96, 256), revokedBootIds: strings(revocations.revokedBootIds, HEX64, 256), revokedWorkerIds: strings(revocations.revokedWorkerIds, /^[a-z0-9][a-z0-9-]{1,63}$/, 256)})});
}
function signature(raw: unknown): ManifestSignature {
  const value = record(raw); exact(value, ["keyId", "algorithm", "signature"]);
  fail(typeof value.keyId === "string" && /^[a-z0-9][a-z0-9._-]{0,63}$/.test(value.keyId) && value.algorithm === MANIFEST_ALGORITHM && typeof value.signature === "string" && BASE64URL.test(value.signature));
  return Object.freeze({keyId: value.keyId, algorithm: MANIFEST_ALGORITHM, signature: value.signature});
}
/** Structural validation only. A parsed manifest is not yet trusted: {@link verifyTrustManifest} is. */
export function parseTrustManifest(raw: unknown): TrustManifest {
  const value = record(raw); fail(Object.prototype.hasOwnProperty.call(value, "signatures"), "MANIFEST_FIELDS");
  const {signatures, ...rest} = value;
  const body = parseManifestBody(rest);
  fail(Array.isArray(signatures) && signatures.length >= 1 && signatures.length <= 4);
  const parsed = Object.freeze((signatures as unknown[]).map(signature));
  fail(new Set(parsed.map(entry => entry.keyId)).size === parsed.length, "MANIFEST_DUPLICATE");
  return Object.freeze({...body, signatures: parsed});
}
/** The exact bytes a signature covers: the body (no `signatures`) in canonical JSON under the domain prefix. */
export function manifestSigningBytes(body: TrustManifestBody): Uint8Array<ArrayBuffer> {
  const {format, version, issuedAt, audience, images, providers, revocations} = body;
  return new TextEncoder().encode(`${MANIFEST_DOMAIN}\n${canonicalJson({format, version, issuedAt, audience, images, providers, revocations})}`);
}
/** The whole signed document in canonical JSON: what `/trust-manifest` serves and `/verification-config` digests. */
export const canonicalManifest = (manifest: TrustManifest): string => canonicalJson(manifest);
export async function manifestDigest(manifest: TrustManifest): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalManifest(manifest)));
  return Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, "0")).join("");
}
const base64url = {
  encode: (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
  decode: (text: string): Uint8Array<ArrayBuffer> => Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(text.length / 4) * 4, "=")), c => c.charCodeAt(0)),
};
const importOwnerKey = (key: OwnerKey) => crypto.subtle.importKey("jwk", {...key.jwk, ext: true}, {name: "ECDSA", namedCurve: "P-256"}, false, ["verify"]);
export function ownerKeyOf(raw: unknown): OwnerKey {
  const value = record(raw); exact(value, ["keyId", "role", "jwk"]);
  fail(typeof value.keyId === "string" && /^[a-z0-9][a-z0-9._-]{0,63}$/.test(value.keyId) && (value.role === "active" || value.role === "standby"));
  const jwk = record(value.jwk); exact(jwk, ["kty", "crv", "x", "y"]);
  fail(jwk.kty === "EC" && jwk.crv === "P-256" && typeof jwk.x === "string" && /^[A-Za-z0-9_-]{43}$/.test(jwk.x) && typeof jwk.y === "string" && /^[A-Za-z0-9_-]{43}$/.test(jwk.y));
  return Object.freeze({keyId: value.keyId, role: value.role, jwk: Object.freeze({kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y})});
}

export type VerifyOptions = Readonly<{
  /** The pinned owner keys, active and standby. Any one valid signature by one of them admits the manifest. */
  keys: readonly OwnerKey[];
  /** The audience this client was built for. A manifest for another application, chain or protocol is refused. */
  audience: ManifestAudience;
  /** The highest version this client has accepted before; a manifest at or below it is a rollback and refused. */
  lastAcceptedVersion?: number;
}>;
export type VerifiedManifest = Readonly<{manifest: TrustManifest; signedBy: readonly string[]; digest: string}>;
/**
 * Parse, then refuse in this order: audience, rollback, unknown key, bad signature, no valid signature. A signature by
 * a key not in `keys` is ignored only when another listed key signs validly; a manifest whose every signature is unknown
 * is refused as `MANIFEST_KEY_UNKNOWN`, so a rotated-away key is visible rather than silently tolerated.
 */
export async function verifyTrustManifest(raw: unknown, options: VerifyOptions): Promise<VerifiedManifest> {
  const manifest = parseTrustManifest(raw);
  const a = manifest.audience, b = options.audience;
  fail(a.application === b.application && a.chain === b.chain && a.protocolVersion === b.protocolVersion && a.trustPolicyVersion === b.trustPolicyVersion, "MANIFEST_AUDIENCE");
  fail(options.lastAcceptedVersion === undefined || manifest.version > options.lastAcceptedVersion, "MANIFEST_ROLLBACK");
  fail(options.keys.length >= 1 && options.keys.length <= 4 && new Set(options.keys.map(key => key.keyId)).size === options.keys.length, "MANIFEST_KEYS");
  const bytes = manifestSigningBytes(manifest);
  const signedBy: string[] = []; let known = 0;
  for (const entry of manifest.signatures) {
    const key = options.keys.find(candidate => candidate.keyId === entry.keyId);
    if (!key) continue;
    known++;
    const ok = await crypto.subtle.verify({name: "ECDSA", hash: "SHA-256"}, await importOwnerKey(key), base64url.decode(entry.signature), bytes);
    fail(ok, "MANIFEST_SIGNATURE");
    signedBy.push(key.keyId);
  }
  fail(known > 0, "MANIFEST_KEY_UNKNOWN");
  fail(signedBy.length > 0, "MANIFEST_UNSIGNED");
  return Object.freeze({manifest, signedBy: Object.freeze(signedBy), digest: await manifestDigest(manifest)});
}
/**
 * Sign a body with a WebCrypto private key. The library half of the signing tool: tests use it with a throwaway key,
 * and track A's `sign-manifest.mjs` calls it with the owner's key file. It never prints or exports a key.
 */
/** A WebCrypto private key as `crypto.subtle.sign` takes it; spelled this way so a server-only typecheck without the DOM lib accepts it. */
export type ManifestSigningKey = Parameters<typeof crypto.subtle.sign>[1];
export async function signTrustManifest(body: TrustManifestBody, signer: {keyId: string; privateKey: ManifestSigningKey}, existing: readonly ManifestSignature[] = []): Promise<TrustManifest> {
  const parsed = parseManifestBody(body);
  fail(/^[a-z0-9][a-z0-9._-]{0,63}$/.test(signer.keyId) && !existing.some(entry => entry.keyId === signer.keyId), "MANIFEST_DUPLICATE");
  const raw = new Uint8Array(await crypto.subtle.sign({name: "ECDSA", hash: "SHA-256"}, signer.privateKey, manifestSigningBytes(parsed)));
  fail(raw.byteLength === 64, "MANIFEST_SIGNATURE");
  return parseTrustManifest({...parsed, signatures: [...existing, {keyId: signer.keyId, algorithm: MANIFEST_ALGORITHM, signature: base64url.encode(raw)}]});
}
/** Whether an image entry covers a receipt verified at `verifiedAt` (unix seconds). */
export const imageAdmittedAt = (entry: ManifestImage, verifiedAt: number) => verifiedAt >= entry.admittedFrom && (entry.admittedUntil === undefined || verifiedAt <= entry.admittedUntil);
