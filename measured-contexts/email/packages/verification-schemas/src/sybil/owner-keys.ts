/**
 * The two owner public keys every client pins for `pines-trust-manifest-v1` (owner decision S4: clients trust the
 * admitted set because the owner signed it; two keys, active and standby, so a rotation is a manifest signed by the
 * standby rather than a release). This is the ONE copy the identity, the web and the extension import; nothing else
 * pins an owner key.
 *
 * ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 * │ PRODUCTION KEYS (owner custody step done 2026-10-20). The private halves exist only where the owner keeps     │
 * │ them, encrypted, outside every repository; nothing in this tree can sign a manifest these pins accept.        │
 * │ Fingerprints: active sha256:38dab6c2b2e8c1657fdb5a7c7e65f24d73aac16bf88852056637542bbfdad7d4,                  │
 * │ standby sha256:7b6258db6053c0855604a2d5337c8c73fb1087a4e08793bb600a3ab82b4630a7.                              │
 * │ The TEST pair the local stack and the suites sign with lives in                                                │
 * │ `tools/tee-native/test/fixtures/owner-test-keys.json` and is injected by the tests; a release never accepts it. │
 * │ A rotation is a manifest signed by the standby, then a new standby here; a rotation past both keys is a         │
 * │ release (the pins ride the extension, the web and the identity).                                               │
 * └──────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
 */
import {ownerKeyOf, type OwnerKey} from "./manifest.ts";

/** `"production"` since the owner's custody step (2026-10-20); a release refuses `"test"`. */
export const OWNER_KEYS_PROVENANCE: "test" | "production" = "production";

export const OWNER_KEYS: readonly OwnerKey[] = Object.freeze([
  ownerKeyOf({keyId: "pines-owner-active-20261020", role: "active",
    jwk: {kty: "EC", crv: "P-256", x: "yP-IQFiBgoPMv4rpeX1ebne-di8atQhXiTeGv9klR5g", y: "CfHXpoX8B6UCD-5x2xXlJ-P1mxfb-TDECHqSF03pWTg"}}),
  ownerKeyOf({keyId: "pines-owner-standby-20261020", role: "standby",
    jwk: {kty: "EC", crv: "P-256", x: "4JeRLYsjnx9vGavukjBd2TVegIi7nxfmRQelrTahBNU", y: "3JIhwrU7KGnl5Dd9lxZsaWILn_uQZOKrazebmcVFRQY"}}),
]);

/** Exactly one active and one standby key, distinct ids and distinct points: the shape the custody step must keep. */
export function checkOwnerKeys(keys: readonly OwnerKey[] = OWNER_KEYS): void {
  const roles = keys.map(key => key.role).sort();
  if (keys.length !== 2 || roles[0] !== "active" || roles[1] !== "standby") throw new Error("OWNER_KEYS_ROLES");
  if (new Set(keys.map(key => key.keyId)).size !== 2 || new Set(keys.map(key => `${key.jwk.x}.${key.jwk.y}`)).size !== 2) throw new Error("OWNER_KEYS_DUPLICATE");
}
checkOwnerKeys();

/**
 * An INJECTED key set for a local stack or a test suite: the public pins of `tools/tee-native/test/fixtures/owner-test-keys.json`
 * (`{keys: [{keyId, role, jwk}]}`), parsed with the same shape rule as the pins. Every consumer that takes one does so
 * only where a public build or a public identity cannot reach it; the pinned `OWNER_KEYS` are never replaced in place.
 */
export function testOwnerKeysFrom(fixture: unknown): readonly OwnerKey[] {
  if (!fixture || typeof fixture !== "object" || !Array.isArray((fixture as {keys?: unknown}).keys)) throw new Error("OWNER_TEST_KEYS");
  const keys = Object.freeze(((fixture as {keys: unknown[]}).keys).map(entry => {
    const value = entry as {keyId?: unknown; role?: unknown; jwk?: {kty?: unknown; crv?: unknown; x?: unknown; y?: unknown}};
    return ownerKeyOf({keyId: value.keyId, role: value.role, jwk: {kty: value.jwk?.kty, crv: value.jwk?.crv, x: value.jwk?.x, y: value.jwk?.y}});
  }));
  checkOwnerKeys(keys);
  for (const key of keys) if (pinnedOwnerKeyOf(key.jwk)) throw new Error("OWNER_TEST_KEYS_ARE_PINS");
  return keys;
}
/** Whether a public JWK is one of the pinned keys (the signing tool refuses a key file that is not). */
export const pinnedOwnerKeyOf = (jwk: {x: string; y: string}, keys: readonly OwnerKey[] = OWNER_KEYS): OwnerKey | undefined =>
  keys.find(key => key.jwk.x === jwk.x && key.jwk.y === jwk.y);
