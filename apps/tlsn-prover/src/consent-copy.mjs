// What the panel says is shared, keyed on the build's signed disclosure policy (config.tee.disclosurePolicy, which
// tools/tee-native/client.mjs binds to every ticket). Import-free: the panel loads it unbundled.
// The client design record (its Consent section) holds both texts; a third policy has no copy and fails closed.
const AUTHORIZE = 'Pines receives your verified plan and an account pseudonym. Verification starts automatically and covers only the wallet below.';
const REQUEST = 'Outgoing credential header values, including Authorization and the complete Cookie value, stay hidden in the request proof.';
// e-mail possession specification §8: the e-mail challenge's consent sentence, per class. Only a schema that discloses the
// e-mail fact (`pines_email`, the sybil-facts generation of the private-headers class, multi-exchange protocol §2.6) adds
// it after AUTHORIZE; every other schema keeps its text byte-for-byte. A class without a sentence has no such schema.
const EMAIL = "If this check includes your account's e-mail address, Pines receives it only to send you a one-time code that confirms this verification, and does not keep it.";
const copy = Object.freeze({
  'full-response-v1': Object.freeze({
    sharing: `Your complete account response, including all response headers and cookies, is encrypted to and checked inside an AWS TEE. It may contain personal data or credentials returned by the provider. ${REQUEST} ${AUTHORIZE}`,
    response: ['Account response', 'Encrypted to TEE'],
    details: ['Account details', 'TEE only'],
    headers: null,
    email: null,
  }),
  // Plan D8/D9: every response header value is hidden except the framing; the body is checked inside the TEE and
  // can carry anything the provider returns. Never say a returned credential in the body is hidden.
  'private-headers-gzip-v1': Object.freeze({
    sharing: `Your account response body is encrypted to and checked inside an AWS TEE. It may contain personal data or credentials returned by the provider. Response header values, including any cookies the provider sets, stay hidden from everyone, including the TEE; it sees only header names and the content type, length and encoding. ${REQUEST} ${AUTHORIZE}`,
    response: ['Account response body', 'Encrypted to TEE'],
    details: ['Account details', 'TEE only'],
    headers: ['Response header values', 'Hidden'],
    email: EMAIL,
  }),
});
// The sybil-facts generation's class (multi-exchange protocol §2.6, owner D4): the complete response is checked inside the
// TEE exactly as under full-response-v1 — the same text, word for word — and its schemas disclose the e-mail fact.
const classes = Object.freeze({...copy, 'facts-complete-v1': Object.freeze({...copy['full-response-v1'], email: EMAIL}),
  'grok-email-complete-v1': Object.freeze({...copy['full-response-v1'], email: EMAIL,
    sharing: `${copy['full-response-v1'].sharing} Your Cloudflare clearance and exact browser user agent also stay hidden in the request proof.`}),
  'grok-clearance-private-v1': Object.freeze({...copy['private-headers-gzip-v1'], email: null,
    sharing: `${copy['private-headers-gzip-v1'].sharing} Your Cloudflare clearance and exact browser user agent also stay hidden in the request proof.`})});
// `discloses.email`: the run's schema discloses the e-mail fact (`disclosesEmail`). The class's text then ends with its
// e-mail sentence; a class without one refuses rather than show copy that omits it.
export function teeCopy(policyId, discloses = {}) {
  if (typeof policyId !== 'string' || !Object.hasOwn(classes, policyId)) throw Error('DISCLOSURE_POLICY');
  const entry = classes[policyId];
  if (discloses.email !== true) return entry;
  if (!entry.email) throw Error('DISCLOSURE_POLICY_EMAIL');
  return Object.freeze({...entry, sharing: `${entry.sharing} ${entry.email}`});
}
/** Whether a bundled verification schema (its first request or any later exchange) discloses `pines_email`. */
export function disclosesEmail(schema) {
  const fields = [...(schema?.fields ?? []), ...(schema?.exchanges ?? []).flatMap(exchange => exchange?.fields ?? [])];
  return fields.some(field => field?.id === 'pines_email');
}
