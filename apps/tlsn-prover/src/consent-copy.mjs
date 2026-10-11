// What the panel says is shared, keyed on the build's signed disclosure policy (config.tee.disclosurePolicy, which
// tools/tee-native/client.mjs binds to every ticket). Import-free: the panel loads it unbundled.
// The client design record (its Consent section) holds both texts; a third policy has no copy and fails closed.
const AUTHORIZE = 'Pines receives your verified plan and an account pseudonym. Agree and verify authorizes this one verification for the wallet below.';
const REQUEST = 'Outgoing credential header values, including Authorization and the complete Cookie value, stay hidden in the request proof.';
const copy = Object.freeze({
  'full-response-v1': Object.freeze({
    sharing: `Your complete account response, including all response headers and cookies, is encrypted to and checked inside an AWS TEE. It may contain personal data or credentials returned by the provider. ${REQUEST} ${AUTHORIZE}`,
    response: ['Account response', 'Encrypted to TEE'],
    details: ['Account details', 'TEE only'],
    headers: null,
  }),
  // Plan D8/D9: every response header value is hidden except the framing; the body is checked inside the TEE and
  // can carry anything the provider returns. Never say a returned credential in the body is hidden.
  'private-headers-gzip-v1': Object.freeze({
    sharing: `Your account response body is encrypted to and checked inside an AWS TEE. It may contain personal data or credentials returned by the provider. Response header values, including any cookies the provider sets, stay hidden from everyone, including the TEE; it sees only header names and the content type, length and encoding. ${REQUEST} ${AUTHORIZE}`,
    response: ['Account response body', 'Encrypted to TEE'],
    details: ['Account details', 'TEE only'],
    headers: ['Response header values', 'Hidden'],
  }),
});
export function teeCopy(policyId) {
  if (typeof policyId !== 'string' || !Object.hasOwn(copy, policyId)) throw Error('DISCLOSURE_POLICY');
  return copy[policyId];
}
