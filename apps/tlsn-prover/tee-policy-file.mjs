export function teePolicyFile(disclosurePolicyId) {
  if (disclosurePolicyId === 'full-response-v1') return 'tools/tee-native/hardware/policy.json';
  if (disclosurePolicyId === 'private-headers-gzip-v1') return 'tools/tee-native/hardware/policy.private-headers-public.json';
  throw Error('TEE_DISCLOSURE_POLICY');
}
