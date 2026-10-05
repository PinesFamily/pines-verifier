// Finite plan-only consent and saved display.
// Display and consent are restricted to the public plan vocabulary. Authority
// still comes from the exact compiled schema/profile and a saved API record.
const services = Object.freeze({
  'pines.chatgpt.tee.native': 'chatgpt',
  'pines.claude.tee.native': 'claude',
  'pines.grok.tee.native': 'grok',
});
const labels = Object.freeze({
  chatgpt: Object.freeze({plus: 'Plus', pro: 'Pro', prolite: 'Pro Lite', promax: 'Pro Max'}),
  claude: Object.freeze({pro: 'Pro', max: 'Max'}),
  grok: Object.freeze({SUBSCRIPTION_TIER_X_PREMIUM_PLUS: 'X Premium+', SUBSCRIPTION_TIER_SUPER_GROK_LITE: 'SuperGrok Lite',
    SUBSCRIPTION_TIER_GROK_PRO: 'SuperGrok', SUBSCRIPTION_TIER_SUPER_GROK_PLUS: 'SuperGrok Plus', SUBSCRIPTION_TIER_SUPER_GROK_PRO: 'SuperGrok Pro'}),
});
export const nativeServiceOf = schemaId => Object.hasOwn(services, schemaId) ? services[schemaId] : null;
export function nativePlanValues(reference) {
  const service = nativeServiceOf(reference?.schemaId);
  if (!service || !(service === 'chatgpt' ? [3, 4] : [1]).includes(reference.version)) return [];
  return Object.keys(labels[service]).filter(plan => !(service === 'chatgpt' && reference.version === 3 && plan === 'promax'));
}
export function nativePlanLabel(reference, plan) {
  return typeof plan === 'string' && nativePlanValues(reference).includes(plan) ? labels[nativeServiceOf(reference.schemaId)][plan] : null;
}
