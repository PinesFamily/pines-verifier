// Fixed provider origins, never a pattern supplied by the website or a message.
// Access is granted before the provider tab is opened or captured.
const origins = Object.freeze({
  'pines.chatgpt.plan': 'https://chatgpt.com/*',
  'pines.claude.plan': 'https://claude.ai/*',
  'pines.grok.plan': 'https://grok.com/*',
});
export const providerPermission = schemaId => Object.hasOwn(origins, schemaId) ? origins[schemaId] : null;

export async function checkProviderPermission(browser, job) {
  const origin = providerPermission(job.schema?.schemaId);
  if (!origin) return true; // Public/private synthetic fixtures keep their existing permissions.
  const granted = await browser.permissions.contains({origins: [origin]});
  // Once granted, losing access is a failure, never another automatic prompt.
  if (!granted && job.permissionGranted) throw Error('PERMISSION_REVOKED');
  job.permissionPending = !granted;
  if (granted) job.permissionGranted = true;
  return granted;
}
