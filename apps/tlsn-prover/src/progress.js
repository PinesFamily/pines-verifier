import {accountBindingMessage} from './binding-error.mjs';
import {localFailureCode} from './failure-code.js';
import {nativeServiceOf} from './tee-provider.mjs';
// Display copy per provider schema. A state without a known provider schema reads
// as ChatGPT, the original pilot; this never gates anything.
const providers = Object.freeze({
  'pines.chatgpt.plan': Object.freeze({name: 'ChatGPT', host: 'chatgpt.com', request: 'a usage request', data: 'usage', identifier: 'account identifier'}),
  'pines.claude.plan': Object.freeze({name: 'Claude', host: 'claude.ai', request: 'an account request', data: 'plan', identifier: 'Claude organization ID'}),
  'pines.grok.plan': Object.freeze({name: 'Grok', host: 'grok.com', request: 'an account request', data: 'subscription', identifier: 'xAI user ID'}),
});
const copySchema = schemaId => nativeServiceOf(schemaId) ? `pines.${nativeServiceOf(schemaId)}.plan` : schemaId;
export const providerOf = schemaId => providers[Object.hasOwn(providers, copySchema(schemaId)) ? copySchema(schemaId) : 'pines.chatgpt.plan'];
// The review rows: the values the verifier judges (the worker's `preview.fields`, from the schema's own selector),
// never a panel's own reading of the raw JSON. Grok lists every subscription, active or not, in one response, and
// its first entry can be an inactive plan the verifier will skip.
const words = value => value.toLowerCase().split('_').filter(Boolean).map(word => word === 'x' ? 'X' : word[0].toUpperCase() + word.slice(1)).join(' ');
// grok.com's names, not its enum's words: `GROK_PRO` is the plan it sells as SuperGrok. X's plan is Premium+ as the app says it.
const grokPlans = Object.freeze({SUBSCRIPTION_TIER_X_PREMIUM_PLUS: 'X Premium+', SUBSCRIPTION_TIER_SUPER_GROK_LITE: 'SuperGrok Lite',
  SUBSCRIPTION_TIER_GROK_PRO: 'SuperGrok', SUBSCRIPTION_TIER_SUPER_GROK_PLUS: 'SuperGrok Plus', SUBSCRIPTION_TIER_SUPER_GROK_PRO: 'SuperGrok Heavy'});
const chatgptPlans = Object.freeze({plus: 'Plus', pro: 'Pro', prolite: 'Pro Lite', promax: 'Pro Max'});
const reviewFields = Object.freeze({
  plan_type: {label: 'Plan', format: value => chatgptPlans[value] ?? value},
  rate_limit_tier: {label: 'Plan', format: value => words(value.replace(/^default_claude_/, ''))},
  tier: {label: 'Plan', format: value => Object.hasOwn(grokPlans, value) ? grokPlans[value] : words(value.replace(/^SUBSCRIPTION_TIER_/, ''))},
  status: {label: 'Status', format: value => words(value.replace(/^SUBSCRIPTION_STATUS_/, ''))},
  user_id: {identity: true}, organization_uuid: {identity: true}, xai_user_id: {identity: true},
});
// Plan first, then status, then the account ID, whatever order the schema lists its fields in.
const reviewOrder = rule => rule.identity ? 2 : rule.label === 'Status' ? 1 : 0;
export function reviewRowsOf(schemaId, fields) {
  if (!fields || typeof fields !== 'object') return [];
  return Object.entries(fields).flatMap(([id, value]) => {
    const rule = Object.hasOwn(reviewFields, id) ? reviewFields[id] : undefined;
    if (!rule || typeof value !== 'string') return [];
    return [{rule, label: rule.identity ? capitalize(providerOf(schemaId).identifier) : rule.label, value: rule.identity ? value : rule.format(value)}];
  }).sort((a, b) => reviewOrder(a.rule) - reviewOrder(b.rule)).map(({label, value}) => ({label, value}));
}
const capitalize = value => /^[a-z][A-Z]/.test(value) ? value : value[0].toUpperCase() + value.slice(1);
// The welcome screen's three steps, short enough for a task row with its detail beside it.
export const stepsFor = schemaId => [`Open ${providerOf(schemaId).name}`, 'Review what’s shared', 'Get verified'];
export const steps = stepsFor();

const helpFor = ({name, host, request}) => Object.freeze({
  CONSENT_REQUIRED: 'This verification could not start. Start again from Pines.',
  PREPARATION_EXPIRED: 'Preparation expired. Return to Pines and start again.',
  RATE_LIMITED: 'Too many verification attempts. Wait for the retry time shown above.',
  VERIFICATION_BUDGET_EXHAUSTED: 'This wallet has no verifications available in its rolling 30-day allowance. Return to Pines to check your saved verifications.',
  HARDWARE_PROFILE_UNQUALIFIED: 'Private verification is not ready. Return to Pines and retry after the service is available.',
  ADMISSION_REFUSED: 'The verification start window expired or the protected verifier is busy. Return to Pines and try again.',
  API_REFUSED: 'Pines has not confirmed a saved result. Return to Pines to check before starting another verification.',
  CHANNEL_REFUSED: 'The protected connection stopped. Return to Pines to check your saved result or retry.',
  ENCLAVE_TERMINATED: 'The protected verifier ended this attempt without saving a verification. Return to Pines and retry; share the error code if it repeats.',
  TEE_ATTESTATION_INIT_FAILED: 'Chrome could not load the enclave security check. Reload the Pines extension and retry.',
  TEE_CHANNEL_FAILED: 'Chrome could not establish the protected connection. Check both localhost forwards and use Chrome 141 or newer, then retry.',
  TEE_NATIVE_INIT_FAILED: 'Chrome could not start the proof engine. Close unused tabs, check that about 4 GiB of memory is free, and retry.',
  TEE_NATIVE_CONFIG_FAILED: 'The proof engine could not initialize this release. Reload the Pines extension; share the error code if it repeats.',
  TEE_NATIVE_SETUP_FAILED: 'The proof engine could not connect to the protected verifier. Return to Pines and retry; share the error code if it repeats.',
  TEE_PROVIDER_REQUEST_FAILED: `The protected request to ${name} could not finish. Return to Pines and retry; share the error code if it repeats.`,
  EXCHANGES_UNSUPPORTED: `This ${name} check needs a newer Pines Verifier. Update the extension, then verify again.`,
  TEE_DISCLOSURE_FAILED: `${name} answered in a way this version of Pines Verifier doesn’t recognise, so it stopped before sharing anything from your account. Check that ${name} is signed in to the account with your paid plan, then try again. If it keeps happening, send us the error code.`,
  TEE_PROOF_FAILED: 'The proof could not be completed or checked. Return to Pines to check the saved result before retrying.',
  ISOLATION_REQUIRED: 'Chrome could not isolate the proof engine. Use desktop Chrome 141 or newer, reload the Pines extension, and retry.',
  INELIGIBLE_PLAN: name === 'ChatGPT' ? 'Your ChatGPT plan can’t be verified. Pines accepts ChatGPT Plus, Pro, Pro Lite and Pro Max; Free and Go don’t qualify. Nothing from your account was shared.' : name === 'Claude'
    ? 'This release verifies paid personal Claude Pro and Max plans. Free, Team and Enterprise plans cannot be verified.'
    : 'This release verifies active SuperGrok and X Premium+ subscriptions. Free, X Basic and X Premium plans cannot be verified.',
  PROVIDER_INVENTORY_UNQUALIFIED: 'This release cannot safely verify the provider response. Update Pines Verifier before retrying.',
  WORKER_FAILED: 'Chrome stopped the proof worker. Close unused tabs, reload the Pines extension, and retry.',
  PROOF_FAILED: 'The extension could not prepare the verification. Reload Pines Verifier and retry; share the error code if it repeats.',
  UNQUALIFIED_FIELD: `${name} returned a new response shape that this release cannot verify. Update Pines Verifier or try again later.`,
  UNQUALIFIED_HEADER: `${name} returned a new response shape that this release cannot verify. Update Pines Verifier or try again later.`,
  VERIFICATION_UNAVAILABLE: 'Pines could not start verification. Return to Pines and try again shortly.',
  PROVIDER_OPEN_FAILED: `Chrome could not open ${name}. Return to Pines and click Verify again. If it repeats, reload the Pines extension in chrome://extensions.`,
  CAPTURE_UNAVAILABLE: `The extension could not read the ${name} tab. Check that the Pines extension has access to ${host}, then retry Verify from Pines.`,
  CAPTURE_TIMEOUT: `${name} did not return subscription information in time. Check that you are signed in, then retry from Pines.`,
  CAPTURE_NAVIGATED: `The ${name} page reloaded or changed during verification. Finish signing in, then return to Pines and start again.`,
  CAPTURE_OWNER_CHANGED: 'A browser tab changed during capture. Return to Pines and start verification again.',
  CAPTURE_TAB_CLOSED: `The ${name} tab closed before capture finished. Start verification again from Pines.`,
  CAPTURE_CANCELLED: 'Capture was cancelled. Return to Pines and start verification again.',
  CAPTURE_BUSY: `Capture is already waiting for ${request}. Keep the ${name} tab open.`,
  TICKET_EXPIRED: 'The start window expired. Start a new verification from Pines.',
  PROVIDER_LEFT: 'The provider tab changed or closed. Return to Pines and start again.',
  PROVIDER_SIGN_IN_REQUIRED: `Sign in to ${name} in the new tab, then start verification again from Pines.`,
  PROVIDER_HTTP_401: `Sign in to ${name} again, then restart verification from Pines.`,
  PROVIDER_HTTP_403: `${name} refused the verification request. Try again later.`,
  PROVIDER_CHALLENGE: `${name} requested a browser check. Return to Pines and verify again to try available assistance.`,
  ASSISTANCE_PROXY_UNSUPPORTED: 'Your current proxy settings cannot be used for assistance. They were kept. Return to Pines to use the usual verification.',
  ASSISTANCE_PERMISSION_DENIED: 'Assistance was declined. Return to Pines to use the usual verification.',
  ASSISTANCE_UNAVAILABLE: 'Grok assistance is unavailable. Return to Pines to use the usual verification.',
  ASSISTANCE_CLEARANCE_UNPROVEN: 'Grok did not issue a fresh browser check for this connection. Assistance stopped and your routing was restored.',
  ASSISTANCE_ENDED: 'Grok assistance ended. Your routing was restored. Return to Pines to check the saved result.',
  ASSISTANCE_RESTORATION_FAILED: 'Chrome could not confirm that routing was restored. Keep this extension enabled while it retries, or check Chrome’s proxy settings.',
  PROVIDER_HTTP_429: `${name} is limiting requests. Try again later.`,
  PROVIDER_RESPONSE_UNSUPPORTED: `${name} returned an unsupported response. Return to Pines and try again.`,
  OPEN_ONE_PROVIDER_TAB: 'Keep exactly one provider tab open in this window, then try again.',
  PROOF_TIMEOUT: 'The verification window expired. Start a new verification from Pines.',
  SESSION_POLICY_UNSUPPORTED: 'This verification needs a newer Pines Verifier. Update the extension, then start again.',
  SESSION_POLICY_INVALID: 'Pines returned an invalid session time limit. Start a new verification.',
  WORKER_RESTARTED: 'The proof worker stopped. Pines can still check for a saved receipt. Return to Pines to retry.',
  EXTENSION_STOPPED: 'The extension stopped before verification finished. Return to Pines to check for a saved receipt, then retry if none appears.',
  WORKER_UNAVAILABLE: 'The verification worker could not start. Reload the Pines extension and retry Verify from Pines.',
  EXTENSION_UNAVAILABLE: 'The extension could not finish this step. Reload the Pines extension in chrome://extensions, then retry Verify from Pines.',
  RECIPIENT_CHANGED: 'Your wallet changed. Start again with your current wallet.',
  OWNER_LEFT: 'The original Pines page changed or closed. Open Pines to check your saved result.',
  VERIFIER_UNAVAILABLE: 'The verification service is unavailable. Return to Pines and try again shortly.',
  VERIFIER_VERSION_MISMATCH: 'This extension and the verifier need matching releases. Install the latest Pines extension and retry.',
  PANEL_GESTURE_REQUIRED: 'Click Verify in Pines again to open the verification panel.',
  PROVIDER_PERMISSION_DENIED: `Access to ${host} was declined. Verification was cancelled. Start again from Pines when you’re ready.`,
  CAPTURE_PERMISSION_LOST: `Provider access was removed. Return to Pines and start verification again.`,
  PERMISSION_REVOKED: `The extension lost a required permission. Restore its access to ${name} and retry Verify from Pines.`,
  // private-headers-gzip-v1 refusals. Each stops before any account fact reaches Pines.
  RESPONSE_ENCODING_UNSUPPORTED: `${name} answered in a format this release does not verify. Try again later; share the error code if it repeats.`,
  RESPONSE_REVEAL_LIMIT: `${name} returned more account data than this release verifies. Share the error code so compatibility can be checked.`,
  RESPONSE_ENCODED_INVALID: `${name} returned a compressed response that could not be checked. Try again later; share the error code if it repeats.`,
  CLAUDE_ORG_UNAVAILABLE: 'Claude did not open an organization in the new tab. Sign in to your paid personal Claude account there, then start again from Pines.',
  CLAUDE_ORG_MISMATCH: 'Claude answered for a different organization than the one requested. Start again from Pines.',
  CLAUDE_ORG_INELIGIBLE: 'The Claude organization open in the new tab is not a paid personal Pro or Max plan. Switch claude.ai to your personal paid organization, then start again from Pines.',
});
const help = Object.freeze(Object.fromEntries(Object.entries(providers).map(([schemaId, provider]) => [schemaId, helpFor(provider)])));
export function failureHelp(code, linkedWallet, schemaId) {
  const messages = help[Object.hasOwn(help, copySchema(schemaId)) ? copySchema(schemaId) : 'pines.chatgpt.plan'];
  return accountBindingMessage({error: code, linkedWallet}) ?? (Object.hasOwn(messages, code) ? messages[code] : 'Something went wrong. Try again from Pines.');
}

// A diagnostic is a member of a closed vocabulary, never an exception message
// or arbitrary uppercase string supplied by a page or provider.
export function failureDiagnostic(state) {
  if (state?.phase !== 'failed' || typeof state.error !== 'string') return '';
  const code = localFailureCode(state.error) || (Object.hasOwn(help['pines.chatgpt.plan'], state.error) ? state.error : null);
  return code ? `Error code: ${code}` : '';
}

// What the panel says about a run: which of the three steps it is on, the one line under that step while it runs,
// and, once it has stopped or finished, a heading and a sentence of its own.
export function progressOf(state, now = Date.now()) {
  const complete = state.phase === 'completed' && state.receiptVerified === true;
  const stopped = ['failed', 'cancelled'].includes(state.phase);
  const receipt = receiptProgressOf(state, now);
  const recovery = receipt.recovery;
  const {name} = providerOf(state.schema?.schemaId);
  const bound = state.error === 'PROVIDER_ACCOUNT_BOUND';
  let step = 0;
  if (['awaiting-disclosure', 'awaiting-consent', 'ready'].includes(state.phase)) step = 1;
  if (state.upfrontConsent && state.preparing === false && !stopped) step = 2;
  if (state.phase === 'proving' || state.phase === 'completed') step = 2;
  if (complete) step = 3;
  const detail = step === 0
    ? state.phase === 'awaiting-permission' ? `Allow access to ${providerOf(state.schema?.schemaId).host} using the button below. Chrome remembers this choice until you remove access in the extension settings.`
      : state.phase === 'requesting' ? `Reading your plan. Keep the ${name} tab open.`
      : state.providerStarted ? `Sign in if ${name} asks. Keep its tab open.` : `Opening ${name} in a new tab…`
    : step === 1 ? state.upfrontConsent ? 'Starting your verification…' : 'Check it below, then share.'
    : state.phase === 'proving' ? 'Checking the proof…'
    : recovery ? 'Pines hasn’t confirmed it yet.' : 'Saving with Pines…';
  const title = bound ? 'Account already linked'
    : stopped ? state.phase === 'cancelled' ? 'Verification cancelled' : state.error === 'INELIGIBLE_PLAN' ? 'Plan not eligible' : 'Couldn’t verify'
    : complete ? 'You’re verified'
    : recovery ? 'Check your result in Pines'
    : `${name} verification`;
  const linked = typeof state.linkedWallet === 'string' ? `${state.linkedWallet.slice(0, 6)}…${state.linkedWallet.slice(-4)}` : 'another wallet';
  const description = bound ? `This ${name} account is linked to ${linked}. Connect that wallet to continue.`
    : stopped ? state.phase === 'cancelled' && !state.error ? 'Start again from Pines when you’re ready.' : failureHelp(state.error, state.linkedWallet, state.schema?.schemaId)
    : complete ? `Your ${name} verification is saved.`
    : recovery ? 'The proof is done, but Pines hasn’t confirmed it here. Return to Pines to check.'
    : '';
  return {step, complete, stopped, recovery, bound, detail, title, description};
}

// The server exposes a pending/verified result, not a percentage. Keep the bar
// indeterminate until the owner page validates its authenticated API receipt.
export function receiptProgressOf(state, now = Date.now()) {
  const complete = state.phase === 'completed' && state.receiptVerified === true;
  const seconds = Math.max(0, Math.floor(((complete ? state.receiptVerifiedAt : now) - (state.phaseStartedAt ?? now)) / 1000)) || 0;
  const recovery = state.receiptRejected === true || state.phase === 'completed' && !complete && (state.receiptWaitStopped === true || seconds >= 30);
  return {
    visible: state.phase === 'completed', complete, seconds, recovery,
    label: complete ? 'Saved and confirmed' : recovery ? 'Confirmation delayed' : 'Waiting for Pines confirmation',
    detail: complete ? `Confirmed in ${seconds}s` : recovery ? 'Use Return to Pines below. Pines will check for your existing result when you retry Verify.' : `${seconds}s waiting · Checking your saved verification…`,
  };
}
