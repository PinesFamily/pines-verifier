// Admission failures are UI information, never proof evidence. Keep bridge input bounded.
export const admissionErrors = new Set(['RATE_LIMITED', 'VERIFICATION_BUDGET_EXHAUSTED', 'VERIFICATION_UNAVAILABLE']);
export function retryTime(value, now = Date.now()) {
  return Number.isSafeInteger(value) && value > 0 && value <= now + 3_600_000 ? value : null;
}
export function retryCopy(state, now = Date.now()) {
  if (state.error !== 'RATE_LIMITED') return null;
  const at = retryTime(state.retryAt, now);
  if (at === null) return {title: 'Too many verification attempts', description: 'Verification attempts are limited over a rolling hour. Cancelled and failed attempts count too. Pines did not provide an exact retry time; wait up to an hour before trying again.', countdown: ''};
  if (at <= now) return {title: 'You can try again now', description: 'Return to Pines and click Verify to try again. Availability will be checked again.', countdown: ''};
  const seconds = Math.ceil((at - now) / 1000);
  const time = new Date(at).toLocaleTimeString([], {hour: 'numeric', minute: '2-digit', second: '2-digit', timeZoneName: 'short'});
  return {title: 'Too many verification attempts', description: `Try again at ${time}. Cancelled and failed attempts count toward the hourly limit. Other verification activity may extend the wait.`,
    countdown: `Try again in ${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`};
}
