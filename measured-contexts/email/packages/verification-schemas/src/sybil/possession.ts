/**
 * The e-mail challenge's public shape (track C, e-mail possession specification; owner S1 in identity policy specification §1): what
 * the identity publishes about one attempt's challenge, the constants both sides agree on, and the parser the app reads
 * it with. Nothing here is or names an address: the identity holds the address in memory for the challenge only, and
 * neither this view, nor a row, nor a log carries it.
 *
 * The challenge sits at the completion seam's **last** position (`evaluate.ts`): the enclave's receipt has arrived, every
 * other rule has passed, and the receipt is held, not saved, until the six-digit code sent to the provider account's
 * e-mail is entered. A stolen provider session alone therefore cannot complete a verification, and the mailbox owner is
 * told, with a link that blocks the attempt.
 */
export const EMAIL_CHALLENGE_FORMAT = "pines-email-challenge-v1";
export const EMAIL_CODE_DIGITS = 6;
/** A code is good for ten minutes, never past the attempt's own result deadline (the receipt must still be savable). */
export const EMAIL_CODE_TTL_MS = 10 * 60_000;
/** Codes per attempt: the first and two resends. */
export const EMAIL_SENDS_PER_ATTEMPT = 3;
export const EMAIL_RESEND_COOLDOWN_MS = 60_000;
/** Wrong entries per attempt, across every code it was sent. The fifth wrong entry locks the attempt. */
export const EMAIL_TRIES_PER_ATTEMPT = 5;
/** Codes per address, counted under a keyed hash that rotates with the window (never the address itself). */
export const EMAIL_SENDS_PER_ADDRESS_HOUR = 5;
export const EMAIL_SENDS_PER_ADDRESS_DAY = 10;
/** How long the mail's block link works. The challenge row (no address) is kept for as long, then deleted. */
export const EMAIL_BLOCK_LINK_TTL_MS = 7 * 86_400_000;

/**
 * - `pending`: a code was sent (or is being sent) and can be entered.
 * - `passed`: the right code was entered; the held receipt is being saved.
 * - `consumed`: the receipt was settled after the pass. Terminal.
 * - `expired`: no right code before the deadline. Terminal: verify again.
 * - `locked`: too many wrong codes. Terminal: verify again.
 * - `blocked`: the mailbox owner used the block link. Terminal; the subject and the wallet are quarantined.
 * - `unavailable`: no challenge can run — the account has no e-mail the provider discloses (`no_email`) or this
 *   identity cannot send mail (`mail_unavailable`). Fail closed: the verification is refused.
 */
export const EMAIL_CHALLENGE_STATES = Object.freeze(["pending", "passed", "consumed", "expired", "locked", "blocked", "unavailable"] as const);
export type EmailChallengeState = typeof EMAIL_CHALLENGE_STATES[number];
export type EmailChallengeReason = "no_email" | "mail_unavailable";
export type EmailDelivery = "sending" | "sent" | "failed";

/** What `GET /verification-attempts/:id/email-challenge` answers. Times are epoch milliseconds. */
export type EmailChallengeView = Readonly<{
  format: typeof EMAIL_CHALLENGE_FORMAT;
  attemptId: string;
  /** `none` when this attempt has no challenge (nothing to show). */
  state: EmailChallengeState | "none";
  reason: EmailChallengeReason | null;
  /** When the current code stops working, or `null` outside `pending`. */
  expiresAt: number | null;
  /** When Resend becomes available, or `null` when no further code can be sent. */
  resendAt: number | null;
  sendsLeft: number;
  triesLeft: number;
  delivery: EmailDelivery | null;
  /** The provider whose account's mailbox received the code (`chatgpt`, `claude`, `grok`), for the copy. */
  provider: string | null;
}>;

export const isEmailCode = (value: unknown): value is string => typeof value === "string" && /^[0-9]{6}$/.test(value);
/** What a pasted or typed entry becomes: its digits, at most six ("123 456", "123-456" are accepted). */
export const normalizeEmailCode = (input: string): string => input.replace(/[^0-9]/g, "").slice(0, EMAIL_CODE_DIGITS);

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const time = (value: unknown) => value === null || (typeof value === "number" && Number.isSafeInteger(value) && value > 0);
const count = (value: unknown, max: number) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= max;
/** Strict: the app shows a challenge only from a view that parses; anything else is no challenge. */
export function parseEmailChallengeView(raw: unknown): EmailChallengeView | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const v = raw as Record<string, unknown>;
  const keys = ["format", "attemptId", "state", "reason", "expiresAt", "resendAt", "sendsLeft", "triesLeft", "delivery", "provider"];
  if (Object.keys(v).length !== keys.length || !keys.every(key => Object.prototype.hasOwnProperty.call(v, key))) return undefined;
  if (v.format !== EMAIL_CHALLENGE_FORMAT || typeof v.attemptId !== "string" || !UUID.test(v.attemptId)) return undefined;
  if (v.state !== "none" && !(EMAIL_CHALLENGE_STATES as readonly unknown[]).includes(v.state)) return undefined;
  if (v.reason !== null && v.reason !== "no_email" && v.reason !== "mail_unavailable") return undefined;
  if (!time(v.expiresAt) || !time(v.resendAt) || !count(v.sendsLeft, EMAIL_SENDS_PER_ATTEMPT) || !count(v.triesLeft, EMAIL_TRIES_PER_ATTEMPT)) return undefined;
  if (v.delivery !== null && v.delivery !== "sending" && v.delivery !== "sent" && v.delivery !== "failed") return undefined;
  if (v.provider !== null && (typeof v.provider !== "string" || !/^[a-z]{1,16}$/.test(v.provider))) return undefined;
  return Object.freeze(v as EmailChallengeView);
}
/** Whether a challenge still accepts a code at `now`. */
export const emailChallengeOpen = (view: Pick<EmailChallengeView, "state" | "expiresAt" | "triesLeft">, now: number) =>
  view.state === "pending" && view.expiresAt !== null && now < view.expiresAt && view.triesLeft > 0;
