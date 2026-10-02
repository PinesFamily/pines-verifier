/** Funnel origins the extension may be driven from. Ports stay in this list; manifest patterns drop them. */
export const DEFAULT_FUNNEL_ORIGINS = ['http://localhost:5180', 'http://127.0.0.1:5180'];
export const FUNNEL_ORIGINS_EXCLUSIVE_ENV = 'PROVER_FUNNEL_ORIGINS_EXCLUSIVE';

function isTruthy(value) {
  if (typeof value !== 'string') return false;
  const v = value.trim().toLowerCase();
  return v !== '' && v !== '0' && v !== 'false' && v !== 'no' && v !== 'off';
}

/** Loopback defaults plus `PROVER_FUNNEL_ORIGINS`, unless the exclusive flag replaces the list. */
export function funnelOrigins(env = process.env) {
  const configured = (env.PROVER_FUNNEL_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
  if (!configured.length) return [...DEFAULT_FUNNEL_ORIGINS];
  if (isTruthy(env[FUNNEL_ORIGINS_EXCLUSIVE_ENV])) return [...new Set(configured)];
  return [...new Set([...configured, ...DEFAULT_FUNNEL_ORIGINS])];
}

/** Chrome match patterns cannot carry a port, so a bare origin becomes `scheme://host/*`. */
export function matchPatternsFor(origins) {
  return [...new Set(origins.map((value) => {
    const url = new URL(value);
    if (url.pathname !== '/' || url.search || url.hash) throw new Error(`funnel origin must be a bare origin, got ${value}`);
    return `${url.protocol}//${url.hostname}/*`;
  }))];
}
