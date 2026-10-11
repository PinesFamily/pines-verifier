// Advisory regional preference. One credential-free probe
// per region, only to canonical names under this build's pinned entry zone. The
// result is a hint the API may ignore; it never selects or authorizes a destination.
import {parseEntryDiscovery, validateRegionHint} from '../../../tools/tee-native/fleet-entry.mjs';

export const PROBE_TIMEOUT_MS = 1500;
export const PREFERENCE_TTL_MS = 10 * 60_000;

export function regionPreference({suffix, fetch: fetchImpl = (...args) => globalThis.fetch(...args), elapsed = () => performance.now(), clock = Date.now}) {
  let cached;
  return async discovery => {
    const entry = parseEntryDiscovery(discovery, suffix), key = JSON.stringify(entry.regions);
    if (cached?.key === key && clock() < cached.until) return cached.regions;
    const timed = await Promise.all(entry.regions.map(async ({region, probes}, index) => {
      const started = elapsed();
      try {
        const response = await fetchImpl(probes[0], {method: 'GET', mode: 'cors', credentials: 'omit', cache: 'no-store', redirect: 'error',
          referrerPolicy: 'no-referrer', signal: AbortSignal.timeout(PROBE_TIMEOUT_MS)});
        return response.status === 204 ? {region, index, ms: elapsed() - started} : undefined;
      } catch {return undefined;}
    }));
    // Unreachable regions are omitted, not penalized: the API still falls back deterministically.
    const ordered = timed.filter(Boolean).sort((a, b) => a.ms - b.ms || a.index - b.index).map(row => row.region);
    const regions = ordered.length ? validateRegionHint(ordered) : Object.freeze([]);
    cached = {key, until: clock() + PREFERENCE_TTL_MS, regions};
    return regions;
  };
}
