// Browser transport selection for regional entry.
// The destination comes only from an API-signed route checked against the
// build-pinned zone. Admission, attestation and HPKE are unchanged either way.
import {openRaw} from './transport.mjs';
import {checkRoute} from './fleet-entry.mjs';

export const DIRECT_CONNECT_MS = 5000;
/** Falls back to the API relay only when the direct socket never opened: no frame
 * was written, so neither path can have consumed the attempt's single-use claim.
 * Once a direct socket is open the caller writes the first frame and never falls back. */
export async function openChannel({cfg, ticket, grant, route, now = Date.now, open = openRaw}) {
  const relay = async fallback => ({wire: await open(cfg.relay), entry: 'relay', ...(fallback ? {fallback} : {})});
  if (!cfg.regionalEntry || route === undefined) return relay();
  let checked;
  try {checked = await checkRoute(route, {ticket, grant, apiKey: cfg.apiKey, suffix: cfg.regionalEntry.suffix, now: now()});}
  catch {return relay('ROUTE_REFUSED');}
  let wire;
  try {wire = await open(checked.channel, {connectMs: DIRECT_CONNECT_MS});}
  catch {return relay('DIRECT_UNAVAILABLE');}
  return {wire, entry: 'direct', region: checked.region};
}
