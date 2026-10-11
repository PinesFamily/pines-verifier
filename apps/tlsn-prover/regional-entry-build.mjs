// Build-time CSP scope for regional entry builds.
import {validateEntrySuffix} from '../../tools/tee-native/fleet-entry.mjs';
/** Exactly the pinned zone's sockets and probes: no other scheme, host, port or apex wildcard. */
export const regionalConnectSources = suffix => [`wss://*.${validateEntrySuffix(suffix)}`, `https://*.${suffix}`];
