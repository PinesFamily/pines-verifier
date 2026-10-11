// Regional channel entry. Routes are transport metadata
// only; HPKE still ends inside the quote-bound enclave and admission stays central.
// No Node-only imports: the extension, page client and parent bundle share this file.
import {check, exact, sign, verify, digest, encode, hex, unhex} from './wire.mjs';
import {REGIONS} from './fleet-region-codes.mjs';

export const ENTRY_PROTOCOL = 'pines-tee-regional-entry-v1';
export const ENTRY_DOMAIN = Object.freeze({route: 'pines/tee/channel-route/v1', claim: 'pines/tee/parent-channel-claim/v1',
  claimed: 'pines/tee/parent-channel-claim-result/v1'});
/** Equal to protocol.mjs DOMAIN.grant (test-pinned); kept here so the parent never loads provider/attestation code. */
export const GRANT_DOMAIN = 'pines/tee/grant/v1';
export const FIRST_FRAME_MAX_BYTES = 8192;
export const ENTRY_CLAIM_SKEW_MS = 10_000;
export const ENTRY_MAX_NODES = 128;
export const ENTRY_MAX_PROBES_PER_REGION = 4;
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/, HEX32 = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const time = value => Number.isSafeInteger(value) && value >= 0;

/** One dedicated zone for proof entry. Three or more labels keep `*.<suffix>` off the apex and the API host. */
export function validateEntrySuffix(value) {
  check(typeof value === 'string' && value.length <= 190, 'ENTRY_SUFFIX');
  const labels = value.split('.');
  check(labels.length >= 3 && labels.every(label => LABEL.test(label)) && !/^\d+$/.test(labels.at(-1)), 'ENTRY_SUFFIX');
  return value;
}
/** Node IDs that are not already one lowercase DNS label have no direct entry. Nothing is converted. */
export function entryLabel(nodeId) {
  check(typeof nodeId === 'string' && LABEL.test(nodeId), 'ENTRY_NODE_LABEL');
  return nodeId;
}
export const entryHost = (nodeId, suffix) => `${entryLabel(nodeId)}.${validateEntrySuffix(suffix)}`;
export const channelUrl = (nodeId, suffix) => `wss://${entryHost(nodeId, suffix)}/channel`;
export const probeUrl = (nodeId, suffix) => `https://${entryHost(nodeId, suffix)}/probe`;

/** Advisory only: the API intersects it with ready, qualified workers and ignores everything else. */
export function validateRegionHint(value) {
  check(Array.isArray(value) && value.length >= 1 && value.length <= REGIONS.length && new Set(value).size === value.length
    && value.every(region => typeof region === 'string' && REGIONS.includes(region)), 'REGION_HINT');
  return Object.freeze([...value]);
}

/** Operator-approved entry registry. Each node has its own parent claim key; keys are never shared. */
export function validateEntryConfiguration(value) {
  exact(value, ['version', 'protocol', 'suffix', 'nodes']);
  check(value.version === 1 && value.protocol === ENTRY_PROTOCOL, 'ENTRY_CONFIGURATION');
  const suffix = validateEntrySuffix(value.suffix);
  check(Array.isArray(value.nodes) && value.nodes.length > 0 && value.nodes.length <= ENTRY_MAX_NODES, 'ENTRY_CONFIGURATION');
  const nodes = new Map(), keys = new Set();
  for (const node of value.nodes) {
    exact(node, ['nodeId', 'awsRegion', 'claimKey']);
    entryLabel(node.nodeId);
    check(!nodes.has(node.nodeId) && REGIONS.includes(node.awsRegion) && typeof node.claimKey === 'string' && HEX32.test(node.claimKey)
      && !keys.has(node.claimKey), 'ENTRY_CONFIGURATION');
    keys.add(node.claimKey);
    nodes.set(node.nodeId, Object.freeze({nodeId: node.nodeId, awsRegion: node.awsRegion, claimKey: node.claimKey}));
  }
  return Object.freeze({suffix, nodes});
}

/** Public discovery: probe hosts are a latency hint source, never a destination authority. */
export function entryDiscovery(configuration) {
  const regions = REGIONS.map(region => ({region, probes: [...configuration.nodes.values()].filter(node => node.awsRegion === region)
    .map(node => node.nodeId).sort().slice(0, ENTRY_MAX_PROBES_PER_REGION).map(nodeId => probeUrl(nodeId, configuration.suffix))}))
    .filter(row => row.probes.length > 0);
  return {version: 1, protocol: ENTRY_PROTOCOL, suffix: configuration.suffix, regions};
}
export function parseEntryDiscovery(value, suffix) {
  exact(value, ['version', 'protocol', 'suffix', 'regions']);
  check(value.version === 1 && value.protocol === ENTRY_PROTOCOL && (suffix === undefined || value.suffix === suffix), 'ENTRY_DISCOVERY');
  validateEntrySuffix(value.suffix);
  check(Array.isArray(value.regions) && value.regions.length <= REGIONS.length, 'ENTRY_DISCOVERY');
  const seen = new Set();
  const regions = value.regions.map(row => {
    exact(row, ['region', 'probes']);
    check(REGIONS.includes(row.region) && !seen.has(row.region) && Array.isArray(row.probes) && row.probes.length > 0
      && row.probes.length <= ENTRY_MAX_PROBES_PER_REGION, 'ENTRY_DISCOVERY');
    seen.add(row.region);
    const probes = row.probes.map(url => {
      const label = typeof url === 'string' ? /^https:\/\/([a-z0-9-]+)\./.exec(url)?.[1] : undefined;
      check(label && url === probeUrl(label, value.suffix), 'ENTRY_DISCOVERY');
      return url;
    });
    check(new Set(probes).size === probes.length, 'ENTRY_DISCOVERY');
    return Object.freeze({region: row.region, probes: Object.freeze(probes)});
  });
  return Object.freeze({version: 1, protocol: ENTRY_PROTOCOL, suffix: value.suffix, regions: Object.freeze(regions)});
}

export const ROUTE_FIELDS = Object.freeze(['version', 'protocol', 'attempt', 'ticketHash', 'grantHash', 'nodeId', 'bootId', 'workerId',
  'region', 'channel', 'issuedAt', 'expiresAt']);
/** API side, after durable admission. The destination comes from the registry and the signed ticket's node. */
export async function signRoute({ticket, grant, region, suffix, now}, key) {
  check(REGIONS.includes(region) && time(now) && now < grant.body.deadline, 'ENTRY_ROUTE');
  return sign(ENTRY_DOMAIN.route, {version: 1, protocol: ENTRY_PROTOCOL, attempt: ticket.body.attempt,
    ticketHash: await digest(encode(ticket)), grantHash: await digest(encode(grant)), nodeId: ticket.body.nodeId,
    bootId: ticket.body.bootId, workerId: ticket.body.workerId, region, channel: channelUrl(ticket.body.nodeId, suffix),
    issuedAt: now, expiresAt: grant.body.deadline}, key);
}
/** Browser side. `suffix` is the build-pinned zone; page or discovery input never selects the destination. */
export async function checkRoute(route, {ticket, grant, apiKey, suffix, now}) {
  const body = await verify(ENTRY_DOMAIN.route, route, apiKey);
  exact(body, ROUTE_FIELDS);
  check(body.version === 1 && body.protocol === ENTRY_PROTOCOL, 'ENTRY_ROUTE_VERSION');
  check(body.attempt === ticket.body.attempt && body.ticketHash === await digest(encode(ticket))
    && body.grantHash === await digest(encode(grant)) && body.nodeId === ticket.body.nodeId
    && body.bootId === ticket.body.bootId && body.workerId === ticket.body.workerId && REGIONS.includes(body.region), 'ENTRY_ROUTE_CONTEXT');
  check(body.channel === channelUrl(body.nodeId, suffix), 'ENTRY_ROUTE_DESTINATION');
  check(time(body.issuedAt) && body.expiresAt === grant.body.deadline && body.issuedAt >= grant.body.issuedAt - 2000
    && body.issuedAt <= now + 2000 && now < body.expiresAt, 'ENTRY_ROUTE_EXPIRED');
  return body;
}

export const CLAIM_REQUEST_FIELDS = Object.freeze(['version', 'protocol', 'nodeId', 'bootId', 'host', 'frame', 'issuedAt', 'nonce']);
/** Parent side: the untouched first frame, bound to this node, its observed enclave boot and its entry name. */
export async function signClaimRequest({nodeId, bootId, suffix, frame, now, nonce}, key) {
  check(frame instanceof Uint8Array && frame.byteLength > 0 && frame.byteLength <= FIRST_FRAME_MAX_BYTES, 'FIRST_FRAME_LIMIT');
  unhex(bootId, 32); unhex(nonce, 32); check(time(now), 'ENTRY_CLAIM');
  return sign(ENTRY_DOMAIN.claim, {version: 1, protocol: ENTRY_PROTOCOL, nodeId, bootId, host: entryHost(nodeId, suffix),
    frame: hex(frame), issuedAt: now, nonce}, key);
}
/** API side. Authenticates the caller node before any frame parsing or ledger access. */
export async function checkClaimRequest(envelope, {configuration, now}) {
  exact(envelope, ['body', 'signature']);
  const nodeId = envelope.body?.nodeId, node = typeof nodeId === 'string' ? configuration.nodes.get(nodeId) : undefined;
  check(node, 'ENTRY_CLAIM_NODE');
  const body = await verify(ENTRY_DOMAIN.claim, envelope, node.claimKey);
  exact(body, CLAIM_REQUEST_FIELDS);
  check(body.version === 1 && body.protocol === ENTRY_PROTOCOL && body.host === entryHost(nodeId, configuration.suffix), 'ENTRY_CLAIM');
  unhex(body.bootId, 32); unhex(body.nonce, 32);
  check(typeof body.frame === 'string' && body.frame.length <= 2 * FIRST_FRAME_MAX_BYTES, 'FIRST_FRAME_LIMIT');
  const frame = unhex(body.frame);
  check(time(body.issuedAt) && body.issuedAt >= now - ENTRY_CLAIM_SKEW_MS && body.issuedAt <= now + 2000, 'ENTRY_CLAIM_STALE');
  return {node, bootId: body.bootId, frame, requestHash: await digest(encode(envelope))};
}

export const CLAIM_RESULT_FIELDS = Object.freeze(['version', 'protocol', 'requestHash', 'attempt', 'nodeId', 'bootId', 'workerId',
  'session', 'grantHash', 'deadline', 'channel', 'issuedAt']);
/** API side, only after the caller-bound single-use claim committed. */
export async function signClaimResult({requestHash, claim, route, suffix, now}, key) {
  check(route.nodeId && route.bootId && route.workerId && HEX32.test(requestHash), 'ENTRY_CLAIM_RESULT');
  return sign(ENTRY_DOMAIN.claimed, {version: 1, protocol: ENTRY_PROTOCOL, requestHash, attempt: claim.attemptId,
    nodeId: route.nodeId, bootId: route.bootId, workerId: route.workerId, session: claim.session, grantHash: claim.grantHash,
    deadline: claim.deadline, channel: channelUrl(route.nodeId, suffix), issuedAt: now}, key);
}
/** Parent side, before it opens any enclave upstream. */
export async function checkClaimResult(envelope, {apiKey, request, expected, now}) {
  const body = await verify(ENTRY_DOMAIN.claimed, envelope, apiKey);
  exact(body, CLAIM_RESULT_FIELDS);
  check(body.version === 1 && body.protocol === ENTRY_PROTOCOL && body.requestHash === await digest(encode(request)), 'ENTRY_CLAIM_RESULT');
  check(typeof body.attempt === 'string' && UUID.test(body.attempt) && ['attempt', 'session', 'grantHash', 'deadline', 'nodeId', 'bootId', 'channel']
    .every(key => body[key] === expected[key]) && /^[a-z0-9][a-z0-9-]{1,63}$/.test(body.workerId), 'ENTRY_CLAIM_BINDING');
  check(time(body.issuedAt) && body.issuedAt <= now + 2000 && body.issuedAt >= now - ENTRY_CLAIM_SKEW_MS && now < body.deadline, 'ENTRY_CLAIM_STALE');
  return body;
}
