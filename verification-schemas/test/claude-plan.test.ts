import test from "node:test";
import assert from "node:assert/strict";
import {capturedFrom, evaluateVerifiedExchange, inspectDisclosedRequest, parseSchema, planDisclosure, prepareReplay, previewExchange} from "../src/index.ts";
import type {Range, VerifiedBytes} from "../src/index.ts";
import {encode, registry, recipient, response} from "./helpers.ts";

// Shapes follow claude.ai's `/api/organizations` response.
// Every value here is synthetic.
const schema = registry.list().find(e => e.reference.schemaId === "pines.claude.plan" && e.reference.version === 1)!.schema;
const personal = "0f0e0d0c-0b0a-4908-8706-050403020100", apiOrg = "11111111-2222-4333-8444-555555555555";
const org = (overrides: Record<string, unknown> = {}) => ({id: 1, uuid: personal, name: "Synthetic Person's Organization",
  capabilities: ["chat", "claude_max"], parent_organization_uuid: null, rate_limit_tier: "default_claude_max_20x",
  billing_type: "stripe_subscription", raven_type: null, settings: {}, ...overrides});
const api = org({id: 2, uuid: apiOrg, capabilities: ["api", "api_individual"], rate_limit_tier: "auto_trust_tier_c", billing_type: "prepaid"});
const sessionKey = "sk-ant-sid01-synthetic-session-never-a-real-cookie";
const userAgent = "Pines synthetic browser";
const wire = `GET /api/organizations HTTP/1.1\r\naccept: application/json\r\nuser-agent: ${userAgent}\r\ncookie: sessionKey=${sessionKey}\r\nhost: claude.ai\r\naccept-encoding: identity\r\nconnection: close\r\n\r\n`;

function masked(text = wire, secrets = [userAgent, `sessionKey=${sessionKey}`]): VerifiedBytes {
  const bytes = encode(text), authenticated: Range[] = [];
  let cursor = 0;
  for (const secret of secrets.map(value => ({start: text.indexOf(value), end: text.indexOf(value) + value.length})).sort((a, b) => a.start - b.start)) {
    if (secret.start > cursor) authenticated.push({start: cursor, end: secret.start});
    bytes.fill(0, secret.start, secret.end); cursor = secret.end;
  }
  if (cursor < bytes.length) authenticated.push({start: cursor, end: bytes.length});
  return {bytes, originalLength: bytes.length, authenticated};
}
const full = (bytes: Uint8Array): VerifiedBytes => ({bytes, originalLength: bytes.length, authenticated: [{start: 0, end: bytes.length}]});
const evaluate = (body: unknown, sent = masked()) =>
  evaluateVerifiedExchange(schema, {mode: "Proxy", serverName: "claude.ai", sent, recv: full(response(body))}, recipient);
const read = (body: unknown) => previewExchange(schema, encode(wire), response(body), recipient);

test("a paid personal org is selected out of the full org list and becomes the identity", () => {
  const facts = evaluate([api, org()]);
  assert.equal(facts.providerId, "CLAUDE-PLAN");
  assert.equal(facts.domain, "claude.ai");
  assert.equal(facts.identityVersion, "claude-org-v1");
  assert.equal(facts.subjectKey, personal, "the org UUID, never the wallet");
  assert.deepEqual({...facts.values}, {organization_uuid: personal, rate_limit_tier: "default_claude_max_20x", capabilities: ["chat", "claude_max"]});
  assert.equal(facts.claimable, false);
  assert.equal(read([org({rate_limit_tier: "default_claude_max_5x"})]).subjectKey, personal);
  assert.equal(read([org({capabilities: ["chat", "claude_pro"], rate_limit_tier: "default_claude_pro"})]).subjectKey, personal);
  // A Team membership next to a personal Max org does not make it ambiguous: Team is never selected.
  const team = org({uuid: apiOrg, capabilities: ["chat", "raven"], rate_limit_tier: "default_raven", raven_type: "team"});
  assert.equal(read([team, org()]).subjectKey, personal);
});

test("free, Team, API-only, ambiguous and inconsistent orgs fail closed", () => {
  for (const body of [
    [org({capabilities: ["chat"], rate_limit_tier: "default_claude_ai"})],  // Free
    [api], [],
    [org({capabilities: ["chat", "raven", "claude_max"]})], [org({raven_type: "team"})],
    [org({parent_organization_uuid: apiOrg})],
    [org(), org({uuid: apiOrg})],  // two paid personal orgs: which one is the account?
    [org({capabilities: ["chat", "claude_max", "claude_pro"]})],
    [org({capabilities: ["chat", "claude_max"], rate_limit_tier: "default_claude_pro"})],
    [org({capabilities: ["claude_max"]})], [org({capabilities: ["chat", "claude_max", "chat"]})],
    [org({capabilities: ["chat", "Claude_Max"]})], [org({capabilities: "chat,claude_max"})],
    [org({rate_limit_tier: "default_claude_ai"})], [org({rate_limit_tier: "DEFAULT_CLAUDE_MAX_20X"})],
    [org({rate_limit_tier: "default_claude_max_20x "})], [org({rate_limit_tier: null})], [org({rate_limit_tier: undefined})],
    [org({uuid: personal.toUpperCase()})], [org({uuid: personal + " "})], [org({uuid: "user-abc"})], [org({uuid: undefined})],
    org(), {organizations: [org()]}, "[]",
  ]) assert.throws(() => read(body), JSON.stringify(body));
});

test("the cookie jar is a required, entirely opaque credential", () => {
  assert.deepEqual(inspectDisclosedRequest(schema, masked()).map(slot => slot.name), ["user-agent", "cookie"]);
  // Fully disclosed: the credential would reach the verifier, so it is refused rather than read.
  assert.throws(() => evaluate([org()], full(encode(wire))), {code: "PRIVATE_REQUEST_UNSUPPORTED"});
  const cookieless = wire.replace(`cookie: sessionKey=${sessionKey}\r\n`, "");
  assert.throws(() => evaluate([org()], masked(cookieless, [userAgent])), {code: "SCOPE_MISMATCH"});
  const twice = wire.replace("host:", `cookie: sessionKey=${sessionKey}\r\nhost:`);
  assert.throws(() => evaluate([org()], masked(twice, [userAgent, `sessionKey=${sessionKey}`])));
  assert.throws(() => evaluate([org()], masked(wire.replace("/api/organizations", "/api/account"))), {code: "SCOPE_MISMATCH"});
  const plan = planDisclosure(schema, encode(wire), response([api, org()]), recipient);
  const disclosed = plan.sent.map(({start, end}) => wire.slice(start, end)).join("");
  assert.equal(disclosed.includes(sessionKey) || disclosed.includes(userAgent), false);
  assert.equal(plan.preview.subjectKey, personal);
});

test("triggered capture takes only the named cookie from the page's own API traffic", () => {
  const replay = prepareReplay(schema, {url: "https://claude.ai/api/account_profile", method: "GET", headers: [
    {name: "Cookie", value: `anthropic-device-id=x; sessionKey=${sessionKey}; cf_clearance=secret; lastActiveOrg=${personal}`},
    {name: "User-Agent", value: userAgent}, {name: "anthropic-client-sha", value: "must-not-replay"}]});
  assert.equal(replay.url, "https://claude.ai/api/organizations", "the proven request stays fixed");
  assert.deepEqual(replay.headers, {accept: "application/json", "user-agent": userAgent, cookie: `sessionKey=${sessionKey}`,
    host: "claude.ai", "accept-encoding": "identity", connection: "close"});
  const headers = [{name: "Cookie", value: `sessionKey=${sessionKey}`}, {name: "User-Agent", value: userAgent}];
  for (const url of ["https://claude.ai/settings/billing", "https://evil.example/api/account", "https://claude.ai.evil.example/api/x",
    "https://user:pass@claude.ai/api/x", "https://claude.ai/api/x#f", "not a url"]) {
    assert.equal(capturedFrom(schema, url), false, url);
    assert.throws(() => prepareReplay(schema, {url, method: "GET", headers}), {code: "INVALID_CAPTURE"});
  }
  assert.equal(capturedFrom(schema, "https://claude.ai/api/organizations/" + personal + "/usage?x=1"), true);
  assert.throws(() => prepareReplay(schema, {url: "https://claude.ai/api/x", method: "GET", headers: [headers[1]!, {name: "Cookie", value: "cf_clearance=x"}]}), {code: "INVALID_CAPTURE"});
  assert.throws(() => prepareReplay(schema, {url: "https://claude.ai/api/x", method: "POST", headers}), {code: "INVALID_CAPTURE"});
});

test("triggers, selectors and Claude handlers are only accepted where they can mean something", () => {
  const base = structuredClone(schema) as any;
  const bad = (edit: (s: any) => void) => { const copy = structuredClone(base); edit(copy); assert.throws(() => parseSchema(copy), {code: "INVALID_SCHEMA"}); };
  bad(s => { s.capture.cookies = []; });
  bad(s => { s.capture.trigger = {pathPrefix: "/api"}; }); bad(s => { s.capture.trigger = {pathPrefix: "api/"}; });
  bad(s => { s.capture.trigger = {pathPrefix: "/api/", extra: 1}; });
  bad(s => { s.capture.headers.push({name: "authorization", required: true, secret: true, validation: "bearer"}); });
  bad(s => { s.request.origin = "https://chatgpt.com"; s.capture.authOrigins = ["https://chatgpt.com"]; s.capture.navigationUrl = "https://chatgpt.com/"; });
  bad(s => { s.selector = {kind: "first-array-element"}; });
  bad(s => { s.checks[2].field = "rate_limit_tier"; }); bad(s => { s.checks[0].handler = "claude-paid-capabilities-v1"; });
  // Without a selector, a Claude-shaped schema reads the root and the org list is refused as a non-object.
  const unselected = structuredClone(base); delete unselected.selector;
  assert.throws(() => previewExchange(parseSchema(unselected), encode(wire), response([org()]), recipient), {code: "INVALID_JSON"});
});
