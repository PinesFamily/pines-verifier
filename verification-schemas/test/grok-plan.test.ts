import test from "node:test";
import assert from "node:assert/strict";
import {capturedFrom, evaluateVerifiedExchange, inspectDisclosedRequest, parseSchema, planDisclosure, prepareReplay, previewExchange} from "../src/index.ts";
import type {Range, VerifiedBytes} from "../src/index.ts";
import {encode, registry, recipient, response} from "./helpers.ts";

// Shapes follow grok.com's `/rest/subscriptions` response and its own tier enum.
// Every value here is synthetic.
const schema = registry.list().find(e => e.reference.schemaId === "pines.grok.plan" && e.reference.version === 1)!.schema;
const user = "0f0e0d0c-0b0a-4908-8706-050403020100", other = "11111111-2222-4333-8444-555555555555";
const sub = (overrides: Record<string, unknown> = {}) => ({x: {}, xaiUserId: user, tier: "SUBSCRIPTION_TIER_X_PREMIUM_PLUS",
  status: "SUBSCRIPTION_STATUS_ACTIVE", createTime: "2026-01-01T00:00:00.000000Z", modTime: "2026-09-01T00:00:00.000000Z",
  futureOffers: [], billingSystem: "BILLING_SYSTEM_LEGACY", ...overrides});
const body = (...subscriptions: unknown[]) => ({subscriptions, dominantPlan: {plan: "x.premium", surfaceNames: {}}});
const sso = "eyJhbGciOiJIUzI1NiJ9.synthetic-session-never-a-real-cookie.x";
const userAgent = "Pines synthetic browser";
const wire = `GET /rest/subscriptions HTTP/1.1\r\naccept: application/json\r\nuser-agent: ${userAgent}\r\ncookie: sso=${sso}\r\nhost: grok.com\r\naccept-encoding: identity\r\nconnection: close\r\n\r\n`;

function masked(text = wire, secrets = [userAgent, `sso=${sso}`]): VerifiedBytes {
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
const evaluate = (json: unknown, sent = masked()) =>
  evaluateVerifiedExchange(schema, {mode: "Proxy", serverName: "grok.com", sent, recv: full(response(json))}, recipient);
const read = (json: unknown) => previewExchange(schema, encode(wire), response(json), recipient);

test("an active paid subscription binds the xAI user, and the highest active tier is the one read", () => {
  const facts = evaluate(body(sub()));
  assert.equal(facts.providerId, "GROK-PLAN");
  assert.equal(facts.domain, "grok.com");
  assert.equal(facts.identityVersion, "grok-user-v1");
  assert.equal(facts.subjectKey, user, "the xAI user UUID, never the wallet");
  assert.deepEqual({...facts.values}, {xai_user_id: user, tier: "SUBSCRIPTION_TIER_X_PREMIUM_PLUS", status: "SUBSCRIPTION_STATUS_ACTIVE"});
  assert.equal(facts.claimable, false);
  for (const tier of ["SUBSCRIPTION_TIER_SUPER_GROK_LITE", "SUBSCRIPTION_TIER_GROK_PRO", "SUBSCRIPTION_TIER_SUPER_GROK_PLUS", "SUBSCRIPTION_TIER_SUPER_GROK_PRO"])
    assert.equal(read(body(sub({tier, billingSystem: "BILLING_SYSTEM_COMMERCE"}))).values.tier, tier);
  // grok.com's getSubscriptionLevel: inactive and unpaid items never win, the highest active paid one does.
  const mixed = body(sub({tier: "SUBSCRIPTION_TIER_SUPER_GROK_PRO", status: "SUBSCRIPTION_STATUS_INACTIVE"}), sub({tier: "SUBSCRIPTION_TIER_X_PREMIUM"}),
    sub({tier: "SUBSCRIPTION_TIER_GROK_PRO"}), sub());
  assert.equal(read(mixed).values.tier, "SUBSCRIPTION_TIER_GROK_PRO");
});

test("free, X Basic/Premium, inactive, past-due, mixed-account and malformed lists fail closed", () => {
  for (const json of [
    body(), {subscriptions: []},
    body(sub({tier: "SUBSCRIPTION_TIER_X_BASIC"})), body(sub({tier: "SUBSCRIPTION_TIER_X_PREMIUM"})),
    body(sub({tier: "SUBSCRIPTION_TIER_INVALID"})), body(sub({tier: "SUBSCRIPTION_TIER_SUPER_GROK_ULTRA"})),
    body(sub({tier: "subscription_tier_grok_pro"})), body(sub({tier: undefined})), body(sub({tier: null})),
    body(sub({status: "SUBSCRIPTION_STATUS_INACTIVE"})), body(sub({status: "SUBSCRIPTION_STATUS_PAST_DUE"})),
    body(sub({status: "SUBSCRIPTION_STATUS_UPDATE_IN_PROGRESS"})), body(sub({status: undefined})),
    body(sub(), sub({xaiUserId: other, tier: "SUBSCRIPTION_TIER_X_BASIC"})),  // two accounts in one list: whose is it?
    body(sub({xaiUserId: user.toUpperCase()})), body(sub({xaiUserId: user + " "})), body(sub({xaiUserId: undefined})), body(sub({xaiUserId: 7})),
    body(sub(), "x"), body(sub(), null), {subscriptions: sub()}, [sub()], sub(), "[]",
    {subscriptions: Array.from({length: 65}, () => sub())},
  ]) assert.throws(() => read(json), JSON.stringify(json));
});

test("the sso cookie is a required, entirely opaque credential", () => {
  assert.deepEqual(inspectDisclosedRequest(schema, masked()).map(slot => slot.name), ["user-agent", "cookie"]);
  assert.throws(() => evaluate(body(sub()), full(encode(wire))), {code: "PRIVATE_REQUEST_UNSUPPORTED"});
  const cookieless = wire.replace(`cookie: sso=${sso}\r\n`, "");
  assert.throws(() => evaluate(body(sub()), masked(cookieless, [userAgent])), {code: "SCOPE_MISMATCH"});
  assert.throws(() => evaluate(body(sub()), masked(wire.replace("/rest/subscriptions", "/rest/auth/get-user"))), {code: "SCOPE_MISMATCH"});
  const plan = planDisclosure(schema, encode(wire), response(body(sub())), recipient);
  const disclosed = plan.sent.map(({start, end}) => wire.slice(start, end)).join("");
  assert.equal(disclosed.includes(sso) || disclosed.includes(userAgent), false);
  assert.equal(plan.preview.subjectKey, user);
});

test("triggered capture takes only sso from the page's own /rest/ traffic, never Cloudflare's cookies", () => {
  const replay = prepareReplay(schema, {url: "https://grok.com/rest/app-chat/conversations?pageSize=60", method: "GET", headers: [
    {name: "Cookie", value: `grok_device_id=x; cf_clearance=secret; __cf_bm=secret; sso-rw=${sso}; sso=${sso}; x-userid=${user}`},
    {name: "User-Agent", value: userAgent}, {name: "x-xai-request-id", value: "must-not-replay"}]});
  assert.equal(replay.url, "https://grok.com/rest/subscriptions", "the proven request stays fixed");
  assert.deepEqual(replay.headers, {accept: "application/json", "user-agent": userAgent, cookie: `sso=${sso}`,
    host: "grok.com", "accept-encoding": "identity", connection: "close"});
  const headers = [{name: "Cookie", value: `sso=${sso}`}, {name: "User-Agent", value: userAgent}];
  for (const url of ["https://grok.com/c/abc", "https://accounts.x.ai/rest/x", "https://grok.com.evil.example/rest/x", "not a url"]) {
    assert.equal(capturedFrom(schema, url), false, url);
    assert.throws(() => prepareReplay(schema, {url, method: "GET", headers}), {code: "INVALID_CAPTURE"});
  }
  assert.equal(capturedFrom(schema, "https://grok.com/rest/products"), true);
  assert.throws(() => prepareReplay(schema, {url: "https://grok.com/rest/x", method: "GET", headers: [headers[1]!, {name: "Cookie", value: "sso-rw=x"}]}), {code: "INVALID_CAPTURE"});
});

test("the Grok selector and handlers are only accepted on grok.com", () => {
  const base = structuredClone(schema) as any;
  const bad = (edit: (s: any) => void) => { const copy = structuredClone(base); edit(copy); assert.throws(() => parseSchema(copy), {code: "INVALID_SCHEMA"}); };
  bad(s => { s.request.origin = "https://claude.ai"; s.capture.authOrigins = ["https://claude.ai"]; s.capture.navigationUrl = "https://claude.ai/"; });
  bad(s => { s.selector = {kind: "claude-paid-personal-org-v1"}; });
  bad(s => { s.checks[1].handler = "grok-user-uuid-v1"; s.fields[1].type = "array"; });
  const claude = structuredClone(registry.list().find(e => e.reference.schemaId === "pines.claude.plan")!.schema) as any;
  claude.selector = {kind: "grok-paid-subscription-v1"};
  assert.throws(() => parseSchema(claude), {code: "INVALID_SCHEMA"});
});
