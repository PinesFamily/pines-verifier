import test from "node:test";
import assert from "node:assert/strict";
import {previewExchange} from "../src/index.ts";
import {inspectDisclosedResponse} from "../src/redacted-response.ts";
import {parseJson} from "../src/json.ts";
import type {VerificationSchema, VerifiedBytes} from "../src/types.ts";
import {decode, encode, recipient, registry, request, response} from "./helpers.ts";

// These are counterexamples to the proposed rules, not a selective JSON parser.
// A good string-only gap and a bad cross-token gap have identical verifier input.
function collision(parts: string[]) {
  const original = parts.join("");
  const benign = parts.map((part, i) => i % 2 ? "x".repeat(part.length) : part).join("");
  const opaque = parts.filter((_, i) => i % 2 === 0).join("");
  for (const json of [original, benign, opaque]) parseJson(json);
  const wire = response(original), goodWire = response(benign);
  assert.equal(wire.length, goodWire.length, "Content-Length and transcript length also match");
  const authenticated: {start: number; end: number}[] = [];
  let cursor = decode(wire).indexOf("\r\n\r\n") + 4;
  authenticated.push({start: 0, end: cursor});
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i]!;
    assert.equal(encode(part).length, part.length, "synthetic vectors are ASCII");
    if (i % 2 === 0) authenticated.push({start: cursor, end: cursor + part.length});
    else {
      // The exact visible boundary rules requested in the release prompt.
      assert.match(parts[i - 1]!, /"[^"\\]+"\s*:\s*"$/);
      assert.match(parts[i + 1]!, /^"\s*[,}\]]/);
    }
    cursor += part.length;
  }
  const project = (bytes: Uint8Array): VerifiedBytes => {
    const masked = new Uint8Array(bytes.length);
    for (const {start, end} of authenticated) masked.set(bytes.subarray(start, end), start);
    return {bytes: masked, originalLength: bytes.length, authenticated};
  };
  const evidence = project(wire);
  assert.deepEqual(evidence, project(goodWire), "all disclosed bytes, positions and lengths are indistinguishable");
  return {original, benign, opaque, evidence};
}
const schemaFor = (schemaId: string, version: number) => registry.list().find(e =>
  e.reference.schemaId === schemaId && e.reference.version === version)!.schema;
const id = "0f0e0d0c-0b0a-4908-8706-050403020100";
const other = "11111111-2222-4333-8444-555555555555";
function sent(schema: VerificationSchema) {
  if (schema.schemaId === "pines.chatgpt.plan") return request(schema);
  const cookie = schema.schemaId === "pines.claude.plan" ? "sessionKey=synthetic" : "sso=synthetic";
  return request(schema, {url: schema.request.origin + schema.request.path, method: "GET", headers: [
    {name: "Cookie", value: cookie}, {name: "User-Agent", value: "Synthetic browser"},
  ]});
}
const facts = (schema: VerificationSchema, body: string) => previewExchange(schema, sent(schema), response(body), recipient);

test("a hidden name can swallow a second paid Claude org without a visible syntax error", () => {
  const schema = schemaFor("pines.claude.plan", 1);
  const fields = (uuid: string) => `"uuid":"${uuid}","capabilities":["chat","claude_max"],"rate_limit_tier":"default_claude_max_20x","raven_type":null,"parent_organization_uuid":null`;
  const c = collision([`[{${fields(id)},"name":"`, `a"},{${fields(other)},"name":"b`, '"}]']);
  assert.throws(() => facts(schema, c.original), {code: "CHECK_FAILED"});
  assert.equal(facts(schema, c.benign).subjectKey, id);
  assert.deepEqual(facts(schema, c.opaque), facts(schema, c.benign));
  assert.throws(() => inspectDisclosedResponse(schema, c.evidence), {code: "PARTIAL_TRANSCRIPT"});
});

test("a hidden Grok billing value can swallow the highest active subscription", () => {
  const schema = schemaFor("pines.grok.plan", 1);
  const fields = (tier: string) => `"xaiUserId":"${id}","tier":"${tier}","status":"SUBSCRIPTION_STATUS_ACTIVE"`;
  const low = "SUBSCRIPTION_TIER_X_PREMIUM_PLUS", high = "SUBSCRIPTION_TIER_SUPER_GROK_PRO";
  const c = collision([`{"subscriptions":[{${fields(low)},"billingSystem":"`,
    `a"},{${fields(high)},"billingSystem":"b`, '"}]}']);
  assert.equal(facts(schema, c.original).values.tier, high);
  assert.equal(facts(schema, c.benign).values.tier, low);
  assert.deepEqual(facts(schema, c.opaque), facts(schema, c.benign));
  assert.throws(() => inspectDisclosedResponse(schema, c.evidence), {code: "PARTIAL_TRANSCRIPT"});
});

test("hidden unknown strings can move nested ChatGPT facts to the root", () => {
  const schema = schemaFor("pines.chatgpt.plan", 3);
  const real = "user-ABCDEFGHIJKLMNOPQRSTUVWX", nested = "user-abcdefghijklmnopqrstuvwx";
  // A synthetic future-field shape, not a claim about today's provider response.
  const c = collision(['{"name":"', 'a","metadata":{"padding":"b',
    `","user_id":"${nested}","plan_type":"plus","tail":"`,
    `c"},"user_id":"${real}","plan_type":"free","last":"d`, '"}']);
  assert.throws(() => facts(schema, c.original), {code: "CHECK_FAILED"});
  assert.equal(facts(schema, c.benign).subjectKey, nested);
  assert.deepEqual(facts(schema, c.opaque), facts(schema, c.benign));
  assert.throws(() => inspectDisclosedResponse(schema, c.evidence), {code: "PARTIAL_TRANSCRIPT"});
});
