import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { parseSchema, schemaDigest, createRegistry, SchemaError, importLegacyChecks } from "../src/index.ts";
import { canonicalJson, parseJson, selectJson } from "../src/json.ts";
import { fixture, chatgpt, registry } from "./helpers.ts";

test("registry pins canonical digests and refuses changed content at the same version", async () => {
  assert.equal(registry.list().length, 9);
  for (const { schema, reference } of registry.list()) {
    const expected = "sha256:" + createHash("sha256").update(canonicalJson(schema)).digest("hex");
    assert.equal(reference.digest, expected);
    assert.equal(await schemaDigest(schema), expected);
    assert.equal(registry.resolve(reference), schema);
  }
  const reference = registry.list().find(entry => entry.schema === chatgpt)!.reference;
  const changed = structuredClone(chatgpt);
  Object.assign(changed.request, { path: "/other" });
  await assert.rejects(createRegistry([changed], [reference]), { code: "SCHEMA_DIGEST_MISMATCH" });
  assert.throws(() => registry.resolve({ ...reference, version: 999 }), { code: "UNKNOWN_SCHEMA" });
  assert.throws(() => registry.resolve({ ...reference, digest: "sha256:" + "0".repeat(64) }), { code: "SCHEMA_DIGEST_MISMATCH" });
  await assert.rejects(createRegistry([chatgpt, chatgpt], [reference, reference]), { code: "INVALID_SCHEMA" });
});

test("canonicalization ignores property order and schemas are deeply immutable", () => {
  assert.equal(canonicalJson({ z: [3, 2], a: { y: true, x: "π" } }), '{"a":{"x":"π","y":true},"z":[3,2]}');
  for (const invalid of [undefined, NaN, Infinity, () => 1, new Date(), { x: undefined }, "\ud800", [1, , 2]]) {
    assert.throws(() => canonicalJson(invalid), SchemaError);
  }
  const disguisedHole = Object.assign(new Array(1), { extra: "not an array element" });
  assert.throws(() => canonicalJson(disguisedHole), SchemaError);
  assert.throws(() => canonicalJson(Object.defineProperty([], "0", { get: () => 1, enumerable: true })), SchemaError);
  const copy = structuredClone(fixture);
  const parsed = parseSchema(copy);
  Object.assign(copy.request, { path: "/mutated" });
  assert.equal(parsed.request.path, "/profile");
  assert.throws(() => Object.assign(parsed.limits, { maxSentBytes: 99999 }), TypeError);
  assert.throws(() => (parsed.fields as unknown[]).push({}), TypeError);
});

test("schema validation rejects unknown transforms, active claims, bad selectors, origins and checks", () => {
  const mutations = [
    (s: any) => { s.claims.enabled = true; },
    (s: any) => { s.replay.transform = "remote-script"; },
    (s: any) => { s.replay.headers.authorization = "secret"; },
    (s: any) => { s.request.origin = "http://schemas.example.test"; },
    (s: any) => { s.request.origin = "https://user:password@schemas.example.test"; },
    (s: any) => { s.request.path = "/a/../profile"; },
    (s: any) => { s.fields[0].pointer = "/data/~2userId"; },
    (s: any) => { s.fields.push(s.fields[0]); },
    (s: any) => { s.checks[0].field = "invented"; },
    (s: any) => { s.checks[0] = { op: "custom", field: "code", handler: "uploaded-handler" }; },
    (s: any) => { s.limits.maxRecvBytes = 0; },
    (s: any) => { s.limits.maxJsonDepth = 1000; },
    (s: any) => { s.capture.headers = [{ name: "authorization", secret: false, required: true, validation: "bearer" }]; },
    (s: any) => { s.extra = "ignored policies are forbidden"; },
  ];
  for (const mutate of mutations) {
    const candidate = structuredClone(fixture);
    mutate(candidate);
    assert.throws(() => parseSchema(candidate), { code: "INVALID_SCHEMA" });
  }
});

test("strict JSON rejects duplicate keys after unescaping, invalid Unicode and lossy numbers", () => {
  for (const input of [
    '{"plan_type":"free","plan_type":"pro"}',
    '{"plan_type":"free","plan_\\u0074ype":"pro"}',
    '{"nested":{"x":1,"x":2}}',
  ]) assert.throws(() => parseJson(input), { code: "DUPLICATE_JSON_KEY" });
  for (const input of ['{"x":01}', '[1,]', '{"x":}', 'true false', '"\\ud800"', '"\\q"', '\ufeff{}', '{"x":"raw\nnewline"}']) {
    assert.throws(() => parseJson(input), SchemaError);
  }
  for (const number of ["9007199254740993", "1.00000000000000001", "1e999", "1e-999", "1.234567890123456789"]) {
    assert.throws(() => parseJson(number), { code: "UNSAFE_JSON_NUMBER" });
  }
  assert.equal(parseJson("1.25e1"), 12.5);
  assert.equal(parseJson("-0"), -0);
  assert.equal(parseJson('"😀"'), "😀");
  assert.throws(() => parseJson("[[[[]]]]", 2), { code: "LIMIT_EXCEEDED" });
});

test("JSON pointers establish ancestry, escape tokens and never traverse inherited properties", () => {
  const input = parseJson('{"data":{"userId":42},"a/b":{"~key":["😀"]},"__proto__":{"safe":true}}');
  assert.equal(selectJson(input, "/data/userId"), 42);
  assert.equal(selectJson(input, "/a~1b/~0key/0"), "😀");
  assert.equal(selectJson(input, "/__proto__/safe"), true);
  for (const path of ["/userId", "/toString", "/data/constructor", "/a~1b/~0key/length", "/a~1b/~0key/00"]) {
    assert.throws(() => selectJson(input, path), { code: "MISSING_FIELD" });
  }
  assert.equal(({} as Record<string, unknown>).safe, undefined);
});

test("legacy conversion requires explicit path bindings and rejects substring/custom checks", () => {
  const legacy = { id: "14", host: "schemas.example.test", user_id: { window: { id: 0, key: "userId" }, type: "any" }, checks: [{ window: { id: 1, key: "kycLevel" }, type: "gte", value: 2 }] };
  const bindings = [
    { windowId: 0, key: "userId", field: fixture.fields[0]! },
    { windowId: 1, key: "kycLevel", field: fixture.fields[1]! },
  ];
  const converted = importLegacyChecks(legacy, bindings, "schemas.example.test");
  assert.equal(converted.identityField, "userId");
  assert.deepEqual(converted.checks, [{ op: "gte", field: "level", value: 2 }]);
  assert.throws(() => importLegacyChecks(legacy, bindings.slice(0, 1), "schemas.example.test"), { code: "UNSUPPORTED_LEGACY_CHECK" });
  assert.throws(() => importLegacyChecks(legacy, bindings, "other.example.test"), { code: "UNSUPPORTED_LEGACY_CHECK" });
  for (const type of ["contains", "custom", "unrecognized"]) {
    assert.throws(() => importLegacyChecks({ ...legacy, checks: [{ window: { id: 1, key: "kycLevel" }, type, value: "Active" }] }, bindings, "schemas.example.test"), { code: "UNSUPPORTED_LEGACY_CHECK" });
  }
  assert.throws(() => importLegacyChecks({ ...legacy, checks: [{ window: { id: 1, key: "kycLevel", check_key: false }, type: "gte", value: 2 }] }, bindings, "schemas.example.test"), { code: "UNSUPPORTED_LEGACY_CHECK" });
});
