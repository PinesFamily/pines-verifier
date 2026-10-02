import test from "node:test";
import assert from "node:assert/strict";
import {parseJson} from "../src/json.ts";
import {encode} from "./helpers.ts";

// Research vectors only: no new schema, disclosure planner or acceptance policy.
test("an authenticated Unicode escape prefix confines two unknown bytes under the valid-JSON premise", () => {
  const prefix = encode('{"private":"\\u00');
  const suffix = encode('","plan_type":"plus"}');
  const bytes = new Uint8Array(prefix.length + 2 + suffix.length);
  bytes.set(prefix); bytes.set(suffix, prefix.length + 2);
  const decoder = new TextDecoder("utf-8", {fatal: true});
  let validCompletions = 0;
  const decoded = new Set<string>();
  // Exhaust all 65,536 byte pairs, including quotes, slashes, invalid UTF-8 and
  // control bytes. Only hex pairs can complete the provider's valid JSON.
  for (let a = 0; a < 256; a++) for (let b = 0; b < 256; b++) {
    bytes[prefix.length] = a; bytes[prefix.length + 1] = b;
    let value;
    try {value = parseJson(decoder.decode(bytes));} catch {continue;}
    assert(value !== null && typeof value === "object" && !Array.isArray(value));
    assert.deepEqual(Object.keys(value), ["private", "plan_type"]);
    assert.equal(value.plan_type, "plus");
    assert.equal(typeof value.private, "string");
    const hidden = value.private as string;
    assert.equal(hidden.length, 1);
    assert(hidden.charCodeAt(0) <= 255);
    assert.match(String.fromCharCode(a, b), /^[a-fA-F0-9]{2}$/);
    decoded.add(hidden); validCompletions++;
  }
  assert.equal(validCompletions, 22 * 22, "10 digits plus uppercase/lowercase A–F");
  assert.equal(decoded.size, 256, "no surrogate ambiguity with the revealed 00 prefix");
});

test("client re-encoding preserves JSON values but changes authenticated transcript bytes", () => {
  const origin = '{"email":"synthetic@example.test","plan_type":"plus"}';
  const transformed = origin.replace("synthetic@example.test", value => [...value]
    .map(c => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")).join(""));
  assert.deepEqual(parseJson(origin), parseJson(transformed));
  assert.notDeepEqual(encode(origin), encode(transformed));
  assert.notEqual(encode(origin).length, encode(transformed).length);
});

test("an authenticated JSON prefix alone does not establish absence of duplicate fields in its hidden suffix", () => {
  const prefix = '{"user_id":"user-ABCDEFGHIJKLMNOPQRSTUVWX","plan_type":"plus",';
  const unique = prefix + '"name":"synthetic"}';
  const duplicate = prefix + '"name":"synthetic","plan_type":"free"}';
  assert.doesNotThrow(() => parseJson(unique));
  assert.throws(() => parseJson(duplicate), {code: "DUPLICATE_JSON_KEY"});
  // Both are JSON grammar-valid. Uniqueness is a stronger policy than RFC 8259
  // grammar and cannot be inferred just from "the honest server emits JSON".
  assert.equal(JSON.parse(duplicate).plan_type, "free");
});
