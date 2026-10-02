import test from "node:test";
import assert from "node:assert/strict";
import {evaluateVerifiedExchange, planDisclosure, SchemaError} from "../src/index.ts";
import {chatgpt, recipient, request, response, exchange, encode, decode} from "./helpers.ts";
import type {Range} from "../src/types.ts";

const project = (bytes: Uint8Array, authenticated: readonly Range[]) => {
  const visible = new Uint8Array(bytes.length);
  for (const range of authenticated) visible.set(bytes.subarray(range.start, range.end), range.start);
  return {bytes: visible, originalLength: bytes.length, authenticated};
};
function evidence(recv = response({plan_type: "pro"}, "Set-Cookie: secret-cookie-canary; HttpOnly\r\nSet-Cookie: another-cookie-canary\r\n")) {
  const sent = request(chatgpt), ranges = planDisclosure(chatgpt, sent, recv, recipient);
  return {original: recv, value: {...exchange(sent, recv, chatgpt), sent: project(sent, ranges.sent), recv: project(recv, ranges.recv)}};
}
test("native cookie redactions preserve complete JSON facts without storing cookies", () => {
  const f = evidence();
  const facts = evaluateVerifiedExchange(chatgpt, f.value, recipient);
  assert.equal(facts.subjectKey, `pro:${recipient.toLowerCase()}`);
  assert.equal(facts.claimable, false);
  assert.equal(JSON.stringify(facts).includes("cookie-canary"), false);
  const body = '{"plan_type":"pro","label":"😀"}', encoded = encode(body);
  const chunked = encode(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: private\r\nTransfer-Encoding: chunked\r\n\r\n${encoded.length.toString(16)}\r\n${body}\r\n0\r\n\r\n`);
  assert.equal(evaluateVerifiedExchange(chatgpt, evidence(chunked).value, recipient).values.plan_type, "pro");
});
test("response status, header structure, framing and JSON gaps are rejected", () => {
  const f = evidence(), text = decode(f.original);
  for (const at of [0, text.indexOf("200"), text.indexOf("Content-Type"), text.indexOf("application/json"),
    text.indexOf("Content-Length"), text.indexOf("Set-Cookie"), text.indexOf(": ", text.indexOf("Set-Cookie")),
    text.indexOf("\r\n", text.indexOf("Set-Cookie")), text.indexOf("\r\n\r\n") + 2, text.indexOf('"plan_type"'), text.length - 1]) {
    assert(at >= 0);
    const ranges = f.value.recv.authenticated.flatMap(range => at < range.start || at >= range.end ? [range] : [
      ...(at > range.start ? [{start: range.start, end: at}] : []),
      ...(at + 1 < range.end ? [{start: at + 1, end: range.end}] : []),
    ]);
    assert.throws(() => evaluateVerifiedExchange(chatgpt, {...f.value, recv: project(f.original, ranges)}, recipient), SchemaError);
  }
});
test("public, partially hidden and nonzero masked cookie values cannot pass", () => {
  const f = evidence(), hiddenStart = f.value.recv.authenticated[0]!.end;
  assert.throws(() => evaluateVerifiedExchange(chatgpt, {...f.value, recv: project(f.original, [{start: 0, end: f.original.length}])}, recipient), {code: "PRIVATE_REQUEST_UNSUPPORTED"});
  const partiallyHidden = f.value.recv.authenticated.map((range, i) => i === 0 ? {...range, end: range.end + 1} : range);
  assert.throws(() => evaluateVerifiedExchange(chatgpt, {...f.value, recv: project(f.original, partiallyHidden)}, recipient), SchemaError);
  const unmasked = {...f.value.recv, bytes: f.value.recv.bytes.slice()}; unmasked.bytes[hiddenStart] = 65;
  assert.throws(() => evaluateVerifiedExchange(chatgpt, {...f.value, recv: unmasked}, recipient), {code: "PARTIAL_TRANSCRIPT"});
});
