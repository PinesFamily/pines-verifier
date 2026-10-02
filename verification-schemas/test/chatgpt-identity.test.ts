import test from "node:test";
import assert from "node:assert/strict";
import {evaluateVerifiedExchange, planDisclosure, previewExchange} from "../src/index.ts";
import {registry, request, response, recipient} from "./helpers.ts";

const schema = registry.list().find(e => e.reference.schemaId === "pines.chatgpt.plan" && e.reference.version === 3)!.schema;
const user = "user-" + "Ab9".repeat(8);
const otherWallet = "0x" + "23".repeat(20);
const read = (body: unknown, wallet = recipient) => previewExchange(schema, request(schema), response(body), wallet);

test("one authenticated user is stable across wallets, tiers and workspace selection", () => {
  for (const wallet of [recipient, otherWallet]) for (const plan of ["plus", "pro", "prolite"]) {
    for (const account_id of ["", "workspace-one", "workspace-two"]) {
      const result = read({user_id: user, plan_type: plan, account_id}, wallet);
      assert.equal(result.subjectKey, user);
      assert.equal(result.identityVersion, "chatgpt-user-v1");
      assert.equal(result.claimable, false);
    }
  }
  assert.notEqual(read({user_id: user, plan_type: "pro"}).subjectKey,
    read({user_id: "user-" + "b".repeat(24), plan_type: "pro"}).subjectKey);
});

test("missing or ambiguous identity and free or unknown tiers fail closed", () => {
  for (const user_id of [undefined, "", " ", 42, null, "USER-" + "a".repeat(24), user + " ", user + "\n", "a@example.test", "workspace-one", "user-a", "user-" + "а".repeat(24)]) {
    assert.throws(() => read({plan_type: "pro", user_id}));
  }
  for (const plan_type of [undefined, "", "free", "Free", "PLUS", "pro ", "business", "team", "enterprise", "invented-paid-plan", null]) {
    assert.throws(() => read({user_id: user, plan_type}));
  }
  assert.throws(() => read({plan_type: "pro", nested: {user_id: user}}));
  assert.throws(() => read({user_id: user, nested: {plan_type: "pro"}}));
  assert.throws(() => read(`{"user_id":"${user}","user_id":"other","plan_type":"pro"}`), {code: "DUPLICATE_JSON_KEY"});
  assert.throws(() => read(`{"user_id":"${user}","plan_type":"free","plan_type":"pro"}`), {code: "DUPLICATE_JSON_KEY"});
});

test("native disclosure authenticates both fields while hiding credentials and response cookies", () => {
  const sent = request(schema), recv = response({user_id: user, plan_type: "pro"}, "Set-Cookie: private-canary\r\n");
  const ranges = planDisclosure(schema, sent, recv, recipient);
  const redact = (bytes: Uint8Array, authenticated: readonly {start: number; end: number}[]) => {
    const visible = new Uint8Array(bytes.length);
    for (const r of authenticated) visible.set(bytes.subarray(r.start, r.end), r.start);
    return {bytes: visible, originalLength: bytes.length, authenticated};
  };
  const exchange = {mode: "Proxy" as const, serverName: "chatgpt.com", sent: redact(sent, ranges.sent), recv: redact(recv, ranges.recv)};
  assert.equal(evaluateVerifiedExchange(schema, exchange, recipient).subjectKey, user);
  assert(!new TextDecoder().decode(exchange.sent.bytes).includes("fixture-secret"));
  assert(!new TextDecoder().decode(exchange.recv.bytes).includes("private-canary"));
  const gap = Buffer.from(recv).indexOf(user);
  const incomplete = ranges.recv.flatMap(r => gap >= r.start && gap < r.end
    ? [{start: r.start, end: gap}, {start: gap + user.length, end: r.end}].filter(r => r.end > r.start) : [r]);
  assert.throws(() => evaluateVerifiedExchange(schema, {...exchange, recv: redact(recv, incomplete)}, recipient));
});
