import test from "node:test";
import assert from "node:assert/strict";
import { evaluateVerifiedExchange, previewExchange, prepareReplay, planDisclosure, deriveSubjectKey, parseSchema, SchemaError } from "../src/index.ts";
import { requireCompleteCoverage } from "../src/evaluate.ts";
import { fixture, chatgpt, recipient, sample, privateCapture, request, response, exchange, encode, decode } from "./helpers.ts";
import type { Range } from "../src/types.ts";

test("complete authenticated HTTP scope produces only normalized fixture facts", () => {
  const result = evaluateVerifiedExchange(fixture, exchange(), recipient);
  assert.equal(result.subjectKey, "4242");
  assert.equal(result.values.level, 2);
  assert.equal(result.claimable, false);
  assert.equal(result.domain, "schemas.example.test");
  assert.equal(Object.hasOwn(result, "body"), false);
});

test("wrong mode, TLS host, HTTP route, method, host header, status and content type fail", () => {
  const valid = exchange();
  for (const bad of [
    { ...valid, mode: "Mpc" }, { ...valid, serverName: "evil.example.test" },
  ]) assert.throws(() => evaluateVerifiedExchange(fixture, bad as any, recipient), { code: "SCOPE_MISMATCH" });
  const sent = decode(valid.sent.bytes);
  for (const bad of [sent.replace("POST /profile", "GET /profile"), sent.replace("/profile ", "/profile?admin=true "), sent.replace("/profile ", "https://schemas.example.test/profile "), sent.replace("host: schemas.example.test", "host: other.example.test"), sent.replace("connection: close", "x-override: /different")]) {
    assert.throws(() => evaluateVerifiedExchange(fixture, exchange(encode(bad)), recipient), { code: "SCOPE_MISMATCH" });
  }
  for (const status of ["403 Forbidden", "302 Found", "201 Created", "100 Continue"]) {
    assert.throws(() => evaluateVerifiedExchange(fixture, exchange(request(), response(sample, "", status)), recipient), { code: "SCOPE_MISMATCH" });
  }
  for (const type of ["text/html", "application/json; charset=iso-8859-1"]) {
    const recv = encode(decode(response()).replace("application/json; charset=utf-8", type));
    assert.throws(() => evaluateVerifiedExchange(fixture, exchange(request(), recv), recipient), { code: "SCOPE_MISMATCH" });
  }
});

test("JSON ancestry, required types, exact values and thresholds defeat decoy fields", () => {
  const badBodies = [
    { code: "000000", userId: 4242, kycLevel: 2 },
    { ...sample, data: { ...sample.data, userId: "4242" } },
    { ...sample, data: { ...sample.data, userId: 0 } },
    { ...sample, data: { ...sample.data, certificateInfo: { kycLevel: 1 } } },
    { ...sample, code: "prefix000000suffix" },
    '{"code":"000000","data":{"userId":4242,"certificateInfo":{"kycLevel":1,"kycLevel":2}}}',
    { ...sample, data: { ...sample.data, userId: [4242] } },
  ];
  for (const bad of badBodies) assert.throws(() => evaluateVerifiedExchange(fixture, exchange(request(), response(bad)), recipient), SchemaError);
});

test("framing rejects truncation, duplicate lengths, TE+CL, encoding and extra messages", () => {
  const recv = response();
  const text = decode(recv);
  const bad = [
    recv.slice(0, -1), encode(text + "x"), encode(text + text),
    response(sample, "Content-Length: 1\r\n"),
    response(sample, "Transfer-Encoding: chunked\r\n"),
    response(sample, "Content-Encoding: gzip\r\n"),
    response(sample, "Content-Type: application/json\r\n"),
    encode(text.replace("Content-Type:", " Content-Type:")),
    encode(text.replace("\r\n", "\n")),
  ];
  for (const value of bad) assert.throws(() => evaluateVerifiedExchange(fixture, exchange(request(), value), recipient), SchemaError);
});

test("fully authenticated chunked and UTF-8 bodies parse without byte/character confusion", () => {
  const body = encode(JSON.stringify({ ...sample, label: "é😀" }));
  const head = encode("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n");
  const raw = Buffer.concat([head, encode(`${body.length.toString(16)}\r\n`), body, encode("\r\n0\r\n\r\n")]);
  assert.equal(evaluateVerifiedExchange(fixture, exchange(request(), raw), recipient).subjectKey, "4242");
  const split = body.indexOf(0xf0) + 1; // Split the emoji across HTTP chunks.
  const splitBody = Buffer.concat([head, encode(`${split.toString(16)}\r\n`), body.slice(0, split), encode(`\r\n${(body.length - split).toString(16)}\r\n`), body.slice(split), encode("\r\n0\r\n\r\n")]);
  assert.equal(evaluateVerifiedExchange(fixture, exchange(request(), splitBody), recipient).subjectKey, "4242");
  for (const ending of ["\r\n0\r\nX-Trailer: bad\r\n\r\n", "\r\n0\r\n\r\nEXTRA"]) {
    const malformed = Buffer.concat([head, encode(`${body.length.toString(16)}\r\n`), body, encode(ending)]);
    assert.throws(() => evaluateVerifiedExchange(fixture, exchange(request(), malformed), recipient), { code: "INVALID_HTTP" });
  }
  const extension = encode(decode(raw).replace(`${body.length.toString(16)}\r\n`, `${body.length.toString(16)};foo=bar\r\n`));
  assert.throws(() => evaluateVerifiedExchange(fixture, exchange(request(), extension), recipient), { code: "INVALID_HTTP" });
  const invalidUtf8 = response(); invalidUtf8[invalidUtf8.length - 2] = 255;
  assert.throws(() => evaluateVerifiedExchange(fixture, exchange(request(), invalidUtf8), recipient), { code: "INVALID_JSON" });
});

test("authenticated coverage rejects gaps, overlap, reordering, bad bounds and omitted tails", () => {
  const source = exchange();
  const length = source.recv.originalLength;
  const cases: Range[][] = [[], [{ start: 1, end: length }], [{ start: 0, end: length - 1 }], [{ start: 0, end: 10 }, { start: 9, end: length }], [{ start: 10, end: length }, { start: 0, end: 10 }], [{ start: 0, end: length + 1 }], [{ start: 0, end: NaN }]];
  for (const authenticated of cases) assert.throws(() => evaluateVerifiedExchange(fixture, { ...source, recv: { ...source.recv, authenticated } }, recipient), { code: "PARTIAL_TRANSCRIPT" });
  requireCompleteCoverage({ ...source.recv, authenticated: [{ start: 0, end: 10 }, { start: 10, end: length }] }, fixture.limits.maxRecvBytes);
  assert.throws(() => requireCompleteCoverage({ ...source.recv, originalLength: length + 1 }, 10000), { code: "PARTIAL_TRANSCRIPT" });
});

test("capture replays only allowed headers and drops cookies and unrelated browser headers", () => {
  const replay = prepareReplay(chatgpt, privateCapture);
  assert.equal(replay.headers.authorization, "Bearer fixture-secret-never-a-real-token");
  assert.equal(replay.headers.host, "chatgpt.com");
  assert.equal(replay.headers["accept-encoding"], "identity");
  assert.equal(replay.headers.cookie, undefined);
  assert.equal(replay.headers["x-unrelated"], undefined);
  for (const url of [privateCapture.url + "?x=1", privateCapture.url + "#fragment", privateCapture.url.replace("chatgpt.com", "chatgpt.com.evil.test"), privateCapture.url.replace("https:", "http:")]) {
    assert.throws(() => prepareReplay(chatgpt, { ...privateCapture, url }), { code: "INVALID_CAPTURE" });
  }
  for (const headers of [
    privateCapture.headers.filter(header => header.name !== "Authorization"),
    [...privateCapture.headers, { name: "authorization", value: "Bearer duplicate" }],
    privateCapture.headers.map(header => ({ ...header, value: header.name === "Authorization" ? "Bearer token\r\nX-Override: true" : header.value })),
  ]) assert.throws(() => prepareReplay(chatgpt, { ...privateCapture, headers }), { code: "INVALID_CAPTURE" });
});

test("client disclosure keeps credential/header secrets hidden and the JSON body complete", () => {
  const sent = request(chatgpt);
  const recv = response({ plan_type: "Pro", label: "😀" }, "Set-Cookie: response_token=private\r\n");
  const disclosure = planDisclosure(chatgpt, sent, recv, recipient);
  const project = (bytes: Uint8Array, ranges: readonly Range[]) => ranges.map(range => decode(bytes.slice(range.start, range.end))).join("");
  const visibleSent = project(sent, disclosure.sent);
  const visibleRecv = project(recv, disclosure.recv);
  assert.equal(visibleSent.includes("fixture-secret"), false);
  assert.equal(visibleSent.includes("fingerprint"), false);
  assert.equal(visibleRecv.includes("response_token=private"), false);
  assert.ok(visibleRecv.endsWith('{"plan_type":"Pro","label":"😀"}'));
  assert.equal(disclosure.requiresUserConsent, true);
  assert.equal(disclosure.preview.claimable, false);
});

test("fixed request body and duplicate request headers cannot change the schema scope", () => {
  const sent = decode(request());
  for (const body of ['{"extra":true}', '{"x":1,"x":2}', '[]']) {
    const changed = encode(sent.replace("content-length: 2", `content-length: ${encode(body).length}`).slice(0, -2) + body);
    assert.throws(() => evaluateVerifiedExchange(fixture, exchange(changed), recipient), SchemaError);
  }
  const duplicate = encode(sent.replace("connection: close\r\n", "connection: close\r\nConnection: keep-alive\r\n"));
  assert.throws(() => evaluateVerifiedExchange(fixture, exchange(duplicate), recipient), { code: "INVALID_HTTP" });
});

test("explicit cookie policy keeps only named cookies and never enables backend acceptance", () => {
  const schema = parseSchema({ ...fixture, capture: { ...fixture.capture, cookies: ["session"] } });
  const capture = { url: "https://schemas.example.test/profile", method: "POST", headers: [{ name: "Cookie", value: "other=drop; session=synthetic-value; unrelated=drop" }], body: "{}" };
  assert.equal(prepareReplay(schema, capture).headers.cookie, "session=synthetic-value");
  const sent = request(schema, capture);
  const disclosure = planDisclosure(schema, sent, response(), recipient);
  assert.equal(disclosure.sent.map(range => decode(sent.slice(range.start, range.end))).join("").includes("synthetic-value"), false);
  assert.throws(() => prepareReplay(schema, { ...capture, headers: [{ name: "Cookie", value: "session=one; session=two" }] }), { code: "INVALID_CAPTURE" });
  assert.throws(() => evaluateVerifiedExchange(schema, exchange(sent, response(), schema), recipient), { code: "PRIVATE_REQUEST_UNSUPPORTED" });
});

test("ChatGPT plan identity preserves the exact legacy plan and lowercase recipient", () => {
  for (const plan of ["free", "plus", "pro", "Pro", "enterprise", "team_2026", "a-b"]) {
    const preview = previewExchange(chatgpt, request(chatgpt), response({ plan_type: plan }), recipient);
    assert.equal(preview.subjectKey, `${plan}:${recipient.toLowerCase()}`);
    assert.equal(preview.identityVersion, "legacy-plan-wallet-v1");
    assert.equal(preview.claimable, false);
  }
  for (const plan of ["", " plus", '"pro"', 42, null, ["pro"], "a".repeat(65), "🦄"]) {
    assert.throws(() => previewExchange(chatgpt, request(chatgpt), response({ plan_type: plan }), recipient), SchemaError);
  }
  assert.throws(() => deriveSubjectKey(chatgpt, "pro", "not-a-wallet"), { code: "INVALID_RECIPIENT" });
});

test("redacted HTTP values cannot certify absence of hidden control characters", () => {
  const valid = request(chatgpt);
  const text = decode(valid);
  const secret = "Bearer fixture-secret-never-a-real-token";
  const offset = text.indexOf(secret);
  const attack = "Bearer x\r\nX-Override: injected".padEnd(secret.length, " ");
  assert.equal(attack.length, secret.length);
  const malicious = encode(text.slice(0, offset) + attack + text.slice(offset + secret.length));
  const redacted = (bytes: Uint8Array) => { const result = bytes.slice(); result.fill(0, offset, offset + secret.length); return result; };
  // Both transcripts have precisely the same disclosed bytes and length. No parser
  // operating only on those bytes can tell the extra header from a normal token.
  assert.deepEqual(redacted(valid), redacted(malicious));
  const original = exchange(valid, response({ plan_type: "pro" }), chatgpt);
  const authenticated = [{ start: 0, end: offset }, { start: offset + secret.length, end: valid.length }];
  assert.throws(() => evaluateVerifiedExchange(chatgpt, { ...original, sent: { ...original.sent, bytes: redacted(valid), authenticated } }, recipient), { code: "PRIVATE_REQUEST_UNSUPPORTED" });
  // User-Agent is also designated private but disclosed in this fixture.
  // Revealing the credential is explicitly not offered as a fallback.
  assert.throws(() => evaluateVerifiedExchange(chatgpt, original, recipient), { code: "PRIVATE_REQUEST_UNSUPPORTED" });
});

test("client field labels and redacted response fragments never replace authenticated JSON", () => {
  const source = exchange();
  const needle = encode('"kycLevel":2');
  const start = decode(source.recv.bytes).indexOf(decode(needle));
  const labelled = { ...source, recv: { ...source.recv, authenticated: [{ start, end: start + needle.length }] }, handler: { path: "/data/certificateInfo/kycLevel", value: 999 } };
  assert.throws(() => evaluateVerifiedExchange(fixture, labelled, recipient), { code: "PARTIAL_TRANSCRIPT" });
  assert.equal(evaluateVerifiedExchange(fixture, { ...source, handler: { value: 999 } } as typeof source, recipient).values.level, 2);
});

test("typed membership, array lengths and upper bounds fail without coercion", () => {
  const schema = parseSchema({ ...fixture, fields: [...fixture.fields, { id: "items", pointer: "/items", type: "array" }], checks: [...fixture.checks, { op: "in", field: "code", values: ["000000", "OK"] }, { op: "array-length-gte", field: "items", value: 2 }, { op: "lte", field: "level", value: 3 }] });
  assert.equal(evaluateVerifiedExchange(schema, exchange(request(schema), response({ ...sample, items: ["a", "b"] }), schema), recipient).values.level, 2);
  assert.throws(() => evaluateVerifiedExchange(schema, exchange(request(schema), response({ ...sample, items: "ab" }), schema), recipient), { code: "INVALID_FIELD" });
  assert.throws(() => evaluateVerifiedExchange(schema, exchange(request(schema), response({ ...sample, items: ["a"] }), schema), recipient), { code: "CHECK_FAILED" });
});

test("limits and errors do not echo provider contents or credentials", () => {
  const sensitive = "PRIVATE-CANARY-DO-NOT-LOG";
  let error: unknown;
  try { previewExchange(chatgpt, request(chatgpt), response(`{"plan_type":"${sensitive}","plan_type":"other"}`), recipient); }
  catch (caught) { error = caught; }
  assert.ok(error instanceof SchemaError);
  assert.equal(String(error).includes(sensitive), false);
  const oversized = new Uint8Array(fixture.limits.maxRecvBytes + 1);
  assert.throws(() => evaluateVerifiedExchange(fixture, exchange(request(), oversized), recipient), { code: "LIMIT_EXCEEDED" });
});
