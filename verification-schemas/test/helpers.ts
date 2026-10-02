import { prepareReplay, loadRegistry } from "../src/index.ts";
import { requestTarget } from "../src/schema.ts";
import type { CapturedRequest, VerificationSchema, VerifiedExchange } from "../src/types.ts";

export const registry = await loadRegistry();
export const chatgpt = registry.list().find(entry => entry.schema.providerId === "CHATGPT-SUBSCRIPTION")!.schema;
export const fixture = registry.list().find(entry => entry.schema.lifecycle === "fixture")!.schema;
export const recipient = "0xABCDEF1234567890ABCDEF1234567890ABCDEF12";
export const encode = (value: string) => new TextEncoder().encode(value);
export const decode = (value: Uint8Array) => new TextDecoder().decode(value);
export const sample = { code: "000000", data: { userId: 4242, certificateInfo: { kycLevel: 2 } } };
export const privateCapture: CapturedRequest = {
  url: "https://chatgpt.com/backend-api/wham/usage",
  method: "GET",
  headers: [
    { name: "Authorization", value: "Bearer fixture-secret-never-a-real-token" },
    { name: "User-Agent", value: "Synthetic private browser fingerprint" },
    { name: "Cookie", value: "ignored_cookie=secret" },
    { name: "X-Unrelated", value: "must-not-replay" },
  ],
};
export function request(schema = fixture, capture?: CapturedRequest): Uint8Array {
  const replay = prepareReplay(schema, capture ?? (schema.schemaId === chatgpt.schemaId ? privateCapture : {
    url: schema.request.origin + requestTarget(schema), method: schema.request.method, headers: [], body: schema.request.body.kind === "empty" ? "" : JSON.stringify(schema.request.body.value),
  }));
  return encode(`${replay.method} ${requestTarget(schema)} HTTP/1.1\r\n${Object.entries(replay.headers).map(([name, value]) => `${name}: ${value}\r\n`).join("")}\r\n${replay.body}`);
}
export function response(body: unknown = sample, extraHeaders = "", status = "200 OK"): Uint8Array {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return encode(`HTTP/1.1 ${status}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: ${encode(text).length}\r\n${extraHeaders}\r\n${text}`);
}
export function exchange(sent = request(), recv = response(), schema: VerificationSchema = fixture): VerifiedExchange {
  return {
    mode: "Proxy", serverName: new URL(schema.request.origin).hostname,
    sent: { bytes: sent, originalLength: sent.length, authenticated: [{ start: 0, end: sent.length }] },
    recv: { bytes: recv, originalLength: recv.length, authenticated: [{ start: 0, end: recv.length }] },
  };
}
