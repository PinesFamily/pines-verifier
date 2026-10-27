import { reject, requireThat } from "./errors.ts";
import type { Json } from "./types.ts";

export function validUnicode(value: string): boolean {
  // In Unicode mode, valid surrogate pairs form one code point outside this range.
  return !/[\uD800-\uDFFF]/u.test(value);
}

// Compare decimal values without first rounding through an IEEE-754 number.
// This rejects e.g. 1.00000000000000001 being silently interpreted as 1.
function decimal(value: string): string {
  const match = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(value);
  requireThat(match, "INVALID_JSON");
  const fraction = match[3] ?? "";
  let digits = (match[2]! + fraction).replace(/^0+/, "");
  if (digits === "") return "0";
  let exponent = Number(match[4] ?? 0) - fraction.length;
  requireThat(Number.isSafeInteger(exponent), "UNSAFE_JSON_NUMBER");
  while (digits.endsWith("0")) { digits = digits.slice(0, -1); exponent++; }
  return `${match[1]}${digits}e${exponent}`;
}

// A bounded recursive-descent parser: JSON.parse alone loses duplicate keys.
// All errors are fixed messages, never parser excerpts containing provider data.
export function parseJson(text: string, maxDepth = 32): Json {
  requireThat(Number.isSafeInteger(maxDepth) && maxDepth > 0 && maxDepth <= 128, "INVALID_JSON");
  let pos = 0;
  let nodes = 0;
  const ws = () => { while (/[\x20\t\r\n]/.test(text[pos] ?? "x")) pos++; };
  function string(): string {
    requireThat(text[pos] === '"', "INVALID_JSON");
    const start = pos++;
    while (pos < text.length) {
      const character = text[pos++]!;
      if (character === '"') {
        let value: unknown;
        try { value = JSON.parse(text.slice(start, pos)); } catch { reject("INVALID_JSON"); }
        requireThat(typeof value === "string" && validUnicode(value), "INVALID_JSON");
        return value;
      }
      requireThat(character.charCodeAt(0) >= 32, "INVALID_JSON");
      if (character === "\\") {
        const escape = text[pos++];
        requireThat(escape !== undefined && '"\\/bfnrtu'.includes(escape), "INVALID_JSON");
        if (escape === "u") {
          requireThat(/^[a-f\d]{4}$/i.test(text.slice(pos, pos + 4)), "INVALID_JSON");
          pos += 4;
        }
      }
    }
    return reject("INVALID_JSON");
  }
  function value(depth: number): Json {
    requireThat(depth <= maxDepth && ++nodes <= 100_000, "LIMIT_EXCEEDED");
    ws();
    const first = text[pos];
    if (first === '"') return string();
    if (first === "{" || first === "[") {
      const object = first === "{";
      const end = object ? "}" : "]";
      const result: Json[] | Record<string, Json> = object ? Object.create(null) : [];
      pos++; ws();
      if (text[pos] === end) { pos++; return result; }
      for (;;) {
        ws();
        if (object) {
          const key = string(); ws();
          requireThat(text[pos++] === ":", "INVALID_JSON");
          requireThat(!Object.hasOwn(result, key), "DUPLICATE_JSON_KEY");
          (result as Record<string, Json>)[key] = value(depth + 1);
        } else (result as Json[]).push(value(depth + 1));
        ws();
        const delimiter = text[pos++];
        if (delimiter === end) return result;
        requireThat(delimiter === ",", "INVALID_JSON");
      }
    }
    for (const [literal, parsed] of [["true", true], ["false", false], ["null", null]] as const) {
      if (text.startsWith(literal, pos)) { pos += literal.length; return parsed; }
    }
    const token = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(pos))?.[0];
    requireThat(token !== undefined && token.length <= 128, "INVALID_JSON");
    pos += token.length;
    const number = Number(token);
    requireThat(Number.isFinite(number) && (!Number.isInteger(number) || Number.isSafeInteger(number)), "UNSAFE_JSON_NUMBER");
    requireThat(decimal(token) === decimal(String(number)), "UNSAFE_JSON_NUMBER");
    return number;
  }
  const result = value(0); ws();
  requireThat(pos === text.length, "INVALID_JSON");
  return result;
}

export function canonicalJson(value: unknown, depth = 0): string {
  requireThat(depth <= 128, "INVALID_SCHEMA");
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") {
    requireThat(validUnicode(value), "INVALID_SCHEMA");
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    requireThat(Number.isFinite(value) && (!Number.isInteger(value) || Number.isSafeInteger(value)), "INVALID_SCHEMA");
    return JSON.stringify(value);
  }
  requireThat(typeof value === "object" && value !== null, "INVALID_SCHEMA");
  if (Array.isArray(value)) {
    requireThat(Object.keys(value).length === value.length, "INVALID_SCHEMA");
    for (let i = 0; i < value.length; i++) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(i));
      requireThat(descriptor && "value" in descriptor, "INVALID_SCHEMA");
    }
    return `[${value.map(item => canonicalJson(item, depth + 1)).join(",")}]`;
  }
  requireThat(Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null, "INVALID_SCHEMA");
  requireThat(Object.getOwnPropertySymbols(value).length === 0, "INVALID_SCHEMA");
  const keys = Object.keys(value).sort();
  return `{${keys.map(key => {
    const property = Object.getOwnPropertyDescriptor(value, key)!;
    requireThat("value" in property && validUnicode(key), "INVALID_SCHEMA");
    return `${JSON.stringify(key)}:${canonicalJson(property.value, depth + 1)}`;
  }).join(",")}}`;
}

export function pointerTokens(pointer: string): string[] {
  requireThat(pointer === "" || (pointer.startsWith("/") && !/~(?:[^01]|$)/.test(pointer)), "INVALID_SCHEMA");
  return pointer === "" ? [] : pointer.slice(1).split("/").map(token => token.replace(/~1/g, "/").replace(/~0/g, "~"));
}

export function selectJson(root: Json, pointer: string): Json {
  let current = root;
  for (const token of pointerTokens(pointer)) {
    requireThat(current !== null && typeof current === "object", "MISSING_FIELD");
    if (Array.isArray(current)) requireThat(/^(?:0|[1-9]\d*)$/.test(token), "MISSING_FIELD");
    requireThat(Object.hasOwn(current, token), "MISSING_FIELD");
    current = (current as Record<string, Json>)[token]!;
  }
  return current;
}
