import { requireThat, reject } from "./errors.ts";
import { canonicalJson, pointerTokens } from "./json.ts";
import type { Check, Field } from "./types.ts";

export type LegacyBinding = Readonly<{ windowId: number; key: string; field: Field }>;

// Converts the old declarative checks only. The caller must supply reviewed HTTP
// scope, full JSON pointers, field types and lifecycle; no provider is activated.
export function importLegacyChecks(input: unknown, bindings: readonly LegacyBinding[], expectedHost: string) {
  const source = JSON.parse(canonicalJson(input)) as Record<string, unknown>;
  requireThat(source && !Array.isArray(source) && typeof source.id === "string" && source.host === expectedHost && Array.isArray(source.checks), "UNSUPPORTED_LEGACY_CHECK");
  requireThat(Object.keys(source).sort().join(",") === "checks,host,id,user_id", "UNSUPPORTED_LEGACY_CHECK");
  const byWindow = new Map<number, LegacyBinding>();
  const fieldIds = new Set<string>();
  for (const binding of bindings) {
    requireThat(Number.isSafeInteger(binding.windowId) && binding.windowId >= 0 && !byWindow.has(binding.windowId) && !fieldIds.has(binding.field.id), "UNSUPPORTED_LEGACY_CHECK");
    requireThat(pointerTokens(binding.field.pointer).at(-1) === binding.key, "UNSUPPORTED_LEGACY_CHECK");
    byWindow.set(binding.windowId, binding); fieldIds.add(binding.field.id);
  }
  const used = new Set<number>();
  const checks: Check[] = [];
  function convert(value: unknown, identity = false): string {
    requireThat(value !== null && typeof value === "object" && !Array.isArray(value), "UNSUPPORTED_LEGACY_CHECK");
    const item = value as Record<string, unknown>;
    requireThat(item.window !== null && typeof item.window === "object" && !Array.isArray(item.window), "UNSUPPORTED_LEGACY_CHECK");
    const window = item.window as Record<string, unknown>;
    requireThat(Object.keys(window).sort().join(",") === "id,key" && Number.isSafeInteger(window.id), "UNSUPPORTED_LEGACY_CHECK");
    const binding = byWindow.get(Number(window.id));
    requireThat(binding && binding.key === window.key, "UNSUPPORTED_LEGACY_CHECK");
    used.add(binding.windowId);
    if (item.type === "any") {
      requireThat(Object.keys(item).sort().join(",") === "type,window", "UNSUPPORTED_LEGACY_CHECK");
      if (identity) requireThat(binding.field.type === "string" || binding.field.type === "safe-integer", "UNSUPPORTED_LEGACY_CHECK");
      return binding.field.id;
    }
    requireThat(!identity && Object.keys(item).sort().join(",") === "type,value,window" && Number.isSafeInteger(item.value), "UNSUPPORTED_LEGACY_CHECK");
    if (item.type === "len_gte") {
      requireThat(binding.field.type === "array" && Number(item.value) >= 0, "UNSUPPORTED_LEGACY_CHECK");
      checks.push({ op: "array-length-gte", field: binding.field.id, value: Number(item.value) });
    } else if (item.type === "gte" || item.type === "lte" || item.type === "eq") {
      requireThat(binding.field.type === "safe-integer", "UNSUPPORTED_LEGACY_CHECK");
      checks.push({ op: item.type, field: binding.field.id, value: Number(item.value) });
    } else reject("UNSUPPORTED_LEGACY_CHECK");
    return binding.field.id;
  }
  const identityField = convert(source.user_id, true);
  for (const check of source.checks) convert(check);
  requireThat(used.size === bindings.length, "UNSUPPORTED_LEGACY_CHECK");
  return { legacyId: source.id, identityField, fields: bindings.map(binding => ({ ...binding.field })), checks };
}
