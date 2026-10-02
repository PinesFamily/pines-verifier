import chatgpt from "../schemas/chatgpt-plan.v1.json" with { type: "json" };
import chatgptClaims from "../schemas/chatgpt-plan.v2.json" with { type: "json" };
import chatgptIdentity from "../schemas/chatgpt-plan.v3.json" with { type: "json" };
import claude from "../schemas/claude-plan.v1.json" with { type: "json" };
import grok from "../schemas/grok-plan.v1.json" with { type: "json" };
import fixture from "../schemas/bringid-simple-fixture.v1.json" with { type: "json" };
import publicFixture from "../schemas/httpbingo-fixture.v1.json" with { type: "json" };
import privateFixture from "../schemas/httpbingo-private-fixture.v1.json" with { type: "json" };
import benchFixture from "../schemas/bench-fixture.v1.json" with { type: "json" };
import references from "../schemas/manifest.json" with { type: "json" };
import { parseSchema, schemaDigest } from "./schema.ts";
import { requireThat } from "./errors.ts";
import type { SchemaReference, VerificationSchema } from "./types.ts";

export const schemaSources: readonly unknown[] = Object.freeze([chatgpt, fixture, publicFixture, privateFixture, chatgptClaims, chatgptIdentity, claude, grok, benchFixture]);

export async function createRegistry(sources: readonly unknown[], pins: readonly SchemaReference[]) {
  const schemas = new Map<string, Readonly<{ schema: VerificationSchema; reference: SchemaReference }>>();
  requireThat(sources.length === pins.length && sources.length <= 128, "INVALID_SCHEMA");
  const seenPins = new Set<string>();
  for (const pin of pins) {
    requireThat(typeof pin.schemaId === "string" && Number.isSafeInteger(pin.version) && /^sha256:[a-f0-9]{64}$/.test(pin.digest), "INVALID_SCHEMA");
    const key = `${pin.schemaId}@${pin.version}`;
    requireThat(!seenPins.has(key), "INVALID_SCHEMA"); seenPins.add(key);
  }
  for (const input of sources) {
    const schema = parseSchema(input);
    const key = `${schema.schemaId}@${schema.version}`;
    requireThat(!schemas.has(key), "INVALID_SCHEMA");
    const pin = pins.find(pin => pin.schemaId === schema.schemaId && pin.version === schema.version);
    requireThat(pin && pin.digest === await schemaDigest(schema), "SCHEMA_DIGEST_MISMATCH");
    schemas.set(key, Object.freeze({ schema, reference: Object.freeze({ ...pin }) }));
  }
  return Object.freeze({
    list: () => Object.freeze([...schemas.values()]),
    resolve(reference: SchemaReference) {
      const entry = schemas.get(`${reference.schemaId}@${reference.version}`);
      requireThat(entry, "UNKNOWN_SCHEMA");
      requireThat(entry.reference.digest === reference.digest, "SCHEMA_DIGEST_MISMATCH");
      return entry.schema;
    },
  });
}

export function loadRegistry() { return createRegistry(schemaSources, references); }
