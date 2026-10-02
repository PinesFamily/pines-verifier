import { schemaSources, loadRegistry } from "../src/registry.ts";
import { parseSchema, schemaDigest } from "../src/schema.ts";

if (process.argv.includes("--print")) {
  const references = [];
  for (const source of schemaSources) {
    const schema = parseSchema(source);
    references.push({ schemaId: schema.schemaId, version: schema.version, digest: await schemaDigest(schema) });
  }
  console.log(JSON.stringify(references, null, 2));
} else {
  const registry = await loadRegistry();
  console.log(`Verified ${registry.list().length} immutable schema digests`);
}
