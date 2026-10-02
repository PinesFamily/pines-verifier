# Verification schemas

Versioned provider policy for Pines' TLSNotary verification. It has no runtime dependencies and runs in Node 22 and
Chromium. The extension compiles it into its package; the Pines API validates verified transcripts with the same
schemas. It neither performs a TLSN proof nor authorizes a claim on its own.

| Schema | Purpose |
|---|---|
| `pines.chatgpt.plan@3` | ChatGPT: a stable user ID and explicit paid tiers, bound to a wallet |
| `pines.chatgpt.plan@2`, `@1` | Earlier ChatGPT plan schemas, kept while receipts reference them |
| `pines.claude.plan@1` | Claude: a paid personal organization (Pro or Max) |
| `pines.grok.plan@1` | Grok: an active SuperGrok or X Premium+ subscription |
| `pines.fixture.httpbingo@1` | Public fixture: `GET https://httpbingo.org/json`, no account |
| `pines.fixture.httpbingo-private@1` | The same public endpoint with a natively redacted synthetic Bearer value |
| `pines.fixture.bringid-simple@1` | Synthetic numeric and identity checks at explicit JSON paths on `schemas.example.test` |
| `pines.fixture.bench@1` | A benchmark fixture for verifier load tests |

## Registry and use

`loadRegistry()` validates the JSON schemas, computes their canonical SHA-256 digests, checks
[manifest.json](schemas/manifest.json), and freezes the policy. Resolve a schema by the complete
`{schemaId, version, digest}` reference. Unknown versions or changed content fail. Once published, a version's content
and digest are immutable: add a new version and keep old versions while attempts and receipts reference them. The
digest is a content pin, not a signature. Canonicalization sorts object keys by UTF-16 code units, preserves array
order and uses ECMAScript JSON number/string serialization after rejecting unsupported values.

```ts
import { loadRegistry, prepareReplay } from "./src/index.ts";

const registry = await loadRegistry();
const schema = registry.resolve(serverOwnedAttempt.schema);
const replay = prepareReplay(schema, capturedRequest);
```

The browser and the API must use the same pinned schema. Request origin/method/path/query, fixed JSON body, credential
allowlists, limits, extraction paths, checks and identity version all contribute to its digest. Handlers and replay
transforms are named, reviewed code in the package; pages cannot upload expressions or executable plugins.

`prepareReplay()` requires an exact captured route, copies only configured headers and cookies, and constructs the
fixed request. It sets `Host`, `Accept-Encoding: identity`, `Connection: close`, and an exact POST content length.
Keep captured credentials and replay headers in extension memory; never send them to the page, persist them, or
include them in errors or telemetry.

`previewExchange()` checks the browser's full transcript for feedback. `planDisclosure()` hides configured private
header values and response `Set-Cookie` values, retains the full JSON body, and requires explicit user consent to
disclosure. These are client helpers; their output is not authoritative evidence.

## Authoritative validation and native disclosure

`evaluateVerifiedExchange()` accepts only verifier-authenticated bytes, the actual TLS hostname and mode, and
authenticated ranges bound to a server-owned attempt and schema. The TypeScript input type alone does not authenticate
evidence.

Public requests require complete authenticated coverage. Schemas with private headers use `inspectDisclosedRequest()`
to check the disclosed request line, fixed header values, header names and delimiters, required headers and empty
body. Native redactions must cover entire secret values, with zeroed hidden bytes and consistent coverage. Disclosing
credentials as a fallback is rejected. The complete authenticated JSON body supplies independently parsed facts.
`inspectDisclosedResponse()` permits entire, zero-masked `Set-Cookie` values while requiring authenticated status,
public headers, delimiters, body and chunk framing.

Hidden contents remain opaque: TLSN selective disclosure does not establish their syntax. The synthetic
control-character regression records that limitation. There are no custom circuits, commitments or additional proof
systems. `test/selective-disclosure-soundness.test.ts` shows why JSON gaps inside the response body cannot
authenticate their own boundaries, so the whole body stays disclosed.

The narrow parser accepts HTTP/1.1 200 JSON responses with exact `Content-Length` or complete chunked framing. It
rejects duplicate framing/type headers, folded headers, TE plus CL, extra or truncated messages, compression, chunk
extensions/trailers and close-delimited responses ([RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html)). JSON uses
fatal UTF-8 decoding, bounded depth and nodes, duplicate-key detection after unescaping, valid Unicode and number round
trips without decimal precision loss ([RFC 8259](https://www.rfc-editor.org/rfc/rfc8259.html)). Selectors follow
complete JSON Pointer ancestry and own properties. Predicates are typed; there is no implicit string/number coercion.

## BringID checks

`importLegacyChecks()` converts BringID's `gte`, `lte`, numeric `eq`, `len_gte` and typed `any`/identity selections.
Each positional window ID/key requires an explicit reviewed JSON Pointer and field type. It rejects substring
`contains`, unrestricted `custom`, disabled key checks and unknown policies. Importing checks never activates a
provider. See [source provenance](PROVENANCE.md).

## Tests

From the repository root:

```
npm test
npm run registry:check
```

All credentials and data in the tests are synthetic.
