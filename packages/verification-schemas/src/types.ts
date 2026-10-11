export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type Scalar = null | boolean | number | string;
export type Field = Readonly<{
  id: string;
  pointer: string;
  type: "string" | "safe-integer" | "boolean" | "array";
}>;
export type Check =
  | Readonly<{ op: "eq"; field: string; value: Scalar }>
  | Readonly<{ op: "in"; field: string; values: readonly Scalar[] }>
  | Readonly<{ op: "gte" | "lte" | "array-length-gte"; field: string; value: number }>
  | Readonly<{ op: "custom"; field: string; handler: CustomHandler }>;
export type CustomHandler =
  | "chatgpt-plan-v1" | "chatgpt-user-id-v1" | "non-empty-string-v1"
  | "claude-org-uuid-v1" | "claude-paid-tier-v1" | "claude-paid-capabilities-v1"
  | "grok-user-uuid-v1" | "grok-paid-tier-v1";
// Which document the fields are read from. Absent: the response root, which must be an object.
// `maxItems` is optional so every selector pinned before it existed keeps its exact digest.
export type Selector =
  | Readonly<{ kind: "claude-paid-personal-org-v1" }>
  // The per-org route answers one organization, so the list's "exactly one qualifies"
  // ambiguity check cannot apply; the same predicate judges that single object.
  | Readonly<{ kind: "claude-paid-personal-org-single-v1" }>
  | Readonly<{ kind: "grok-paid-subscription-v1"; maxItems?: number }>;

// A declared path parameter. The value is authenticated in the request start line and
// must equal the selected document's `bindsTo` pointer, so a prover cannot prove one
// organization's request against another organization's response.
export type PathParam = Readonly<{ kind: "lowercase-uuid-v1"; bindsTo: string }>;
export type PathParams = Readonly<Record<string, PathParam>>;

// Response-header privacy. Only the framing values stay public; every other header
// value is one complete hidden range. Header NAMES stay public and stay allowlisted.
export type ResponsePrivacy = Readonly<{
  mode: "private-headers-v1";
  visibleHeaders: readonly ["content-type", "content-length", "transfer-encoding", "content-encoding"];
  encodings: readonly ("gzip" | "identity")[];
}>;
export type ResponseDisclosureMode = "selective" | "complete" | "private-headers";

export type VerificationSchema = Readonly<{
  format: "pines-verification-schema-v1";
  schemaId: string;
  version: number;
  providerId: string;
  lifecycle: "fixture" | "candidate" | "qualified";
  request: Readonly<{
    origin: string;
    method: "GET" | "POST";
    path: string;
    query: Readonly<Record<string, string>>;
    body: Readonly<{ kind: "empty" }> | Readonly<{ kind: "json"; value: Json }>;
    // Optional, so every schema pinned before it existed keeps its exact digest.
    pathParams?: PathParams;
  }>;
  capture: Readonly<{
    navigationUrl: string;
    authOrigins: readonly string[];
    headers: readonly Readonly<{
      name: string;
      required: boolean;
      secret: boolean;
      validation: "bearer" | "visible-ascii";
    }>[];
    cookies: readonly string[];
    // Cookie-authenticated providers: the credential is origin-wide, so it is taken from any
    // same-origin GET under this prefix that the page itself makes. The proven request is still
    // the fixed `request` above; only the cookie jar and schema headers cross into the replay.
    trigger?: Readonly<{ pathPrefix: string }>;
  }>;
  replay: Readonly<{ transform: "fixed-request-v1"; headers: Readonly<Record<string, string>> }>;
  limits: Readonly<{
    maxSentBytes: number;
    maxRecvBytes: number;
    maxHeaderBytes: number;
    // The de-chunked wire body, i.e. the ENCODED body when a content coding applies.
    maxBodyBytes: number;
    maxJsonDepth: number;
    sessionTimeoutMs: number;
    maxRecvRecords: number;
    concurrency: number;
    // Optional, and only together with `response.privacy`, so every existing digest
    // is unchanged. Decoding stops at maxDecodedBodyBytes + 1 before allocating.
    maxDecodedBodyBytes?: number;
    maxChunks?: number;
    maxRevealedRecvBytes?: number;
    maxRevealedSentBytes?: number;
  }>;
  response: Readonly<{ status: 200; contentType: "application/json"; disclosure: "full-json-body";
    // Optional to preserve every existing schema digest. Set-Cookie is always
    // private; this closed list adds the reviewed opaque ChatGPT state header.
    secretHeaders?: readonly ("x-oai-is-update")[];
    // Optional for the same reason. Present exactly when the private-headers
    // disclosure mode applies: the two are refused apart.
    privacy?: ResponsePrivacy }>;
  selector?: Selector;
  fields: readonly Field[];
  checks: readonly Check[];
  identity: Readonly<{ version: string; kind: "legacy-plan-wallet" | "field"; field: string }>;
  claims: Readonly<{ enabled: boolean; domain: string; templateIds: readonly string[] }>;
}>;

export type SchemaReference = Readonly<{ schemaId: string; version: number; digest: string }>;
export type Range = Readonly<{ start: number; end: number }>;
export type VerifiedBytes = Readonly<{
  bytes: Uint8Array;
  originalLength: number;
  authenticated: readonly Range[];
}>;
// These fields must come from authenticated verifier delivery. This type is not
// a cryptographic proof and must never be populated from the browser's result.
export type VerifiedExchange = Readonly<{
  mode: "Proxy";
  serverName: string;
  sent: VerifiedBytes;
  recv: VerifiedBytes;
}>;
export type CapturedRequest = Readonly<{
  url: string;
  method: string;
  headers: readonly Readonly<{ name: string; value: string }>[];
  body?: string;
}>;
export type ReplayRequest = Readonly<{
  url: string;
  method: "GET" | "POST";
  headers: Readonly<Record<string, string>>;
  body: string;
}>;
export type EvidenceFacts = Readonly<{
  providerId: string;
  domain: string;
  identityVersion: string;
  subjectKey: string;
  values: Readonly<Record<string, Json>>;
  claimable: false;
}>;
