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
export type Selector = Readonly<{ kind: "claude-paid-personal-org-v1" | "grok-paid-subscription-v1" }>;

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
    maxBodyBytes: number;
    maxJsonDepth: number;
    sessionTimeoutMs: number;
    maxRecvRecords: number;
    concurrency: number;
  }>;
  response: Readonly<{ status: 200; contentType: "application/json"; disclosure: "full-json-body";
    // Optional to preserve every existing schema digest. Set-Cookie is always
    // private; this closed list adds the reviewed opaque ChatGPT state header.
    secretHeaders?: readonly ("x-oai-is-update")[] }>;
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
