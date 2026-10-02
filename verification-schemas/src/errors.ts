const messages = {
  INVALID_SCHEMA: "Invalid verification schema",
  UNKNOWN_SCHEMA: "Unknown schema version",
  SCHEMA_DIGEST_MISMATCH: "Schema content does not match its pinned digest",
  INVALID_CAPTURE: "Captured request does not satisfy the capture policy",
  SCOPE_MISMATCH: "Verified exchange does not match the required request or response",
  LIMIT_EXCEEDED: "Verification schema limit exceeded",
  INVALID_HTTP: "Unsupported or ambiguous HTTP framing",
  INVALID_JSON: "Invalid or ambiguous JSON document",
  DUPLICATE_JSON_KEY: "Duplicate JSON object key",
  UNSAFE_JSON_NUMBER: "JSON number cannot be represented without loss",
  MISSING_FIELD: "Required response field is missing",
  INVALID_FIELD: "Response field has an unexpected type or value",
  CHECK_FAILED: "Response does not satisfy a required check",
  INVALID_RECIPIENT: "Invalid claimant address",
  PARTIAL_TRANSCRIPT: "Authenticated coverage is insufficient to establish message structure",
  PRIVATE_REQUEST_UNSUPPORTED: "Unsupported private request disclosure",
  UNSUPPORTED_LEGACY_CHECK: "Legacy check needs an explicit reviewed conversion",
} as const;

export type SchemaErrorCode = keyof typeof messages;
export class SchemaError extends Error {
  readonly code: SchemaErrorCode;
  constructor(code: SchemaErrorCode) {
    super(messages[code]);
    this.name = "SchemaError";
    this.code = code;
  }
}
export function reject(code: SchemaErrorCode): never { throw new SchemaError(code); }
export function requireThat(condition: unknown, code: SchemaErrorCode): asserts condition {
  if (!condition) reject(code);
}
