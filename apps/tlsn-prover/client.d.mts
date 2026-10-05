export type TeeProvider = {id: 'chatgpt' | 'claude' | 'grok'; profile: string; schema: SchemaReference; savedSchemas: SchemaReference[]};
export type TeeCapability = {capabilityVersion: 2; application: string; chain: number; revision: string; verificationEpoch: string; protocolVersion: string; trustPolicyVersion: number; deploymentHash: string; protocol: string; providers: TeeProvider[]; claimSigningAvailable: boolean};
export function sameTeeCapability(a: unknown, b: unknown): boolean;
export function teeProviderFor(capability: TeeCapability | undefined, reference: SchemaReference, saved?: boolean): TeeProvider | undefined;
export type SchemaReference = {schemaId: string; version: number; digest: string};
export type AttemptRouting = 'pinned' | 'assigned';
export type TlsnConfiguration = {
  protocol: 'pines-verification-config-v1'; engine: 'tlsn'; enabled: true;
  application: string; chainId: number; mode: 'Proxy'; claimable: boolean;
  /** The pinned (pre-assignment) instance's revision and origin, for extensions built before per-attempt routing. */
  verifierRevision: string; verifierOrigin: string; schemas: SchemaReference[];
  /** Present on APIs that assign a verifier per attempt. */
  attemptRouting?: AttemptRouting[];
  tee?: TeeCapability;
};
export type VerifierAssignment = {instanceId: string; origin: string; revision: string};
export type ReceiptHandle = {
  recipient: string; runId?: string;
  attempt: {attemptId: string; schema: SchemaReference; resultExpiresAt: number; routing?: AttemptRouting; verifier?: VerifierAssignment};
};
export type ReceiptStatus = {
  attemptId: string; recipient: string; schema: SchemaReference; engine: 'tlsn'; mode: 'Proxy';
  application: string; chainId: number; verifierRevision: string; claimable: boolean;
  status: 'pending' | 'verifying' | 'awaiting-result' | 'verified' | 'cancelled' | 'expired' | 'failed';
  receiptId: string | null; expiresAt: number; error: string | null;
  /** The owner asked to stop; the attempt settles from the verifier's outcome or the result deadline. */
  cancelRequested?: boolean;
  executionProfile?: string; verificationEpoch?: string;
  linkedWallet?: string;
};
export type ExtensionState = {
  runId: string; attemptId: string; recipient: string; schema: SchemaReference; claimable: false;
  phase: 'initializing' | 'awaiting-permission' | 'awaiting-capture' | 'requesting' | 'awaiting-disclosure' | 'proving' | 'completed' | 'failed' | 'cancelled';
  error: string | null;
  pollDelayMs?: number;
};
export const TLSN_EXTENSION_ID: string;
export const POLL_INTERVAL_MS: number;
export function createTlsnClient(options: {
  request: (path: string, init: RequestInit) => Promise<Response>;
  extensionId?: string; chainId: number; application: string; configuration?: TlsnConfiguration;
  now?: () => number; random?: () => number; sleep?: (ms: number) => Promise<void>;
}): {
  openPanel(): Promise<{ok: true; opened: true}>;
  closePanel?(): Promise<{ok: true; closed: true}>;
  capabilities(): Promise<{engine: 'tlsn'; mode: 'Proxy'; application: string; chainId: number; verifierRevision: string; verifierOrigin: string; schemas: SchemaReference[]; claimable: false; routingMode?: AttemptRouting; routing?: AttemptRouting[]; admissionErrorScreen?: boolean; prepareProvider?: boolean; ownerConnection?: boolean; tee?: TeeCapability}>;
  start(recipient: string, schemaId?: string, options?: {signal?: AbortSignal; onAttempt?: (handle: ReceiptHandle) => void}): Promise<ReceiptHandle>;
  extensionStatus(handle: ReceiptHandle): Promise<ExtensionState | null>;
  receiptStatus(handle: ReceiptHandle): Promise<ReceiptStatus>;
  cancel(handle: ReceiptHandle): Promise<void>;
  recipientChanged(handle: ReceiptHandle, recipient: string | null): Promise<void>;
  waitForReceipt(handle: ReceiptHandle, options?: {signal?: AbortSignal; timeoutMs?: number; onProgress?: (progress: {status: ReceiptStatus['status']; phase: ExtensionState['phase'] | 'reconnecting'}) => void}): Promise<ReceiptStatus>;
};
