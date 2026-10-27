// Two-exchange proofs on the client (multi-exchange protocol §1.7). Pure and import-light, shared by the capture controller
// and the proof worker: the ordered replays of a session from the ONE captured request, and the request targets the
// worker issues in that order. Nothing here persists, logs or sends a value.
import {captureHeaderNames, exchangeViews, prepareReplays} from '../../../packages/verification-schemas/src/index.ts';
import {requestTarget} from '../../../packages/verification-schemas/src/schema.ts';

export const exchangeCount = schema => exchangeViews(schema).length;
/** The capture keeps every exchange's header names, so an exchange-only header (a provider's per-route selector) survives it. */
export const capturedHeaderNames = schema => captureHeaderNames(schema);
/** The ordered replays and their targets: `targets[i]` is what the worker sends as the i-th request's target. */
export function sessionReplays(schema, captured, pathParams) {
  const replays = prepareReplays(schema, captured, pathParams ? {pathParams} : {});
  const views = exchangeViews(schema);
  return Object.freeze({replays, targets: Object.freeze(views.map(view => requestTarget(view.schema, view.index === 0 ? pathParams : undefined)))});
}
