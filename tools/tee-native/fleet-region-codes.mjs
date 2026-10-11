// Region codes shared by the API, parent and browser bundles. No Node-only imports:
// the extension bundles this file. Operator evidence lives in fleet-regions.mjs.
export const INITIAL_REGIONS=Object.freeze(['us-east-1','ap-southeast-1']);
export const DEFERRED_REGIONS=Object.freeze(['eu-central-1']);
export const REGIONS=Object.freeze([...INITIAL_REGIONS,...DEFERRED_REGIONS]);
