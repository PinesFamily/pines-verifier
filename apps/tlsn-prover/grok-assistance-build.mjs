import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {GROK_CLEARANCE,GROK_EMAIL} from '../../tools/tee-native/disclosure-policy.mjs';
import {CLEARANCE_GENERATION,CLEARANCE_PROVIDERS,GROK_EMAIL_GENERATION,GROK_EMAIL_PROVIDERS,hardwareCapability} from '../../tools/tee-native/profile.mjs';
import {teePolicyFile} from './tee-policy-file.mjs';
import {policyForSchema} from '../../tools/tee-native/policy.mjs';
import {publicAddress} from '../../tools/grok-cloudflare/relay.mjs';
const check = value => {if (!value) throw Error('ASSISTANCE_BUILD_REFUSED');};
export async function assistanceBuild({file,tee,root,publicRelease,qualification,recoveryQualification}) {
  if (file === undefined) return;
  check(tee?.disclosurePolicy === 'private-headers-gzip-v1' && !qualification);
  const input = JSON.parse(await readFile(file, 'utf8')), pin = input.pin;
  const generation = input.generation ?? CLEARANCE_GENERATION;
  check([CLEARANCE_GENERATION,GROK_EMAIL_GENERATION].includes(generation));
  const email = generation === GROK_EMAIL_GENERATION, disclosure = email ? GROK_EMAIL : GROK_CLEARANCE;
  const provider = (email ? GROK_EMAIL_PROVIDERS : CLEARANCE_PROVIDERS)[0];
  if(recoveryQualification)check(!publicRelease&&email&&recoveryQualification.variant==='email'
    &&recoveryQualification.declaration?.qualificationOnly===true&&recoveryQualification.declaration?.productionAdmission===false
    &&tee.api==='http://localhost:8994/tee'&&input.manifestRequired===false
    &&pin.group==='gm1026-qualification'&&pin.nodeId==='gm1026-qualification-v2');
  check(!publicRelease || email && input.enabled && input.manifestRequired === true);
  check(input.version === 1 && typeof input.enabled === 'boolean' && pin?.schemaDigest === provider.reference.digest
    && pin.egressPath === 'pines-grok-relay-v1' && publicAddress(pin.egressIpv4) && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(pin.egressIpv4)
    && /^[a-z0-9-]{1,48}$/.test(pin.group) && /^[a-z0-9-]{1,64}$/.test(pin.nodeId)
    && Number.isInteger(pin.browserPort) && pin.browserPort > 0 && pin.browserPort <= 65535);
  // A public release selects its separately qualified recovery policy. Keep the
  // original experiment policy immutable for its historical package bindings.
  check(input.policyFile === undefined || publicRelease && email
    && input.policyFile === 'tools/tee-native/hardware/policy.grok-email-gm1026-qualified.json');
  const policySet = recoveryQualification?.companionPolicy
    ?? JSON.parse(await readFile(resolve(root, input.policyFile ?? teePolicyFile(disclosure.id, generation)), 'utf8'));
  check(JSON.stringify(input.policy) === JSON.stringify(policySet));
  const policy = await policyForSchema(policySet, provider.reference, disclosure);
  const q = input.qualification;
  check(q && Array.isArray(q.chromeMajors) && q.chromeMajors.length > 0 && q.chromeMajors.every(v => Number.isInteger(v) && v >= 141));
  check(Boolean(q.qualificationOnly)===Boolean(recoveryQualification));
  if (input.enabled) check(policy?.admissionEnabled && policy.providerQualified && policy.clockQualified && policy.lifecycleQualified
    && ['existingSockets','http3','serviceWorkers','restartCleanup','desktopTransport'].every(k => q[k] === true));
  return {version: 1, enabled: input.enabled, pin, qualification: q, tee: {...tee,
    policySet, providers: [{schema: provider.schema, reference: provider.reference, profile: provider.profile,
      publicPlanValues: provider.publicPlanValues, policy}], disclosurePolicy: disclosure.id, generation,
    manifest: {...tee.manifest, required: input.manifestRequired === true || publicRelease},
    capability: hardwareCapability(disclosure, generation)}};
}
