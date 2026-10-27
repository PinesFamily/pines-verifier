// The companion is selected by an owned assisted retry, never by replacing the
// ordinary provider map or accepting a relay/profile supplied by a web page.
export function grokCompanion(config) {
  const companion = config.grokAssistance;
  if (!companion || companion.version !== 1 || companion.enabled !== true) throw Error('ASSISTANCE_DISABLED');
  return {...config, tee: companion.tee, schemas: companion.tee.providers.filter(p => p.policy?.admissionEnabled).map(p => p.reference),
    grokAssistanceView: true};
}
