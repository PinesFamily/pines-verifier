import assert from 'node:assert/strict';
import test from 'node:test';
import {DEFAULT_FUNNEL_ORIGINS, funnelOrigins, matchPatternsFor} from '../src/funnel-origins.mjs';

test('funnel origins add loopback unless the build says the list is exclusive', () => {
  assert.deepEqual(funnelOrigins({}), [...DEFAULT_FUNNEL_ORIGINS]);
  assert.deepEqual(funnelOrigins({PROVER_FUNNEL_ORIGINS: 'https://app.pines.family'}), ['https://app.pines.family', ...DEFAULT_FUNNEL_ORIGINS]);
  assert.deepEqual(funnelOrigins({PROVER_FUNNEL_ORIGINS: 'https://app.pines.family', PROVER_FUNNEL_ORIGINS_EXCLUSIVE: '1'}), ['https://app.pines.family']);
  assert.deepEqual(funnelOrigins({PROVER_FUNNEL_ORIGINS: 'https://app.pines.family', PROVER_FUNNEL_ORIGINS_EXCLUSIVE: '0'}), ['https://app.pines.family', ...DEFAULT_FUNNEL_ORIGINS]);
});

test('manifest patterns drop the port', () => {
  assert.deepEqual(matchPatternsFor(['http://localhost:5180', 'https://app.pines.family']), ['http://localhost/*', 'https://app.pines.family/*']);
  assert.throws(() => matchPatternsFor(['https://app.pines.family/claim']), /bare origin/);
});
