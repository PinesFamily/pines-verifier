import test from 'node:test';
import assert from 'node:assert/strict';
import {retryCopy, retryTime} from '../src/retry.js';
const now = 1_790_000_000_000;
test('retry display counts down and offers an explicit retry after the deadline', () => {
  const state = {error: 'RATE_LIMITED', retryAt: now + 61000};
  assert.equal(retryCopy(state, now).countdown, 'Try again in 1:01');
  assert.match(retryCopy(state, now).description, /Try again at/);
  assert.equal(retryCopy(state, now + 61000).title, 'You can try again now');
  assert.equal(retryCopy(state, now + 62000).countdown, '');
});
test('missing or invalid retry timing never invents a countdown', () => {
  for (const retryAt of [undefined, null, NaN, '123', 0, now + 3600001]) {
    assert.equal(retryTime(retryAt, now), null);
    const copy = retryCopy({error: 'RATE_LIMITED', retryAt}, now);
    assert.match(copy.description, /did not provide an exact retry time/); assert.equal(copy.countdown, '');
  }
  assert.equal(retryCopy({error: 'WORKER_RESTARTED'}, now), null);
});
