import test from 'node:test';
import assert from 'node:assert/strict';
import {OwnerConnections} from '../src/owner-connection.js';
const event = () => {const listeners = []; return {addListener: fn => listeners.push(fn), emit: value => listeners.forEach(fn => fn(value))};};
const owner = {origin: 'https://app.pines.family', tabId: 1, windowId: 2, documentId: 'owner'};
function fixture() {
  const lost = [], browser = {runtime: {onConnectExternal: event()}};
  const connections = new OwnerConnections(browser, [owner.origin], value => lost.push(value));
  const connect = (extra = {}) => {
    const port = {name: 'pines-tlsn-owner-v1', sender: {origin: owner.origin, url: owner.origin+'/', tab: {id: 1, windowId: 2, incognito: false}, documentId: 'owner', frameId: 0, ...extra},
      onMessage: event(), onDisconnect: event(), disconnect() {this.disconnected = true; this.onDisconnect.emit();},
      postMessage(value) {this.onMessage.emit(value);}};
    browser.runtime.onConnectExternal.emit(port); return port;
  };
  return {connections, lost, connect};
}
test('owner connection uses browser sender identity without a privileged tab URL', async () => {
  const f = fixture(), port = f.connect();
  assert.equal(await f.connections.live(owner), true);
  assert.equal(await f.connections.live({...owner, documentId: 'other'}), false);
  assert.equal(await f.connections.live({...owner, windowId: 3}), false);
  port.disconnect(); assert.equal(await f.connections.live(owner), false); assert.deepEqual(f.lost, [owner]);
});
test('replacement connection from the same document does not falsely cancel its run', async () => {
  const f = fixture(), previous = f.connect(); f.connect();
  assert.equal(previous.disconnected, true); assert.deepEqual(f.lost, []); assert.equal(await f.connections.live(owner), true);
});
test('foreign origins, subframes and inactive senders cannot become owners', async () => {
  for (const extra of [{origin: 'https://evil.test'}, {frameId: 1}, {documentId: undefined}, {documentLifecycle: 'cached'}]) {
    const f = fixture(), port = f.connect(extra); assert.equal(port.disconnected, true); assert.equal(await f.connections.live(owner), false);
  }
});
test('disconnect during a liveness challenge rejects the pending handoff', async () => {
  const f = fixture(), port = f.connect(); port.postMessage = () => port.disconnect();
  assert.equal(await f.connections.live(owner), false);
});
