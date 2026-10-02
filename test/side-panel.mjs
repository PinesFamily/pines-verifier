// Chrome side panels are not regular tabs and are absent from Playwright's page
// list. Drive the actual renderer through its public CDP target, not a substitute
// extension tab. Everything here is test-only and uses an isolated Chrome profile.
import assert from 'node:assert/strict';
import {writeFile} from 'node:fs/promises';

export async function sidePanel(browser, url) {
  const cdp = await browser.newBrowserCDPSession();
  const target = (await cdp.send('Target.getTargets')).targetInfos.find(target => target.url === url);
  assert.ok(target, 'The actual Chrome side panel must exist');
  const {sessionId} = await cdp.send('Target.attachToTarget', {targetId: target.targetId, flatten: false});
  let sequence = 0;
  const pending = new Map();
  cdp.on('Target.receivedMessageFromTarget', event => {
    if (event.sessionId !== sessionId) return;
    const message = JSON.parse(event.message); const request = pending.get(message.id);
    if (!request) return;
    clearTimeout(request.timer); pending.delete(message.id);
    if (message.error) request.reject(Error(message.error.message)); else request.resolve(message.result);
  });
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(Error('Side panel CDP timeout: ' + method)); }, 10_000);
    pending.set(id, {resolve, reject, timer});
    cdp.send('Target.sendMessageToTarget', {sessionId, message: JSON.stringify({id, method, params})}).catch(error => {clearTimeout(timer); pending.delete(id); reject(error);});
  });
  const evaluate = async (fn, argument) => {
    const result = await send('Runtime.evaluate', {expression: `(${fn.toString()})(${JSON.stringify(argument) ?? ''})`, returnByValue: true, awaitPromise: true});
    assert.equal(result.exceptionDetails, undefined, 'Side panel evaluation failed');
    return result.result.value;
  };
  return {
    evaluate,
    text: selector => evaluate(selector => document.querySelector(selector)?.textContent, selector),
    visible: selector => evaluate(selector => {const node = document.querySelector(selector); return !!node && node.getClientRects().length > 0;}, selector),
    async click(selector) {
      const point = await evaluate(selector => {
        const node = document.querySelector(selector);
        if (!node || node.disabled || !node.getClientRects().length) throw Error('Control unavailable');
        node.scrollIntoView({block: 'center'});
        const {x, y, width, height} = node.getBoundingClientRect(); return {x: x + width/2, y: y + height/2};
      }, selector);
      await send('Input.dispatchMouseEvent', {type: 'mousePressed', ...point, button: 'left', clickCount: 1});
      await send('Input.dispatchMouseEvent', {type: 'mouseReleased', ...point, button: 'left', clickCount: 1});
    },
    async screenshot(path) { const {data} = await send('Page.captureScreenshot', {format: 'png'}); await writeFile(path, Buffer.from(data, 'base64')); },
  };
}
