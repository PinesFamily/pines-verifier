import {mkdtemp, mkdir, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {chromium} from 'playwright';
import {loadRegistry} from '../verification-schemas/src/index.ts';
import {buildCapture} from './build.mjs';

const check = condition => {if (!condition) throw Error('INVALID_CAPTURE_REPORT');};
const phases = new Set(['consumed', 'failed', 'cancelled']);
const codes = new Set(['INVALID_CAPTURE', 'CAPTURE_CANCELLED', 'CAPTURE_NAVIGATED',
  'CAPTURE_TAB_CLOSED', 'CAPTURE_OWNER_CHANGED', 'CAPTURE_PERMISSION_LOST', 'CAPTURE_UNAVAILABLE', 'CAPTURE_TIMEOUT']);

// Explicitly project metadata; no website text, response body, private request
// material or generic exception object can be serialized by the report writer.
export function captureReport(value, {reference, schema}, browserVersion) {
  const capture = value?.capture;
  check(value?.ok === true && value.claimable === false && capture?.claimable === false);
  check(['schemaId', 'version', 'digest'].every(key => value.schema?.[key] === reference[key]));
  check(phases.has(capture.phase) && (capture.error === null || codes.has(capture.error)));
  check(capture.maxHeaderBytes === schema.limits.maxHeaderBytes && Array.isArray(capture.headers) && capture.headers.length <= 2);
  const names = new Set();
  const headers = capture.headers.map(header => {
    check(['authorization', 'user-agent'].includes(header.name) && !names.has(header.name)
      && Number.isSafeInteger(header.bytes) && header.bytes > 0 && header.bytes <= 8192 && header.secret === true);
    names.add(header.name); return {name: header.name, bytes: header.bytes, secret: true};
  });
  check(typeof browserVersion === 'string' && /^[\d.]{1,64}$/.test(browserVersion));
  return {measuredAt: new Date().toISOString(), browser: browserVersion, kind: 'native-mv3-capture-only',
    schema: {...reference}, phase: capture.phase, error: capture.error, headers,
    maxHeaderBytes: schema.limits.maxHeaderBytes, claimable: false};
}

async function measure() {
  const endpoint = process.env.TLSN_BROWSER_CDP ?? 'http://127.0.0.1:9222';
  if (!/^http:\/\/(127\.0\.0\.1|localhost):\d{1,5}$/.test(endpoint)) throw Error('LOOPBACK_CDP_REQUIRED');
  const temporary = await mkdtemp(join(tmpdir(), 'pines-provider-measure-'));
  let browser, cdp, extensionId, panel;
  try {
    const registry = await loadRegistry();
    const entry = registry.list().find(entry => entry.reference.schemaId === 'pines.chatgpt.plan');
    const extension = await buildCapture(join(temporary, 'extension'));
    browser = await chromium.connectOverCDP(endpoint, {timeout: 10000});
    const providers = browser.contexts()[0].pages().filter(page => {try {return new URL(page.url()).origin === 'https://chatgpt.com';} catch {return false;}});
    if (providers.length !== 1) throw Error('OPEN_ONE_PROVIDER_TAB');
    const provider = providers[0];
    cdp = await browser.newBrowserCDPSession();
    ({id: extensionId} = await cdp.send('Extensions.loadUnpacked', {path: extension}));
    panel = await browser.contexts()[0].newPage();
    await panel.goto(`chrome-extension://${extensionId}/probe.html`);
    await panel.waitForFunction(() => {try {return JSON.parse(document.getElementById('status').textContent).ok;} catch {return false;}});
    await panel.locator('#start').click();
    await panel.waitForFunction(() => {
      try {return JSON.parse(document.getElementById('status').textContent).capture?.phase === 'waiting'
        || Boolean(document.getElementById('error').textContent);} catch {return false;}
    }, null, {timeout: 5000});
    if (await panel.locator('#error').innerText()) throw Error('CAPTURE_START_FAILED');
    await provider.bringToFront();
    // Observe ordinary traffic only. The current Usage warning button is
    // informational; the integrated pilot has an explicit reload/capture action.
    await panel.waitForFunction(() => {
      try {return ['failed', 'consumed', 'cancelled'].includes(JSON.parse(document.getElementById('status').textContent).capture?.phase)
        || Boolean(document.getElementById('error').textContent);} catch {return false;}
    }, null, {timeout: 35000});
    if (await panel.locator('#error').innerText()) throw Error('CAPTURE_START_FAILED');
    const report = captureReport(JSON.parse(await panel.locator('#status').innerText()), entry, browser.version());
    const reports = fileURLToPath(new URL('../reports/', import.meta.url)); await mkdir(reports, {recursive: true});
    await writeFile(join(reports, 'chatgpt-capture.json'), JSON.stringify(report, null, 2) + '\n', {mode: 0o600});
    console.log(JSON.stringify(report));
  } finally {
    if (panel) {await panel.locator('#cancel').click().catch(() => {}); await panel.close().catch(() => {});}
    try {
      if (extensionId) await cdp.send('Extensions.uninstall', {id: extensionId});
    } finally {
      await cdp?.detach().catch(() => {}); await browser?.close();
      await rm(temporary, {recursive: true, force: true});
    }
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  measure().catch(() => {console.error('CAPTURE_MEASUREMENT_FAILED: check the hosted browser and keep one signed-in ChatGPT tab open.'); process.exitCode = 1;});
}
