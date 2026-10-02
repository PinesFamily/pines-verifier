import assert from 'node:assert/strict';
import {mkdtemp, readFile, rm, mkdir, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {createServer} from 'node:https';
import {X509Certificate, createHash} from 'node:crypto';
import {chromium} from 'playwright';
import {buildCapture} from '../capture/build.mjs';

// The real candidate URL and browser event API, but a synthetic HTTPS origin
// mapped only inside this disposable Chrome profile. Never attach this harness
// to the manually authenticated browser on port 9222.
const temporary = await mkdtemp(join(tmpdir(), 'pines-capture-test-'));
const reports = fileURLToPath(new URL('../reports/', import.meta.url));
const report = {startedAt: new Date().toISOString(), headed: process.env.PINES_TLSN_HEADED === '1', cases: []};
const pass = name => {report.cases.push({name, passed: true}); console.log('PASS ' + name);};
let server, context, requests = 0;
const browserLogs = [];
try {
  const keyFile = join(temporary, 'key.pem'), certFile = join(temporary, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyFile, '-out', certFile,
    '-days', '1', '-subj', '/CN=chatgpt.com', '-addext', 'subjectAltName=DNS:chatgpt.com'], {stdio: 'ignore'});
  const key = await readFile(keyFile), cert = await readFile(certFile);
  const spki = createHash('sha256').update(new X509Certificate(cert).publicKey.export({type: 'spki', format: 'der'})).digest('base64');
  server = createServer({key, cert}, (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    if (req.url === '/backend-api/wham/usage') {
      requests++; res.setHeader('Content-Type', 'application/json'); res.end('{"plan_type":"synthetic"}'); return;
    }
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Set-Cookie', 'fixture-cookie=unselected-browser-cookie-canary; Secure; HttpOnly; Path=/');
    res.end(`<!doctype html><title>Synthetic provider capture</title><h1>Synthetic provider</h1><button id="refresh">Refresh usage</button><script>
      window.allowUsage=true; window.tokenBytes=80;
      window.emitUsage=()=>fetch('/backend-api/wham/usage',{headers:{authorization:'Bearer capture-browser-secret-'.padEnd(window.tokenBytes,'a'),'x-unselected-secret':'unselected-browser-header-canary'}}).then(r=>r.json());
      window.addEventListener('hashchange',()=>{if(window.allowUsage && location.hash==='#settings/Usage')void window.emitUsage();});
      document.getElementById('refresh').onclick=()=>{if(window.allowUsage)void window.emitUsage();};
      window.ready=true;
    </script>`);
  });
  await new Promise((resolve, reject) => {server.once('error', reject); server.listen(0, '127.0.0.1', resolve);});
  const extension = await buildCapture(join(temporary, 'extension'));
  context = await chromium.launchPersistentContext(join(temporary, 'profile'), {
    executablePath: chromium.executablePath(), headless: !report.headed, viewport: {width: 1200, height: 850},
    args: ['--no-sandbox', '--no-proxy-server', '--disable-component-extensions-with-background-pages',
      `--disable-extensions-except=${extension}`, `--load-extension=${extension}`,
      `--host-resolver-rules=MAP chatgpt.com 127.0.0.1:${server.address().port}`,
      `--ignore-certificate-errors-spki-list=${spki}`],
  });
  context.on('console', message => {if (browserLogs.length < 1000) browserLogs.push(message.text());});
  context.on('weberror', error => {if (browserLogs.length < 1000) browserLogs.push(error.error().message);});
  report.chromium = context.browser().version();
  const worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker');
  const extensionId = new URL(worker.url()).host;
  const provider = await context.newPage(); await provider.goto('https://chatgpt.com/');
  assert.equal(await provider.title(), 'Synthetic provider capture', 'The profile must reach only the local fixture');
  const panel = await context.newPage(); await panel.goto(`chrome-extension://${extensionId}/probe.html`);
  const state = () => panel.locator('#status').innerText().then(JSON.parse);
  const phase = async expected => {
    await panel.waitForFunction(expected => {
      try {return JSON.parse(document.getElementById('status').textContent).capture?.phase === expected;} catch {return false;}
    }, expected, {timeout: 10000});
    return state();
  };
  const start = async () => {
    const previous = (await state()).capture?.runId;
    await panel.locator('#start').click();
    await panel.waitForFunction(previous => {
      try {const value=JSON.parse(document.getElementById('status').textContent);return value.capture?.runId && value.capture.runId !== previous;} catch {return false;}
    }, previous ?? null, {timeout: 10000});
    await provider.getByRole('button', {name: 'Refresh usage', exact: true}).click();
  };
  await panel.waitForFunction(() => {try {return JSON.parse(document.getElementById('status').textContent).ok;} catch {return false;}});
  await start(); const first = await phase('consumed');
  assert.ok(requests >= 1); assert.equal(first.claimable, false);
  assert.equal(first.capture.headers.find(header => header.name === 'authorization').bytes, 80);
  assert.deepEqual(first.capture.headers.map(header => header.name), ['authorization', 'user-agent']);
  assert.ok(first.capture.headers[1].bytes > 0);
  assert.equal(/secret-|canary|Bearer/.test(JSON.stringify(first)), false);
  pass('Native MV3 Authorization/User-Agent capture and one-shot replay construction');

  await provider.evaluate(() => {window.tokenBytes=2189;});
  await start(); const providerSized = await phase('consumed');
  assert.equal(providerSized.capture.error, null);
  assert.equal(providerSized.capture.headers[0].bytes, 2189);
  pass('Provider-sized private header captured and consumed within schema limits');

  await provider.evaluate(() => {window.allowUsage=false; window.tokenBytes=80;});
  await start(); await phase('waiting');
  await provider.evaluate(() => fetch('/backend-api/wham/usage?wrong=1', {headers:{authorization:'Bearer unrelated-canary'}}));
  assert.equal((await state()).capture.phase, 'waiting');
  const other = await context.newPage(); await other.goto('https://chatgpt.com/');
  await other.evaluate(() => window.emitUsage());
  assert.equal((await state()).capture.phase, 'waiting'); await other.close();
  pass('Other tabs and modified URLs cannot supply credentials');
  await panel.locator('#cancel').click(); await phase('cancelled');
  await provider.evaluate(() => window.emitUsage());
  assert.equal((await state()).capture.phase, 'cancelled');
  pass('Cancelled capture cannot be revived by a late native request');

  await start(); await phase('waiting');
  await provider.goto('https://chatgpt.com/another-document');
  assert.equal((await phase('cancelled')).capture.error, 'CAPTURE_NAVIGATED');
  pass('Top-level navigation cancels the owned document');

  await provider.goto('https://chatgpt.com/another-document?temporary=true');
  await start(); await phase('consumed');
  assert.equal(new URL(provider.url()).pathname, '/another-document');
  assert.equal(new URL(provider.url()).search, '?temporary=true');
  pass('Provider refresh preserves document ownership on a path with query parameters');
  await provider.evaluate(() => {window.allowUsage=false;});
  await start(); await phase('waiting'); await provider.close();
  assert.equal((await phase('cancelled')).capture.error, 'CAPTURE_TAB_CLOSED');
  pass('Provider tab closure clears the pending capture');

  const manifest = JSON.parse(await readFile(join(extension, 'manifest.json')));
  assert.equal(manifest.externally_connectable, undefined); assert.equal(manifest.content_scripts, undefined);
  assert.deepEqual(manifest.host_permissions, ['https://chatgpt.com/*']);
  assert.equal(manifest.permissions.includes('storage'), false); assert.equal(manifest.permissions.includes('cookies'), false);
  assert.equal(browserLogs.some(line => /capture-browser-secret-|unselected-browser-.*canary/.test(line)), false);
  pass('Diagnostic grants only provider observation and exposes no credential canaries');
  await mkdir(reports, {recursive: true});
  await writeFile(join(reports, `capture-${report.headed ? 'headed' : 'headless'}.json`), JSON.stringify(report, null, 2) + '\n');
} finally {
  await context?.close();
  if (server?.listening) {server.closeAllConnections(); await new Promise(resolve => server.close(resolve));}
  await rm(temporary, {recursive: true, force: true});
}
