// Synthetic HTTPS traffic in a disposable profile only. Build the three-provider
// extension first. Chrome's own extensions page supplies the initial grant; then
// the real panel button exercises permissions.request after remove(), without a
// native modal. First-install native prompt appearance remains a manual check.
import assert from 'node:assert/strict';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {execFileSync, spawn} from 'node:child_process';
import {createServer} from 'node:https';
import {X509Certificate, createHash} from 'node:crypto';
import {chromium} from 'playwright';
const extension = resolve('dist');
const manifest = JSON.parse(await readFile(join(extension, 'manifest.json')));
assert.deepEqual(manifest.optional_host_permissions, ['https://chatgpt.com/*', 'https://claude.ai/*', 'https://grok.com/*']);
assert.equal(manifest.host_permissions, undefined);
for (const permission of ['tabs', 'webNavigation', 'scripting', 'activeTab', 'history']) assert(!manifest.permissions.includes(permission));
const temporary = await mkdtemp(join(tmpdir(), 'pines-permission-test-'));
let context, server, browserProcess, browser, endpoint, prerenderExecuted = false, prerenderActivated = false;
try {
  const keyFile = join(temporary, 'key.pem'), certFile = join(temporary, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyFile, '-out', certFile,
    '-days', '1', '-subj', '/CN=chatgpt.com', '-addext', 'subjectAltName=DNS:chatgpt.com'], {stdio: 'ignore'});
  const key = await readFile(keyFile), cert = await readFile(certFile);
  const spki = createHash('sha256').update(new X509Certificate(cert).publicKey.export({type: 'spki', format: 'der'})).digest('base64');
  server = createServer({key, cert}, (req, res) => {
    if (req.url === '/prerender-activated') {prerenderActivated = true; res.end('ok'); return;}
    if (req.url === '/prerender-status?active=true') {prerenderExecuted = true; res.end('ok'); return;}
    if (req.url === '/settings/usage?fixture=prerender') {res.setHeader('Content-Type', 'text/html'); res.end('<title>Prerender target</title><script>document.addEventListener("prerenderingchange",()=>navigator.sendBeacon("/prerender-activated"));fetch("/prerender-status?active="+document.prerendering);</script>'); return;}
    if (['/backend-api/wham/usage', '/api/account_profile', '/rest/subscriptions'].includes(req.url)) {res.setHeader('Content-Type', 'application/json'); res.end('{"plan_type":"plus"}'); return;}
    res.setHeader('Content-Type', 'text/html'); res.setHeader('Set-Cookie', ['fixture=cookie-canary; Secure; HttpOnly; Path=/', 'sessionKey=synthetic-cookie-canary; Secure; HttpOnly; Path=/', 'sso=synthetic-cookie-canary; Secure; HttpOnly; Path=/']);
    const path = req.headers.host === 'claude.ai' ? '/api/account_profile' : req.headers.host === 'grok.com' ? '/rest/subscriptions' : '/backend-api/wham/usage';
    const early = req.url.includes('fixture=early-api');
    res.end('<!doctype html><title>Synthetic provider</title><script>history.replaceState({},"",location.pathname+"?fixture=provider-boot");history.replaceState({},"",location.href);'+
      (early ? 'fetch('+JSON.stringify(path)+',{headers:{authorization:"Bearer synthetic-permission-canary"}});' : '')+
      '</script><button onclick="fetch(\'/backend-api/wham/usage\',{headers:{authorization:\'Bearer synthetic-permission-canary\'}})">Read plan</button>'.replace('/backend-api/wham/usage', path));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  let browserOutput = '';
  browserProcess = spawn(process.env.TLSN_BROWSER_EXECUTABLE ?? '/usr/bin/google-chrome', [
    `--user-data-dir=${join(temporary, 'profile')}`, '--remote-debugging-port=0', '--headless=new', '--no-first-run',
    '--no-sandbox', '--no-proxy-server', '--enable-unsafe-extension-debugging',
    `--host-resolver-rules=${['chatgpt.com', 'claude.ai', 'grok.com', 'ungranted.test'].map(host=>`MAP ${host} 127.0.0.1:${server.address().port}`).join(',')}`, `--ignore-certificate-errors-spki-list=${spki}`], {stdio: ['ignore', 'ignore', 'pipe']});
  browserProcess.stderr.on('data', bytes => {browserOutput = (browserOutput + bytes.toString()).slice(-8192);});
  for (let n=0;n<100&&!endpoint;n++) {endpoint=browserOutput.match(/DevTools listening on (ws:\/\/[^\s]+)/)?.[1];if(!endpoint)await new Promise(r=>setTimeout(r,50));}
  assert(endpoint, 'Chrome debugging endpoint missing');
  browser = await chromium.connectOverCDP(endpoint); context = browser.contexts()[0];
  const cdp = await context.browser().newBrowserCDPSession();
  const {id} = await cdp.send('Extensions.loadUnpacked', {path: extension});
  await cdp.detach();
  let panel = await context.newPage(); await panel.goto(`chrome-extension://${id}/panel.html`);
  await panel.waitForFunction(() => document.querySelector('.panel').dataset.view === 'start');
  assert.equal(await panel.evaluate(() => chrome.permissions.contains({origins: ['https://chatgpt.com/*']})), false);
  // Use the production panel renderer and button, substituting only its run IPC.
  await panel.evaluate(() => {
    window.nativeRequest = chrome.permissions.request.bind(chrome.permissions);
    window.permissionCalls = []; window.results = [];
    window.fakeState = {runId: crypto.randomUUID(), schema: {schemaId: 'pines.chatgpt.plan'}, phase: 'awaiting-permission',
      automaticCapture: true, origin: 'https://app.pines.family', recipient: '0x' + '1'.repeat(40), deadline: Date.now() + 60000};
    window.baseState = {...window.fakeState};
    chrome.runtime.sendMessage = async message => {
      if (message.type === 'panel-recover') {window.fakeState = null; return {ok: true};}
      if (message.type === 'panel-status') return {ok: true, state: window.fakeState};
      if (message.type === 'panel-permission') {
        window.results.push(message); window.fakeState.phase = message.granted ? 'awaiting-capture' : 'cancelled';
        window.fakeState.error = message.granted ? null : 'PROVIDER_PERMISSION_DENIED'; return {ok: true};
      }
      throw Error('Unexpected panel message');
    };
    chrome.permissions.request = async request => {window.permissionCalls.push(request); return false;};
  });
  await panel.getByRole('button', {name: 'Allow access to chatgpt.com', exact: true}).click();
  await panel.waitForFunction(() => window.results.length === 1);
  assert.match(await panel.locator('#description').textContent(), /declined/);
  assert.deepEqual(await panel.evaluate(() => window.permissionCalls), [{origins: ['https://chatgpt.com/*']}]);
  console.log('PASS production-panel-single-provider-request-and-denial');
  for (const phase of ['cancelled', 'failed']) {
    if (phase === 'failed') {
      await panel.evaluate(() => {
        window.fakeState = {...window.baseState, runId: crypto.randomUUID(), phase: 'awaiting-disclosure',
          preview: {request: 'GET /synthetic HTTP/1.1', response: 'HTTP/1.1 200 OK\r\n\r\n{"plan_type":"plus","email":"synthetic@example.test"}', fields: {plan_type: 'plus'}}};
      });
      await panel.locator('#approve').waitFor({state: 'visible'});
      await panel.evaluate(() => {window.fakeState.phase = 'failed'; window.fakeState.error = 'WORKER_RESTARTED'; delete window.fakeState.preview;});
    }
    await panel.getByRole('button', {name: 'Return to Pines', exact: true}).click();
    await panel.waitForFunction(() => document.querySelector('.panel').dataset.view === 'start');
    assert.equal(await panel.locator('#preview').textContent(), '');
    assert.equal(await panel.locator('#shared-rows').textContent(), '');
    assert.equal(await panel.locator('#status').textContent(), '');
    assert.equal(await panel.locator('#help').textContent(), '');
    console.log(`PASS ${phase}-panel-return-resets-home-and-clears-previous-review`);
  }
  await panel.evaluate(() => {window.fakeState = {...window.baseState, runId: crypto.randomUUID(), phase: 'failed', error: 'RATE_LIMITED', retryAt: Date.now() + 61000};});
  await panel.waitForFunction(() => document.querySelector('#heading').textContent === 'Too many verification attempts');
  assert.match(await panel.locator('#retry-countdown').textContent(), /Try again in/);
  assert.match(await panel.locator('#description').textContent(), /Try again at/);
  assert.equal(await panel.locator('#progress').isVisible(), false);
  assert.equal(await panel.locator('#approve').isVisible(), false);
  await panel.evaluate(() => {window.fakeState.retryAt = Date.now() - 1;});
  await panel.waitForFunction(() => document.querySelector('#heading').textContent === 'You can try again now');
  assert.equal(await panel.locator('#retry-countdown').isVisible(), false);
  await panel.evaluate(() => {window.fakeState.retryAt = null;});
  await panel.waitForFunction(() => document.querySelector('#description').textContent.includes('did not provide an exact retry time'));
  await panel.getByRole('button', {name: 'Return to Pines', exact: true}).click();
  await panel.waitForFunction(() => document.querySelector('.panel').dataset.view === 'start');
  console.log('PASS rate-limit-countdown-expiry-legacy-fallback-and-return');
  const settings = await context.newPage(); await settings.goto('chrome://extensions/');
  await settings.evaluate(async id => {await new Promise((resolve, reject) => chrome.developerPrivate.addHostPermission(id, 'https://chatgpt.com/*', () => chrome.runtime.lastError ? reject(Error(chrome.runtime.lastError.message)) : resolve()));}, id);
  await panel.evaluate(async () => {
    await chrome.permissions.remove({origins: ['https://chatgpt.com/*']});
    window.fakeState = {...window.baseState, runId: crypto.randomUUID(), phase: 'awaiting-permission', error: null};
    chrome.permissions.request = window.nativeRequest;
  });
  await panel.getByRole('button', {name: 'Allow access to chatgpt.com', exact: true}).click();
  await panel.waitForFunction(() => window.results.length === 2);
  assert.equal(await panel.evaluate(() => window.results[1].granted), true);
  assert.equal(await panel.evaluate(() => window.results[1].runId === window.fakeState.runId), true);
  for (const host of ['claude.ai', 'grok.com']) assert.equal(await panel.evaluate(host => chrome.permissions.contains({origins: [`https://${host}/*`]}), host), false);
  console.log('PASS native-permissions-request-on-panel-user-gesture');
  await panel.evaluate(async () => {
    const {ProviderCapture} = await import('./provider-capture.js');
    const {loadRegistry} = await import('./schemas/src/index.js');
    const entries = (await loadRegistry()).list();
    window.captureResult = null; window.captureError = null; window.sawCookie = false;
    chrome.webRequest.onBeforeRequest.addListener(d => {if (d.tabId===window.captureJob?.ownedProviderTabId) window.captureNavigationObserved = true;}, {urls:['https://chatgpt.com/*'],types:['main_frame']});
    chrome.webRequest.onBeforeSendHeaders.addListener(details => {
      window.sawCookie = details.requestHeaders.some(h => h.name.toLowerCase() === 'cookie' && h.value.includes('cookie-canary'));
    }, {urls: ['https://chatgpt.com/backend-api/wham/usage']}, ['requestHeaders', 'extraHeaders']);
    window.startCapture = async (schemaId = 'pines.chatgpt.plan', early = false) => {
      const schema = entries.find(e => e.reference.schemaId === schemaId && e.reference.version === (schemaId === 'pines.chatgpt.plan' ? 3 : 1)).schema;
      window.controller?.cancel(); window.captureResult = null; window.captureError = null;
      const tab = await chrome.tabs.create({url: 'about:blank'});
      const job = {runId: crypto.randomUUID(), phase: 'awaiting-capture', captureExpiresAt: Date.now()+30000,
        ownedProviderTabId: tab.id, owner: {tabId: 1, windowId: tab.windowId, documentId: 'synthetic-owner'}};
      window.controller = new ProviderCapture({browser: chrome, current: () => job, owner: async (_, owner) => {job.providerOwner = owner;}, ownerReady: async () => true,
        deliver: async (_, replay) => {window.captureResult = schemaId === 'pines.chatgpt.plan' ? replay.headers.authorization === 'Bearer synthetic-permission-canary' : replay.headers.cookie === (schemaId === 'pines.claude.plan' ? 'sessionKey=' : 'sso=') + 'synthetic-cookie-canary';},
        fail: async error => {window.captureError = error;}});
      window.captureJob = job;
      await window.controller.start(job, schema, {tabId: tab.id, navigateTo: (schemaId === 'pines.chatgpt.plan' ? 'https://chatgpt.com/settings/usage' : schema.capture.navigationUrl) + (early ? '?fixture=early-api' : '')});
    };
    await window.startCapture();
  });
  const wait = async fn => {for (let n=0;n<100;n++) {const value = await fn(); if(value) return value; await new Promise(r=>setTimeout(r,50));} throw Error('Provider page unavailable');};
  const provider = await wait(() => context.pages().find(p => p.url().startsWith('https://chatgpt.com/')));
  await provider.getByRole('button', {name: 'Read plan'}).click();
  await panel.waitForFunction(() => window.captureResult !== null || window.captureError !== null);
  assert.equal(await panel.evaluate(() => window.captureError), null);
  assert.equal(await panel.evaluate(() => window.captureResult), true);
  assert.equal(await panel.evaluate(() => window.sawCookie), true);
  await panel.evaluate(() => window.controller.validate(window.captureJob));
  console.log('PASS optional-grant-native-capture-and-extraHeaders-cookie');
  await provider.evaluate(() => history.replaceState({}, '', location.pathname + '?fixture=same-document'));
  await new Promise(resolve => setTimeout(resolve, 200));
  assert.equal(await panel.evaluate(() => window.captureError), null, 'Same-document query updates must preserve the captured document');
  await panel.evaluate(() => window.controller.validate(window.captureJob));
  console.log('PASS same-document-query-update-retains-capture');
  await provider.reload();
  await panel.waitForFunction(() => window.captureError !== null);
  assert.equal(await panel.evaluate(() => window.captureError), 'CAPTURE_NAVIGATED');
  assert.equal(await panel.evaluate(async () => {try {await window.controller.validate(window.captureJob);return true;}catch{return false;}}), false);
  console.log('PASS same-URL-reload-invalidates-captured-document-before-Share');
  await panel.evaluate(() => window.startCapture());
  const second = await wait(() => context.pages().find(p => p !== provider && p.url().startsWith('https://chatgpt.com/')));
  await provider.getByRole('button', {name: 'Read plan'}).click();
  await new Promise(r => setTimeout(r, 100)); assert.equal(await panel.evaluate(() => window.captureResult), null);
  await second.getByRole('button', {name: 'Read plan'}).click();
  await panel.waitForFunction(() => window.captureResult === true);
  await second.evaluate(() => {window.addEventListener('pageshow', e => {window.restoredFromCache = e.persisted;});});
  await second.goto('https://chatgpt.com/other');
  await panel.waitForFunction(() => window.captureError !== null);
  await second.goBack({waitUntil: 'commit'});
  assert.equal(await panel.evaluate(async () => {try {await window.controller.validate(window.captureJob);return true;}catch{return false;}}), false);
  assert.equal(await second.evaluate(() => window.restoredFromCache === true), true);
  console.log('PASS unrelated-tab-is-ignored-and-real-BFCache-return-cannot-resurrect-capture');
  for (const destination of ['about:blank', 'https://ungranted.test/']) {
    await panel.evaluate(() => window.startCapture());
    const tabId = await panel.evaluate(() => window.captureJob.ownedProviderTabId);
    const currentPage = await wait(() => context.pages().find(p => p.url().startsWith('https://chatgpt.com/') && ![provider, second].includes(p)));
    await currentPage.getByRole('button', {name:'Read plan'}).click();
    await panel.waitForFunction(()=>window.captureResult===true);
    await currentPage.goto(destination);
    await panel.waitForFunction(()=>window.captureError!==null);
    assert.equal(await panel.evaluate(async()=>{try {await window.controller.validate(window.captureJob);return true;}catch{return false;}}),false);
    await panel.evaluate(tabId=>chrome.tabs.remove(tabId),tabId);
    console.log(`PASS navigation-to-${destination==='about:blank'?'blank':'ungranted-origin'}-invalidates-capture`);
  }
  if (process.env.TLSN_SKIP_PRERENDER !== '1') {
    await panel.evaluate(() => window.startCapture());
    const third = await wait(() => context.pages().find(p => p !== provider && p !== second && p.url().startsWith('https://chatgpt.com/')));
    await third.getByRole('button', {name: 'Read plan'}).click();await panel.waitForFunction(() => window.captureResult === true);
    await panel.evaluate(()=>{window.captureNavigationObserved=false;});
    await third.bringToFront();
    // DevTools-attached renderers disable prerendering. Schedule synthetic navigation, then detach the test
    // client while Chrome (and the extension's native listeners) keep running. No production injection is used.
    await third.evaluate(() => {
      setTimeout(() => {const script=document.createElement('script');script.type='speculationrules';
        script.textContent=JSON.stringify({prerender:[{source:'list',urls:['/settings/usage?fixture=prerender'],eagerness:'immediate'}]});document.head.append(script);},500);
      setTimeout(() => {location.href='/settings/usage?fixture=prerender';},3000);
    });
    await browser.close();
    await wait(() => prerenderExecuted); await wait(() => prerenderActivated);
    browser=await chromium.connectOverCDP(endpoint);context=browser.contexts()[0];
    panel=context.pages().find(p=>p.url()===`chrome-extension://${id}/panel.html`); assert(panel);
    await new Promise(resolve=>setTimeout(resolve,500));
    assert.equal(await panel.evaluate(()=>window.captureNavigationObserved),true, 'Silent prerender is covered by the native main-frame guard');
    assert.equal(await panel.evaluate(async () => {try {await window.controller.validate(window.captureJob);return true;}catch{return false;}}), false);
    assert.equal(await panel.evaluate(()=>window.captureResult),true, 'prerender traffic cannot replace the captured replay');
    console.log('PASS real-prerender-activation-invalidates-captured-document');
  } else console.log('SKIP prerender fixture (explicit TLSN_SKIP_PRERENDER=1; qualified separately in Chrome)');
  await panel.evaluate(async () => {await window.startCapture(); await chrome.permissions.remove({origins: ['https://chatgpt.com/*']});});
  await panel.waitForFunction(() => window.captureError !== null);
  assert.equal(await panel.evaluate(() => window.captureError), 'CAPTURE_PERMISSION_LOST');
  console.log('PASS real-permission-removal-stops-active-capture');
  // Repeat native cookie capture under each distinct optional provider grant.
  const grantSettings = await context.newPage(); await grantSettings.goto('chrome://extensions/');
  for (const [host, schemaId] of [['claude.ai', 'pines.claude.plan'], ['grok.com', 'pines.grok.plan']]) {
    const pattern = `https://${host}/*`;
    await grantSettings.evaluate(async ({id, pattern}) => {await new Promise((resolve, reject) => chrome.developerPrivate.addHostPermission(id, pattern, () => chrome.runtime.lastError ? reject(Error(chrome.runtime.lastError.message)) : resolve()));}, {id, pattern});
    await panel.evaluate(async pattern => {
      await chrome.permissions.remove({origins: [pattern]}); window.fixtureGrant = false;
      document.querySelector('#fixture-grant')?.remove(); const b=document.createElement('button'); b.id='fixture-grant';b.textContent='Grant fixture';
      b.onclick=()=>chrome.permissions.request({origins:[pattern]}).then(v=>window.fixtureGrant=v);document.body.append(b);
    }, pattern);
    await panel.locator('#fixture-grant').click(); await panel.waitForFunction(()=>window.fixtureGrant);
    await panel.evaluate(schemaId=>window.startCapture(schemaId), schemaId);
    const providerPage = await wait(()=>context.pages().find(p=>p.url().startsWith(`https://${host}/`)));
    await providerPage.evaluate(()=>history.replaceState({},'',location.href));
    await new Promise(resolve=>setTimeout(resolve,100));
    assert.equal(await panel.evaluate(()=>window.captureError),null, 'Replacing history at the identical URL before capture must retain the document');
    await providerPage.getByRole('button', {name:'Read plan'}).click();
    await panel.waitForFunction(()=>window.captureResult!==null||window.captureError!==null);
    assert.equal(await panel.evaluate(()=>window.captureError),null);assert.equal(await panel.evaluate(()=>window.captureResult),true);
    await providerPage.evaluate(()=>history.replaceState({},'',location.pathname+'?fixture=provider-review'));
    await new Promise(resolve=>setTimeout(resolve,100));
    await panel.evaluate(()=>window.controller.validate(window.captureJob));
    assert.equal(await panel.evaluate(()=>window.captureError),null);
    await providerPage.evaluate(()=>history.replaceState({},'',location.href));
    await new Promise(resolve=>setTimeout(resolve,100));
    await panel.evaluate(()=>window.controller.validate(window.captureJob));
    assert.equal(await panel.evaluate(()=>window.captureError),null, 'Replacing history at the identical URL during review must retain the document');
    await panel.evaluate(()=>window.controller.cancel());
    console.log(`PASS ${host}-optional-grant-native-HttpOnly-cookie-capture`);
    await panel.evaluate(schemaId=>window.startCapture(schemaId,true),schemaId);
    await panel.waitForFunction(()=>window.captureResult!==null||window.captureError!==null);
    assert.equal(await panel.evaluate(()=>window.captureError),null);
    assert.equal(await panel.evaluate(()=>window.captureResult),true);
    await panel.evaluate(()=>window.controller.validate(window.captureJob));
    await panel.evaluate(()=>window.controller.cancel());
    console.log(`PASS ${host}-startup-history-update-and-early-API-capture`);
  }

} finally {
  if (browser?.isConnected()) {const closing = await browser.newBrowserCDPSession(); await closing.send('Browser.close').catch(()=>{});}
  await browser?.close(); if (browserProcess && browserProcess.exitCode === null) {browserProcess.kill();await new Promise(r=>browserProcess.once('exit',r));} if (server) await new Promise(resolve => server.close(resolve));
  await rm(temporary, {recursive: true, force: true, maxRetries: 5, retryDelay: 200});
}
