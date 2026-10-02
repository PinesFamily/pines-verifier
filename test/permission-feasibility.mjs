// Fresh headed Chrome, production side panel and a real native grant. Synthetic pages only.
import assert from 'node:assert/strict';
import {mkdtemp, readFile, writeFile, mkdir, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {execFileSync, spawn} from 'node:child_process';
import {createServer} from 'node:https';
import {X509Certificate, createHash} from 'node:crypto';
import {chromium} from 'playwright';
import {sidePanel} from './side-panel.mjs';
const temporary = await mkdtemp(join(tmpdir(), 'pines-no-host-'));
const pause = ms => new Promise(r => setTimeout(r, ms));
const wait = async fn => {for(let n=0;n<150;n++) {const result=await fn();if(result)return result;await pause(100);}throw Error('Feasibility condition timed out');};
const display = ':197';
let context, server, xvfb;
const screenshot = file => execFileSync('python3',['-c',`from PIL import ImageGrab; ImageGrab.grab(xdisplay='${display}').save('${file}')`]);
function nativeClick(xpos, ypos) {
  execFileSync('python3',['-c',`import ctypes
x=ctypes.CDLL('libX11.so.6');t=ctypes.CDLL('libXtst.so.6');x.XOpenDisplay.restype=ctypes.c_void_p;d=x.XOpenDisplay(b'${display}');assert d
t.XTestFakeMotionEvent.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_ulong];t.XTestFakeButtonEvent.argtypes=[ctypes.c_void_p,ctypes.c_uint,ctypes.c_int,ctypes.c_ulong];x.XFlush.argtypes=[ctypes.c_void_p]
t.XTestFakeMotionEvent(d,-1,${xpos},${ypos},0);t.XTestFakeButtonEvent(d,1,1,0);t.XTestFakeButtonEvent(d,1,0,0);x.XFlush(d);x.XCloseDisplay.argtypes=[ctypes.c_void_p];x.XCloseDisplay(d)`]);
}
try {
  const extension=resolve('dist'), manifest=JSON.parse(await readFile(join(extension,'manifest.json')));
  assert.equal(manifest.host_permissions,undefined);
  for(const name of ['tabs','webNavigation','scripting','activeTab','history']) assert(!manifest.permissions.includes(name));
  xvfb=spawn('Xvfb',[display,'-screen','0','1280x900x24','-nolisten','tcp'],{stdio:'ignore'});await pause(700);
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(temporary,'key'),'-out',join(temporary,'cert'),'-days','1','-subj','/CN=chatgpt.com'],{stdio:'ignore'});
  const key=await readFile(join(temporary,'key')),cert=await readFile(join(temporary,'cert'));
  const spki=createHash('sha256').update(new X509Certificate(cert).publicKey.export({type:'spki',format:'der'})).digest('base64');
  server=createServer({key,cert},(req,res)=>{
    if(req.url==='/backend-api/wham/usage'){res.setHeader('Content-Type','application/json');res.end('{}');return;}
    res.setHeader('Content-Type','text/html');res.setHeader('Set-Cookie','fixture=canary; Secure; HttpOnly; Path=/');
    res.end('<!doctype html><title>Synthetic provider</title><button onclick="fetch(\'/backend-api/wham/usage\',{headers:{authorization:\'Bearer canary\'}})">Read plan</button><script>fetch("/backend-api/wham/usage",{headers:{authorization:"Bearer canary"}})</script>');
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  context=await chromium.launchPersistentContext(join(temporary,'profile'),{headless:false,executablePath:'/usr/bin/google-chrome',env:{...process.env,DISPLAY:display},ignoreDefaultArgs:['--disable-extensions'],args:['--no-sandbox','--no-proxy-server','--enable-unsafe-extension-debugging','--window-size=1280,900',`--host-resolver-rules=MAP chatgpt.com 127.0.0.1:${server.address().port}`,`--ignore-certificate-errors-spki-list=${spki}`]});
  const cdp=await context.browser().newBrowserCDPSession();const {id}=await cdp.send('Extensions.loadUnpacked',{path:extension});await cdp.detach();
  const runner=await context.newPage();await runner.goto(`chrome-extension://${id}/panel.html?feasibility-runner`);
  assert.equal(await runner.evaluate(()=>chrome.permissions.contains({origins:['https://chatgpt.com/*']})),false);
  assert.deepEqual((await runner.evaluate(()=>chrome.permissions.getAll())).origins,[]);
  const client=await readFile(join(extension,'client.mjs'),'utf8');
  await context.route('http://localhost:5180/permission-test',r=>r.fulfill({contentType:'text/html',body:`<!doctype html><button id="verify">Verify</button><script type="module">
import {createTlsnClient} from '/permission-client.mjs';window.attempts=0;window.error=null;
window.client=createTlsnClient({chainId:4663,application:'pines',request:async()=>{window.attempts++;return new Response(JSON.stringify({error:'RATE_LIMITED'}),{status:429});}});
document.querySelector('#verify').onclick=()=>{window.error=null;client.openPanel().then(()=>client.start('0x'+'1'.repeat(40),'pines.chatgpt.plan')).catch(e=>window.error=e.message);};window.ready=true;
</script>`}));
  await context.route('http://localhost:5180/permission-client.mjs',r=>r.fulfill({contentType:'text/javascript',body:client}));
  const page=await context.newPage();await page.goto('http://localhost:5180/permission-test');await page.waitForFunction(()=>window.ready);
  await page.locator('#verify').click();await pause(700);
  const panel=await sidePanel(context.browser(),`chrome-extension://${id}/panel.html`);
  await wait(()=>panel.visible('#allow-access'));assert.equal(await page.evaluate(()=>window.attempts),0);
  await panel.click('#allow-access');await pause(500);await mkdir('reports',{recursive:true});screenshot('reports/permission-native-prompt.png');
  console.log('Native prompt saved; denying first request');
  nativeClick(714,266);
  await page.waitForFunction(()=>window.error!==null);assert.equal(await page.evaluate(()=>window.error),'PROVIDER_PERMISSION_DENIED');assert.equal(await page.evaluate(()=>window.attempts),0);
  await wait(()=>panel.visible('#recover'));await panel.click('#recover');
  console.log('PASS real-side-panel-native-denial-consumes-no-attempt');
  await page.locator('#verify').click();await pause(500);
  const acceptedPanel=await sidePanel(context.browser(),`chrome-extension://${id}/panel.html`);
  await wait(()=>acceptedPanel.visible('#allow-access'));await acceptedPanel.click('#allow-access');await pause(500);nativeClick(824,266);
  await page.waitForFunction(()=>window.attempts===1);assert.equal(await runner.evaluate(()=>chrome.permissions.contains({origins:['https://chatgpt.com/*']})),true);
  await wait(()=>acceptedPanel.visible('#recover'));await acceptedPanel.click('#recover');
  await page.locator('#verify').click();await page.waitForFunction(()=>window.attempts===2);
  const savedPanel=await sidePanel(context.browser(),`chrome-extension://${id}/panel.html`);
  assert.equal(await savedPanel.visible('#allow-access'),false);
  await wait(()=>savedPanel.visible('#recover'));await savedPanel.click('#recover');
  console.log('PASS grant-before-admission-and-saved-grant-skips-native-prompt');
  // A fresh production capture uses only a new owned tab. Its initial page request is deliberately early.
  await runner.evaluate(async()=>{
    const {ProviderCapture}=await import('./provider-capture.js');const {loadRegistry}=await import('./schemas/src/index.js');
    const schema=(await loadRegistry()).list().find(e=>e.reference.schemaId==='pines.chatgpt.plan'&&e.reference.version===3).schema;
    window.begin=async()=>{
      window.controller?.cancel();window.result=null;window.failure=null;
      const tab=await chrome.tabs.create({url:'about:blank'});
      const job={runId:crypto.randomUUID(),phase:'awaiting-capture',captureExpiresAt:Date.now()+30000,ownedProviderTabId:tab.id,owner:{windowId:tab.windowId,tabId:1,documentId:'synthetic-owner'}};
      window.job=job;
      window.controller=new ProviderCapture({browser:chrome,current:()=>job,ownerReady:async()=>true,owner:async(_,o)=>{job.providerOwner=o;},
        deliver:async(_,replay)=>{window.result=replay.headers.authorization==='Bearer canary';},fail:async e=>{window.failure=e;}});
      await window.controller.start(job,schema,{tabId:tab.id,navigateTo:'https://chatgpt.com/settings/usage'});
    };await window.begin();
  });
  await runner.waitForFunction(()=>window.result!==null||window.failure!==null);
  assert.equal(await runner.evaluate(()=>window.failure),null);assert.equal(await runner.evaluate(()=>window.result),true);
  const metadata=await runner.evaluate(async()=>({document:!!window.job.providerOwner.documentId,url:(await chrome.tabs.get(window.job.ownedProviderTabId)).url}));
  assert.deepEqual(metadata,{document:true,url:'https://chatgpt.com/settings/usage'});
  await runner.evaluate(()=>window.controller.validate(window.job));
  console.log('PASS early-native-capture-after-first-grant-without-scripting');
  const provider=context.pages().find(p=>p.url().startsWith('https://chatgpt.com/'));
  await provider.evaluate(()=>history.pushState({},'', '/settings/security'));
  await runner.waitForFunction(()=>window.failure!==null);assert.equal(await runner.evaluate(()=>window.failure),'CAPTURE_NAVIGATED');
  await runner.evaluate(()=>window.begin());await runner.waitForFunction(()=>window.result!==null||window.failure!==null);assert.equal(await runner.evaluate(()=>window.result),true);
  await runner.evaluate(()=>chrome.permissions.remove({origins:['https://chatgpt.com/*']}));await runner.waitForFunction(()=>window.failure!==null);
  assert.equal(await runner.evaluate(()=>window.failure),'CAPTURE_PERMISSION_LOST');
  assert.equal(await runner.evaluate(async()=>{try{await window.begin();return true;}catch{return false;}}),false);
  console.log('PASS SPA-route-change-and-revocation-prevent-reuse');
  const settings=await context.newPage();await settings.goto(`chrome://extensions/?id=${id}`);await pause(600);screenshot('reports/permission-fresh-site-access.png');
  await writeFile('reports/permission-feasibility.json',JSON.stringify({version:manifest.version,chrome:context.browser().version(),requiredHosts:[],permissions:manifest.permissions,optionalHosts:manifest.optional_host_permissions,nativeGrant:true,nativeDenial:true,earlyCapture:true,admissionAfterGrant:true},null,2)+'\n');
} finally {await context?.close();if(server)await new Promise(r=>server.close(r));xvfb?.kill();await rm(temporary,{recursive:true,force:true});}
