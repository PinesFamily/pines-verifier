// Point TLSN_PREVIOUS_EXTENSION_ZIP at the retained 0.8.0 preview archive.
import assert from 'node:assert/strict';
import {mkdtemp, cp, rm, readFile} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {chromium} from 'playwright';
const archive = process.env.TLSN_PREVIOUS_EXTENSION_ZIP;
assert(archive, 'Set TLSN_PREVIOUS_EXTENSION_ZIP to the existing 0.8.0 archive');
const temporary = await mkdtemp(join(tmpdir(),'pines-permission-upgrade-'));
const extension = join(temporary,'extension'); let context;
try {
  execFileSync('unzip',['-q',archive,'-d',extension]);
  assert.equal(JSON.parse(await readFile(join(extension,'manifest.json'))).version,'0.8.0');
  context=await chromium.launchPersistentContext(join(temporary,'profile'),{headless:true,executablePath:'/usr/bin/google-chrome',ignoreDefaultArgs:['--disable-extensions'],args:['--no-sandbox','--enable-unsafe-extension-debugging']});
  const cdp=await context.browser().newBrowserCDPSession();const {id}=await cdp.send('Extensions.loadUnpacked',{path:extension});await cdp.detach();
  const settings=await context.newPage();await settings.goto('chrome://extensions/');
  await settings.evaluate(()=>chrome.developerPrivate.updateProfileConfiguration({inDeveloperMode:true}));
  await settings.evaluate(async id=>{await new Promise((resolve,reject)=>chrome.developerPrivate.addHostPermission(id,'https://grok.com/*',()=>chrome.runtime.lastError?reject(Error(chrome.runtime.lastError.message)):resolve()));},id);
  const runner=await context.newPage();await runner.goto(`chrome-extension://${id}/panel.html`);
  await runner.evaluate(async()=>{await chrome.permissions.remove({origins:['https://grok.com/*']});const b=document.createElement('button');b.id='upgrade-grant';b.textContent='Grant';b.onclick=()=>chrome.permissions.request({origins:['https://grok.com/*']}).then(v=>window.upgradeGranted=v);document.body.append(b);});
  await runner.locator('#upgrade-grant').click();await runner.waitForFunction(()=>window.upgradeGranted===true);
  assert.equal(await runner.evaluate(()=>chrome.permissions.contains({origins:['https://grok.com/*']})),true);
  await runner.close();
  await rm(extension,{recursive:true});await cp(resolve('dist'),extension,{recursive:true});
  await settings.evaluate(async id=>{await new Promise((resolve,reject)=>chrome.developerPrivate.reload(id,{failQuietly:true},()=>chrome.runtime.lastError?reject(Error(chrome.runtime.lastError.message)):resolve()));},id);
  const upgraded=await context.newPage();await upgraded.goto(`chrome-extension://${id}/panel.html`);
  const result=await upgraded.evaluate(async()=>({manifest:chrome.runtime.getManifest(),granted:await chrome.permissions.getAll(),saved:await chrome.permissions.contains({origins:['https://grok.com/*']})}));
  assert.equal(result.manifest.version,JSON.parse(await readFile(resolve('dist/manifest.json'))).version);assert.equal(result.manifest.host_permissions,undefined);assert.equal(result.saved,true);
  assert.deepEqual(result.granted.origins,['https://grok.com/*']);
  for(const forbidden of ['tabs','webNavigation','scripting','activeTab','history']) assert(!result.granted.permissions.includes(forbidden));
  console.log('PASS 0.8.0-to-current-reload-preserves-optional-grant-and-drops-required-verifier-and-history-permissions');
} finally {await context?.close();await rm(temporary,{recursive:true,force:true});}
