import {mkdir, rm, cp, writeFile} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {resolve, join} from 'node:path';
import {build} from 'esbuild';

const here = fileURLToPath(new URL('./', import.meta.url));
export async function buildCapture(out = resolve(here, '../dist-capture')) {
  await rm(out, {recursive: true, force: true}); await mkdir(out, {recursive: true});
  await build({entryPoints: [join(here, 'probe-background.mjs')], bundle: true, format: 'esm', platform: 'browser', target: 'chrome116', outfile: join(out, 'background.js'), logLevel: 'warning'});
  for (const name of ['probe.html', 'probe.js']) await cp(join(here, name), join(out, name));
  await writeFile(join(out, 'manifest.json'), JSON.stringify({
    manifest_version: 3, minimum_chrome_version: '116', name: 'Pines — provider capture diagnostic', version: '0.1.0',
    description: 'Local ChatGPT request-shape measurements. No proof, receipt, claims or credential export.',
    background: {service_worker: 'background.js', type: 'module'}, action: {default_popup: 'probe.html'},
    permissions: ['tabs', 'webRequest', 'webNavigation'], host_permissions: ['https://chatgpt.com/*'],
    content_security_policy: {extension_pages: "default-src 'self'; script-src 'self'; connect-src 'none'; object-src 'none'; frame-ancestors 'none'"},
  }, null, 2) + '\n');
  await writeFile(join(out, 'build.json'), JSON.stringify({purpose: 'capture-only', claimable: false,
    revision: execFileSync('git', ['rev-parse', 'HEAD'], {cwd: here, encoding: 'utf8'}).trim(),
    dirty: Boolean(execFileSync('git', ['status', '--porcelain'], {cwd: here, encoding: 'utf8'}).trim()),
  }, null, 2) + '\n');
  return out;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) console.log('Built capture-only diagnostic: ' + await buildCapture());
