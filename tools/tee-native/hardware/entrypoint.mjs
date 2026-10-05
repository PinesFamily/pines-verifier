import {spawn, execFileSync} from 'node:child_process';
import {existsSync} from 'node:fs';
// No host mode or simulation fallback. Time comes from NSM before any TLSN work.
if (!existsSync('/dev/nsm')) {process.stderr.write('NSM_REQUIRED\n'); process.exit(78);}
try {execFileSync('/app/bin/pines-nitro-runtime', ['clock'], {stdio: 'ignore', timeout: 5000});}
catch {process.stderr.write('CLOCK_PROVENANCE\n'); process.exit(78);}
try {execFileSync('/app/bin/pines-nitro-runtime', ['loopback'], {stdio: 'ignore', timeout: 5000});}
catch {process.stderr.write('LOOPBACK_REQUIRED\n');process.exit(78);}
const children = [];
let stopping = false;
function stop() {if (stopping) return; stopping = true; for (const c of children) c.kill('SIGTERM');
  setTimeout(() => {for (const c of children) c.kill('SIGKILL'); process.exit(1);}, 2500).unref();}
for (const mode of ['enclave-ingress', 'enclave-egress']) {
  const child = spawn('/app/bin/pines-nitro-runtime', [mode], {stdio: 'ignore'}); children.push(child); child.on('exit', stop); child.on('error', stop);
}
const app = spawn(process.execPath, ['/app/tools/tee-native/hardware/enclave.mjs'], {stdio: 'ignore', env: {PATH: '/usr/local/bin:/usr/bin:/bin'}});
children.push(app); app.on('exit', stop); app.on('error', stop);
process.on('SIGTERM', stop); process.on('SIGINT', stop);
