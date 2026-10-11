#!/usr/bin/env python3
"""Rebuild the pinned TLSNotary browser package in a new private directory.

Usage: prover-wasm.py NEW_OUTPUT_DIRECTORY
Requires git, Python 3, rustup with nightly-2026-05-31/rust-src/wasm32-unknown-unknown,
and network access. Acquires the shared heavy-build lock on this workspace.
The source patch and every final package byte are checked against the public pin.
"""
from pathlib import Path
import fcntl, hashlib, json, os, resource, shutil, subprocess, sys, tarfile, time, urllib.request

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
assert len(sys.argv) == 2 and not out.exists(), 'NEW_OUTPUT_REQUIRED'
out.mkdir(mode=0o700)
pin = json.loads((root / 'apps/tlsn-prover/config/tee-wasm-io.json').read_text())
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
patch = root / 'apps/tlsn-prover/patches/tlsn-wasm-awaited-io.patch'
if not patch.exists():
    matches = [p for p in (root / 'apps/tlsn-prover/patches').glob('*') if p.is_file() and sha(p) == pin['patchSha256']]
    assert len(matches) == 1, 'PATCH_PIN'
    patch = matches[0]
assert sha(patch) == pin['patchSha256'], 'PATCH_PIN'
tools = [
    ('https://github.com/wasm-bindgen/wasm-pack/releases/download/v0.14.0/wasm-pack-v0.14.0-x86_64-unknown-linux-musl.tar.gz',
     '278a8d668085821f4d1a637bd864f1713f872b0ae3a118c77562a308c0abfe8d', 'wasm-pack-v0.14.0-x86_64-unknown-linux-musl'),
    ('https://github.com/wasm-bindgen/wasm-bindgen/releases/download/0.2.120/wasm-bindgen-0.2.120-x86_64-unknown-linux-musl.tar.gz',
     'ceb6f0b9fea9d2868f258215a1d7f86a4c28330a0d64432cc7d53674618772d6', 'wasm-bindgen-0.2.120-x86_64-unknown-linux-musl'),
    ('https://github.com/WebAssembly/binaryen/releases/download/version_117/binaryen-version_117-x86_64-linux.tar.gz',
     '3dc677006555b355ea2da5e82602065a161d5e83eaefd3f759afa00b96e83212', 'binaryen-version_117/bin')]
lock = open('/var/tmp/pines-heavy-build.lock', 'a')
fcntl.flock(lock, fcntl.LOCK_EX)
assert shutil.disk_usage(out).free >= 12 * 1024**3, 'DISK_RESERVE'
tool_dir = out / 'tools'
tool_dir.mkdir()
for i, (url, expected, _) in enumerate(tools):
    archive = tool_dir / (str(i) + '.tar.gz')
    with urllib.request.urlopen(url, timeout=60) as response, archive.open('xb') as stream:
        shutil.copyfileobj(response, stream)
    assert sha(archive) == expected, 'TOOL_HASH'
    with tarfile.open(archive) as contents:
        contents.extractall(tool_dir, filter='data')
source = out / 'tlsn'
subprocess.run(['git', 'clone', '--quiet', '--no-checkout', 'https://github.com/tlsnotary/tlsn.git', str(source)], check=True, timeout=300)
subprocess.run(['git', '-C', str(source), 'checkout', '--quiet', pin['upstreamCommit']], check=True)
subprocess.run(['git', '-C', str(source), 'apply', str(patch)], check=True)
assert sha(source / 'crates/wasm/src/io.rs') == pin['ioSourceSha256'], 'IO_SOURCE_HASH'
env = {k:v for k,v in os.environ.items() if k not in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS']}
env.update(RUSTC_WRAPPER='', RUSTC_WORKSPACE_WRAPPER='', RUSTUP_TOOLCHAIN='nightly-2026-05-31',
           CARGO_BUILD_JOBS='2', CARGO_TARGET_DIR=str(out / 'target'), WASM_PACK_CACHE=str(out / 'cache'),
           PATH=':'.join(str(tool_dir / t[2]) for t in tools) + ':' + env['PATH'])
def bounds():
    os.setsid()
    os.nice(10)
    os.sched_setaffinity(0, sorted(os.sched_getaffinity(0))[-2:])
    resource.setrlimit(resource.RLIMIT_AS, (8*1024**3, 8*1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (4*1024**3, 4*1024**3))
command = ['wasm-pack','build','--profile','wasm','--target','web','--mode','no-install','--out-dir',str(out/'package'),'.','--locked']
with (out / 'build.log').open('x') as log:
    process = subprocess.Popen(command, cwd=source/'crates/wasm', env=env, stdout=log, stderr=subprocess.STDOUT, preexec_fn=bounds)
    start = time.monotonic()
    try:
        while process.poll() is None:
            assert time.monotonic()-start < 1500, 'BUILD_DEADLINE'
            assert shutil.disk_usage(out).free >= 8*1024**3, 'DISK_RESERVE'
            time.sleep(.5)
        assert process.returncode == 0, 'WASM_BUILD_FAILED'
    finally:
        if process.poll() is None:
            import signal
            os.killpg(process.pid, signal.SIGTERM)
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
package = out / 'package'
snippets = list((package / 'snippets').rglob('spawn.js'))
assert len(snippets) == 1
snippet = snippets[0]
value = snippet.read_text()
assert value.count("import('../../..')") == 2
snippet.write_text(value.replace("import('../../..')", "import('../../../tlsn_wasm.js')"))
shutil.copyfile(snippet, package / 'spawn.js')
metadata = package / 'package.json'
value = json.loads(metadata.read_text())
value['files'] += ['tlsn_wasm_bg.wasm.d.ts', 'spawn.js', 'snippets/']
metadata.write_text(json.dumps(value, indent=2)+'\n')
(package / '.gitignore').unlink(missing_ok=True)
actual = {p.relative_to(package).as_posix():sha(p) for p in package.rglob('*') if p.is_file()}
report = {'passed': actual == pin['files'], 'sourceCommit':pin['upstreamCommit'], 'patchSha256':pin['patchSha256'],
          'toolArchives':[t[1] for t in tools], 'files':actual, 'hardwareExecuted':False}
(out / 'result.json').write_text(json.dumps(report, indent=2)+'\n')
assert report['passed'], 'PACKAGE_DIFFERS_FROM_PIN'
print(json.dumps({'passed':True, 'wasmSha256':actual['tlsn_wasm_bg.wasm']}))
