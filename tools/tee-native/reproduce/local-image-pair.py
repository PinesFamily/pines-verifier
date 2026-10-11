#!/usr/bin/env python3
"""Build two clean enclave images from one sealed context and compare their measurements.

Usage:
  local-image-pair.py --context DIR --manifest-sha256 HEX --output NEW_DIR --label LABEL
                      [--eif-name NAME] [--profile NAME] [--build-minutes N] [--nitro-image IMAGE]
                      [--minimum-free-gib N] [--builder-network host]

DIR is a context made by ../prepare-image.py (or a fixture overlay of one) and HEX the
SHA-256 of its context-manifest.json, recorded before this runs. Each build uses a fresh,
memory/CPU-bounded BuildKit container (pinned image), --no-cache, the manifest's
sourceEpoch as SOURCE_DATE_EPOCH, then packages the EIF with the pinned Nitro toolchain
image. Never runs a native verifier, an enclave or any AWS call; never reads env or state.
The result is reproduction evidence only: hardwareQualified stays false.

Ported from the reviewed private 1.5.x reproduction runners (tee-three-provider-images-*
reproduce-local.py): same ownership labels, absolute deadlines, disk/memory bounds,
in-image source check and cleanup of only what this run created.
"""
import argparse, datetime, fcntl, hashlib, json, os, pathlib, re, shutil, signal, subprocess, sys, time, uuid

BUILDER_IMAGE = 'moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8'
BUILDER_IMAGE_ID = 'sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8'
# Default Nitro packaging toolchain: the local Amazon Linux 2023 + aws-nitro-enclaves-cli image
# the qualified 1.5.x images used. PCR1 comes from the kernel/init blobs it ships; another
# toolchain (for example one built from Dockerfile.nitro-cli) must reproduce PCR1 to be equivalent.
DEFAULT_TOOL_IMAGE = 'sha256:d5accbaf08c3e57d0318280a1fc93bfa259dcde6a6e2f711324e28d001e26237'
LABEL_KEY = 'PinesLocalReproduction'
GIB = 1024 ** 3


def parse():
    p = argparse.ArgumentParser()
    p.add_argument('--context', required=True)
    p.add_argument('--manifest-sha256', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--label', required=True)
    p.add_argument('--eif-name', default='pines-normal-redacted.eif')
    p.add_argument('--profile', default='normal-redacted')
    p.add_argument('--build-minutes', type=int, default=60)
    # Free space required before each build. A measured build peaks at about 3.9 GiB, and the 8 GiB
    # abort floor below is unchanged, so 12 GiB still leaves the machine more than 8 GiB at the peak.
    p.add_argument('--minimum-free-gib', type=int, default=15)
    # The BuildKit container's own network. The default is Docker's bridge; `host` is for a daemon whose
    # bridge device is missing. Source, extract, package and describe stay --network none.
    p.add_argument('--builder-network', choices=['host'], default=None)
    p.add_argument('--nitro-image', default=DEFAULT_TOOL_IMAGE)
    a = p.parse_args()
    assert re.fullmatch(r'[a-f0-9]{64}', a.manifest_sha256), 'MANIFEST_SHA256'
    assert re.fullmatch(r'[a-z0-9][a-z0-9-]{2,40}', a.label), 'LABEL'
    assert re.fullmatch(r'[a-z0-9][a-z0-9.-]{2,60}\.eif', a.eif_name), 'EIF_NAME'
    assert re.fullmatch(r'[a-z0-9-]{3,40}', a.profile), 'PROFILE'
    assert 10 <= a.build_minutes <= 180, 'BUILD_MINUTES'
    assert 12 <= a.minimum_free_gib <= 15, 'MINIMUM_FREE_GIB'
    assert re.fullmatch(r'sha256:[a-f0-9]{64}|[a-z0-9][a-z0-9._/-]{0,100}(:[A-Za-z0-9._-]{1,64})?', a.nitro_image), 'NITRO_IMAGE'
    return a


A = parse()
CONTEXT = pathlib.Path(A.context).resolve()
ROOT = pathlib.Path(A.output).resolve()
assert (CONTEXT / 'context-manifest.json').is_file(), 'CONTEXT_MANIFEST'
assert not ROOT.exists(), 'OUTPUT_MUST_BE_NEW'
MANIFEST = json.loads((CONTEXT / 'context-manifest.json').read_text())
EPOCH = int(MANIFEST['sourceEpoch'])
ENV = {k: os.environ[k] for k in ['PATH', 'HOME', 'USER', 'LOGNAME'] if k in os.environ}
TOOL_IMAGE = A.nitro_image
# Disk bounds watch the filesystem Docker actually writes to.
DOCKER_ROOT = pathlib.Path(subprocess.check_output(['docker', 'info', '--format', '{{.DockerRootDir}}'], env=ENV, text=True, timeout=30).strip())
assert DOCKER_ROOT.is_absolute(), 'DOCKER_ROOT'
RUN_ID = uuid.uuid4().hex
BUILDER = f'pines-pair-{A.label}'
IMAGES = [f'pines-pair-{A.label}:{n}' for n in [1, 2]]
NAMES = [f'{BUILDER}-{kind}-{n}' for n in [1, 2] for kind in ['source', 'extract', 'package', 'describe']]
BUILDER_RECORD = pathlib.Path(ENV['HOME']) / '.docker/buildx/instances' / BUILDER
BUILD_STOP = int(time.time()) + A.build_minutes * 60
CLEANUP_STOP = BUILD_STOP + 240
CLOCK_OFFSET = time.monotonic() - time.time()
CLEANING = False
created_builder = False
builder_create_attempted = False
created_containers = {}
loaded_images = {}


def budget(seconds):
    deadline = CLEANUP_STOP if CLEANING else BUILD_STOP
    available = min(deadline - time.time(), deadline + CLOCK_OFFSET - time.monotonic())
    if available <= 0:
        raise RuntimeError('ABSOLUTE_LOCAL_ARTIFACT_DEADLINE')
    return min(seconds, available)


def acquire(lock):
    while True:
        budget(1)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            time.sleep(min(.2, budget(.2)))


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def write(name, value):
    p = ROOT / name
    with p.open('x') as f:
        json.dump(value, f, indent=2)
        f.write('\n')
    p.chmod(0o600)


def event(stage, **kw):
    record = {'at': stamp(), 'stage': stage, **kw}
    with (ROOT / 'events.jsonl').open('a') as f:
        f.write(json.dumps(record) + '\n')
    print(json.dumps(record), flush=True)


def disk():
    return {'dockerFreeBytes': shutil.disk_usage(DOCKER_ROOT).free, 'artifactFreeBytes': shutil.disk_usage(ROOT).free}


def available_memory():
    values = dict(line.split(':', 1) for line in pathlib.Path('/proc/meminfo').read_text().splitlines())
    return int(values['MemAvailable'].split()[0]) * 1024


def inspect_container(name):
    r = subprocess.run(['docker', 'container', 'inspect', name], env=ENV, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, timeout=budget(30))
    return json.loads(r.stdout)[0] if r.returncode == 0 else None


def verify_context(build):
    manifest_path = CONTEXT / 'context-manifest.json'
    assert digest(manifest_path) == A.manifest_sha256, 'SEALED_MANIFEST_CHANGED'
    m = json.loads(manifest_path.read_text())
    assert m['sourceDirty'] is False and re.fullmatch(r'[a-f0-9]{40}', m['sourceCommit']) and int(m['sourceEpoch']) == EPOCH
    actual = {str(p.relative_to(CONTEXT)) for p in CONTEXT.rglob('*') if p.is_file() and p != manifest_path}
    assert actual == set(m['files']), 'CONTEXT_FILE_SET_CHANGED'
    for name, expected in m['files'].items():
        p = CONTEXT / name
        assert p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(CONTEXT), 'CONTEXT_PATH_INVALID'
        assert digest(p) == expected, 'CONTEXT_FILE_CHANGED:' + name
    event('sealed-context-verified', build=build, files=len(m['files']), manifestSha256=A.manifest_sha256)


def run(args, log, timeout=120, output=False):
    timeout = budget(timeout)
    p = ROOT / log
    with p.open('xb') as f:
        process = subprocess.Popen(args, cwd=ROOT, env=ENV, stdout=f, stderr=subprocess.STDOUT, start_new_session=True)
        start = time.monotonic()
        last_sample = 0
        try:
            while process.poll() is None:
                budget(1)
                sample = disk()
                if time.monotonic() - last_sample >= 10:
                    with (ROOT / 'disk-watch.jsonl').open('a') as monitor:
                        monitor.write(json.dumps({'at': stamp(), 'commandLog': log,
                                                  'availableMemoryBytes': available_memory(), **sample}) + '\n')
                    last_sample = time.monotonic()
                if time.monotonic() - start > timeout or min(sample.values()) < 8 * GIB or available_memory() < 6 * GIB:
                    raise RuntimeError('LOCAL_BUILD_TIME_OR_DISK_BOUND:' + log)
                time.sleep(2)
            if process.returncode:
                raise RuntimeError('LOCAL_COMMAND_FAILED:' + log + ':' + str(process.returncode))
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
            raise
    p.chmod(0o600)
    return p.read_text() if output else None


def remember_container(name):
    c = inspect_container(name)
    if c is None:
        return None
    assert c.get('Config', {}).get('Labels', {}).get(LABEL_KEY) == RUN_ID, 'CONTAINER_OWNERSHIP_MISMATCH'
    assert c['Name'] == '/' + name, 'CONTAINER_NAME_MISMATCH'
    created_containers[c['Id']] = name
    return c['Id']


def create_container(n, kind, args):
    name = f'{BUILDER}-{kind}-{n}'
    assert name in NAMES and inspect_container(name) is None, 'CONTAINER_PREEXISTS'
    try:
        raw = run(['docker', 'create', '--name', name, '--label', f'{LABEL_KEY}={RUN_ID}', *args],
                  f'build{n}/{kind}-create.log', output=True)
        cid = remember_container(name)
        assert cid and raw.strip() == cid, 'CONTAINER_CREATE_ACK_MISMATCH'
        return cid
    except BaseException:
        # A lost CLI ACK may leave a container; only our unguessable run label proves ownership.
        remember_container(name)
        raise


def remove_container(cid, log):
    assert cid in created_containers, 'CONTAINER_NOT_CREATED_BY_RUN'
    c = inspect_container(cid)
    if c is None:
        del created_containers[cid]
        return
    assert c.get('Config', {}).get('Labels', {}).get(LABEL_KEY) == RUN_ID and c['Name'] == '/' + created_containers[cid], \
        'CONTAINER_OWNERSHIP_MISMATCH'
    run(['docker', 'rm', cid], log)
    del created_containers[cid]


def execute_container(n, kind, args, log, timeout=120, output=False):
    cid = create_container(n, kind, args)
    raw = run(['docker', 'start', '--attach', cid], log, timeout=timeout, output=output)
    c = inspect_container(cid)
    assert c and not c['State']['Running'] and c['State']['ExitCode'] == 0, 'CONTAINER_COMMAND_FAILED'
    remove_container(cid, f'build{n}/{kind}-remove.log')
    return raw


def package(n, image):
    build = ROOT / f'build{n}'
    (build / 'extracted').mkdir()
    script = ('const fs=require("node:fs"),crypto=require("node:crypto"),files={};'
              'for(const [name,hash] of Object.entries(JSON.parse(fs.readFileSync("/context-manifest.json")).files)){'
              'if(!name.startsWith("tools/tee-native/")&&!name.startsWith("packages/verification-schemas/"))continue;'
              'const actual=crypto.createHash("sha256").update(fs.readFileSync("/app/"+name)).digest("hex");'
              'if(actual!==hash)throw Error("IMAGE_SOURCE_MISMATCH: "+name);files[name]=actual;}'
              'console.log(JSON.stringify({matched:true,files}));')
    execute_container(n, 'source', ['--network', 'none', '--cpus', '2', '--memory', '2g', '--mount',
                                    f'type=bind,src={CONTEXT}/context-manifest.json,dst=/context-manifest.json,readonly',
                                    '--entrypoint', '/usr/local/bin/node', image, '-e', script],
                      f'build{n}/runtime-source-manifest.json')
    actual_sources = json.loads((build / 'runtime-source-manifest.json').read_text())
    expected_sources = {name: sha for name, sha in MANIFEST['files'].items()
                        if name.startswith(('tools/tee-native/', 'packages/verification-schemas/'))}
    assert actual_sources == {'matched': True, 'files': expected_sources}, 'COPIED_RUNTIME_MANIFEST_CHANGED'
    cid = create_container(n, 'extract', ['--network', 'none', image])
    for binary, source in [('pines-nitro-runtime', '/app/bin/pines-nitro-runtime'), ('tee-hardware', '/app/bin/tee-hardware'), ('tee-identity', '/app/bin/tee-identity'),
                           ('node', '/usr/local/bin/node')]:
        run(['docker', 'cp', f'{cid}:{source}', str(build / 'extracted' / binary)], f'build{n}/copy-{binary}.log')
    remove_container(cid, f'build{n}/extract-remove.log')
    raw = run(['docker', 'image', 'inspect', image], f'build{n}/docker-image.json', output=True)
    assert json.loads(raw)[0]['Architecture'] == 'amd64'
    eif = A.eif_name
    package_script = (f'nitro-cli build-enclave --docker-uri "$1" --output-file /out/{eif}; code=$?; '
                      f'chown {os.getuid()}:{os.getgid()} /out/{eif} 2>/dev/null || true; exit "$code"')
    with open('/var/tmp/pines-heavy-job.lock', 'a') as lock:
        acquire(lock)
        execute_container(n, 'package', ['--network', 'none', '--cpus', '2', '--memory', '4g', '--mount',
                                         'type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock', '--mount',
                                         f'type=bind,src={build},dst=/out', '--entrypoint', '/bin/bash', TOOL_IMAGE, '-c',
                                         package_script, '--', image], f'build{n}/eif-build.log', timeout=900)
    raw = execute_container(n, 'describe', ['--network', 'none', '--cpus', '2', '--memory', '2g', '--mount',
                                            f'type=bind,src={build},dst=/out,readonly', '--entrypoint', 'nitro-cli', TOOL_IMAGE,
                                            'describe-eif', '--eif-path', f'/out/{eif}'],
                            f'build{n}/eif-describe.json', output=True)
    description = json.loads(raw)
    assert description['CheckCRC'] is True
    assert all(len(description['Measurements'][key]) == 96 and set(description['Measurements'][key]) <= set('0123456789abcdef')
               and set(description['Measurements'][key]) != {'0'} for key in ['PCR0', 'PCR1', 'PCR2'])
    (build / eif).chmod(0o444)
    hashes = {f.name: digest(f) for f in [build / 'image.tar', build / eif, *(build / 'extracted').iterdir()]}
    write(f'build{n}/hashes.json', hashes)
    event('local-image-packaged', build=n, eifSha256=hashes[eif], hardwareQualified=False, activated=False)
    return description, hashes


def remove_image(tag):
    """Remove only a tag this run loaded, and only while it still names the loaded image id."""
    r = subprocess.run(['docker', 'image', 'inspect', '--format', '{{.Id}}', tag], env=ENV, capture_output=True, text=True,
                       timeout=budget(30))
    if r.returncode != 0:
        return {'image': tag, 'alreadyAbsent': True}
    assert r.stdout.strip() == loaded_images[tag], 'IMAGE_OWNERSHIP_MISMATCH'
    r = subprocess.run(['docker', 'image', 'rm', tag], env=ENV, capture_output=True, text=True, timeout=budget(60))
    return {'image': tag, 'removed': r.returncode == 0}


def terminate(signum, frame):
    raise InterruptedError('LOCAL_ARTIFACT_TERMINATED')


signal.signal(signal.SIGTERM, terminate)
os.umask(0o077)
ROOT.mkdir(mode=0o700, parents=False)
lock = open('/var/tmp/pines-heavy-build.lock', 'a')
acquire(lock)
result = {'format': 'pines-local-image-pair-v1', 'sourceCommit': MANIFEST['sourceCommit'], 'sourceEpoch': EPOCH,
          'hardwareQualified': False, 'capacityQualified': False, 'activated': False, 'profile': A.profile,
          'nativeVerifierExecuted': False, 'contextManifestSha256': A.manifest_sha256, 'contextFiles': len(MANIFEST['files']),
          'startedAt': stamp(), 'buildStopEpoch': BUILD_STOP, 'cleanupStopEpoch': CLEANUP_STOP, 'runId': RUN_ID,
          'builder': BUILDER, 'builderImage': BUILDER_IMAGE, 'nitroPackagingImage': TOOL_IMAGE, 'eifName': A.eif_name,
          'dockerRoot': str(DOCKER_ROOT),
          'builderNetwork': A.builder_network or 'bridge', 'limits': {'buildCpu': 2, 'buildMemoryBytes': 12 * GIB, 'minimumFreeBeforeEachBuildBytes': A.minimum_free_gib * GIB,
                     'diskAbortBytes': 8 * GIB, 'minimumAvailableMemoryBeforeBuildBytes': 18 * GIB, 'memoryAbortBytes': 6 * GIB,
                     'watchedPaths': [str(ROOT), str(DOCKER_ROOT)]}}
try:
    assert subprocess.check_output(['docker', 'info', '--format', '{{.DockerRootDir}}'], env=ENV, text=True,
                                   timeout=budget(10)).strip() == str(DOCKER_ROOT), 'DOCKER_ROOT_CHANGED'
    assert subprocess.run(['docker', 'image', 'inspect', TOOL_IMAGE], env=ENV, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, timeout=budget(30)).returncode == 0, 'NITRO_IMAGE_ABSENT'
    assert not BUILDER_RECORD.exists(), 'BUILDER_RECORD_ALREADY_EXISTS'
    existing = subprocess.run(['docker', 'buildx', 'inspect', BUILDER], env=ENV, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=budget(10))
    assert existing.returncode != 0, 'BUILDER_ALREADY_EXISTS'
    assert inspect_container(f'buildx_buildkit_{BUILDER}0') is None, 'BUILDER_CONTAINER_ALREADY_EXISTS'
    for name in NAMES:
        assert inspect_container(name) is None, 'CONTAINER_ALREADY_EXISTS:' + name
    for image in IMAGES:
        assert subprocess.run(['docker', 'image', 'inspect', image], env=ENV, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=budget(10)).returncode != 0, 'IMAGE_TAG_ALREADY_EXISTS'
    assert subprocess.run(['docker', 'volume', 'inspect', f'buildx_buildkit_{BUILDER}0_state'], env=ENV,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=budget(10)).returncode != 0, \
        'BUILDER_VOLUME_ALREADY_EXISTS'
    verify_context(0)
    event('preparation-verified', **disk())
    builder_create_attempted = True
    run(['docker', 'buildx', 'create', '--name', BUILDER, '--driver', 'docker-container', '--driver-opt',
         f'image={BUILDER_IMAGE},memory=12g,memory-swap=12g,cpu-period=100000,cpu-quota=200000,restart-policy=no,'
         f'env.PINES_LOCAL_REPRODUCTION={RUN_ID}' + (f',network={A.builder_network}' if A.builder_network else '')],
        'builder-create.log')
    created_builder = True
    run(['docker', 'buildx', 'inspect', BUILDER, '--bootstrap'], 'builder-inspect.log', timeout=300)
    c = json.loads(run(['docker', 'inspect', f'buildx_buildkit_{BUILDER}0'], 'builder-container.json', output=True))[0]
    assert c['HostConfig']['Memory'] == 12 * GIB and c['HostConfig']['MemorySwap'] == 12 * GIB
    assert c['HostConfig']['CpuPeriod'] == 100000 and c['HostConfig']['CpuQuota'] == 200000
    assert c['HostConfig']['RestartPolicy']['Name'] == 'no' and c['Image'] == BUILDER_IMAGE_ID
    assert c['HostConfig']['NetworkMode'] == (A.builder_network or c['HostConfig']['NetworkMode']), 'BUILDER_NETWORK'
    event('bounded-builder-ready', memoryBytes=c['HostConfig']['Memory'], cpuQuota=c['HostConfig']['CpuQuota'])
    packaged = []
    for n, image in enumerate(IMAGES, 1):
        verify_context(n)
        assert min(disk().values()) >= A.minimum_free_gib * GIB, 'INSUFFICIENT_DISK_BEFORE_BUILD'
        assert available_memory() >= 18 * GIB, 'INSUFFICIENT_MEMORY_BEFORE_BUILD'
        build = ROOT / f'build{n}'
        build.mkdir()
        event('build-started', build=n, **disk())
        run(['docker', 'buildx', 'build', '--builder', BUILDER, '--no-cache', '--progress', 'plain', '--platform', 'linux/amd64',
             '--build-arg', f'SOURCE_DATE_EPOCH={EPOCH}', '--file', str(CONTEXT / 'tools/tee-native/hardware/Dockerfile.preparation'),
             '--output', f'type=docker,dest={build}/image.tar,rewrite-timestamp=true', '--tag', image, str(CONTEXT)],
            f'build{n}/docker-build.log', timeout=3600)
        event('build-compiled', build=n, tarBytes=(build / 'image.tar').stat().st_size)
        # Every build is --no-cache, so dropping this run's own builder cache changes nothing
        # but the disk the next build needs.
        run(['docker', 'buildx', 'prune', '--builder', BUILDER, '--all', '--force'], f'build{n}/builder-prune.log', timeout=300)
        run(['docker', 'load', '--input', str(build / 'image.tar')], f'build{n}/docker-load.log', timeout=300)
        loaded_images[image] = subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', image], env=ENV,
                                                       text=True, timeout=budget(30)).strip()
        packaged.append(package(n, image))
    first, second = packaged
    assert first[0]['Measurements'] == second[0]['Measurements'], 'EIF_MEASUREMENTS_DIFFER'
    assert json.loads((ROOT / 'build1/runtime-source-manifest.json').read_text()) == \
        json.loads((ROOT / 'build2/runtime-source-manifest.json').read_text()), 'RUNTIME_SOURCE_MANIFESTS_DIFFER'
    for name in ['node', 'pines-nitro-runtime', 'tee-hardware', 'tee-identity']:
        assert first[1][name] == second[1][name], 'EXECUTABLE_DIFFER:' + name
    verify_context(3)
    result.update(passed=True, reproduciblePcrs=True, reproducibleExecutables=True, measurements=first[0]['Measurements'],
                  imageIdsEqual=len(set(loaded_images.values())) == 1,
                  builds=[{'eifSha256': v[1][A.eif_name], 'imageTarSha256': v[1]['image.tar'], 'crcVerified': v[0]['CheckCRC'],
                           'executables': {k: v[1][k] for k in ['node', 'pines-nitro-runtime', 'tee-hardware', 'tee-identity']}} for v in packaged])
    event('reproduction-passed', hardwareQualified=False, activated=False)
except BaseException as error:
    result.update(passed=False, error=type(error).__name__ + ':' + str(error))
    event('build-stopped', error=result['error'])
finally:
    CLEANING = True
    cleanup = []
    for cid, name in list(created_containers.items()):
        try:
            c = inspect_container(cid)
            if c is None:
                cleanup.append({'container': name, 'alreadyAbsent': True})
                continue
            assert c.get('Config', {}).get('Labels', {}).get(LABEL_KEY) == RUN_ID and c['Name'] == '/' + name, \
                'CONTAINER_OWNERSHIP_MISMATCH'
            r = subprocess.run(['docker', 'rm', '--force', cid], env=ENV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               timeout=budget(60))
            cleanup.append({'container': name, 'createdByRun': True, 'removed': r.returncode == 0})
        except (OSError, subprocess.TimeoutExpired, AssertionError, RuntimeError) as error:
            cleanup.append({'container': name, 'removed': False, 'error': type(error).__name__})
    for tag in list(loaded_images):
        try:
            cleanup.append(remove_image(tag))
        except (OSError, subprocess.TimeoutExpired, AssertionError, RuntimeError) as error:
            cleanup.append({'image': tag, 'removed': False, 'error': type(error).__name__})
    if builder_create_attempted:
        try:
            if BUILDER_RECORD.exists():
                b = json.loads(BUILDER_RECORD.read_text())
                nodes = b.get('Nodes', [])
                assert b.get('Name') == BUILDER and b.get('Driver') == 'docker-container' and len(nodes) == 1, \
                    'BUILDER_OWNERSHIP_MISMATCH'
                opts = nodes[0].get('DriverOpts', {})
                assert opts.get('env.PINES_LOCAL_REPRODUCTION') == RUN_ID and opts.get('image') == BUILDER_IMAGE, \
                    'BUILDER_OWNERSHIP_MISMATCH'
                created_builder = True
            elif not created_builder:
                cleanup.append({'builder': BUILDER, 'createdByRun': False, 'alreadyAbsent': True})
            else:
                raise RuntimeError('OWNED_BUILDER_RECORD_DISAPPEARED')
            if created_builder:
                with (ROOT / 'builder-cleanup.log').open('xb') as f:
                    r = subprocess.run(['docker', 'buildx', 'rm', BUILDER], env=ENV, stdout=f, stderr=subprocess.STDOUT,
                                       timeout=budget(120))
                cleanup.append({'builder': BUILDER, 'createdByRun': True, 'removed': r.returncode == 0})
        except (OSError, subprocess.TimeoutExpired, AssertionError, RuntimeError, ValueError) as error:
            cleanup.append({'builder': BUILDER, 'removed': False, 'error': type(error).__name__})
    if any(c.get('removed') is False for c in cleanup):
        result['passed'] = False
        result['cleanupFailed'] = True
    result.update(cleanup=cleanup, finishedAt=stamp(), freeBytesAfter=disk())
    write('reproduction-result.json', result)
    print(json.dumps({'passed': result.get('passed'), 'result': str(ROOT / 'reproduction-result.json'),
                      'finishedAt': result['finishedAt']}), flush=True)
    raise SystemExit(0 if result.get('passed') else 1)
