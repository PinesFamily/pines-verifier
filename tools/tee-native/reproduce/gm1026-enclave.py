#!/usr/bin/env python3
"""Rebuild an exported recovery image twice from its exact measured context.

Usage: gm1026-enclave.py ordinary|email NEW_OUTPUT_DIR --nitro-image IMAGE
The exported measured-contexts directory must be present. No AWS operation runs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('image', choices=['ordinary', 'email'])
parser.add_argument('output', type=Path)
parser.add_argument('--nitro-image', required=True)
args = parser.parse_args()
record = json.loads((root / 'tools/tee-native/reproduce/gm1026' / (args.image + '.json')).read_bytes())
context = root / 'measured-contexts' / args.image
raw = (context / 'context-manifest.json').read_bytes()
assert hashlib.sha256(raw).hexdigest() == record['contextManifestSha256']
manifest = json.loads(raw)
assert all(hashlib.sha256((context / name).read_bytes()).hexdigest() == digest
           for name, digest in manifest['files'].items())
subprocess.run([sys.executable, str(root / 'tools/tee-native/reproduce/local-image-pair.py'),
    '--context', str(context), '--manifest-sha256', record['contextManifestSha256'],
    '--output', str(args.output.resolve()), '--label', 'gm1026-' + args.image,
    '--profile', record['profile'], '--nitro-image', args.nitro_image], check=True)
result = json.loads((args.output / 'reproduction-result.json').read_bytes())
assert [result['measurements']['PCR' + str(i)] for i in range(3)] == record['pcrs']
assert all(build['executables'] == record['executables'] for build in result['builds'])
print('PCR0/PCR1/PCR2 and executable hashes match the recovery release.')
