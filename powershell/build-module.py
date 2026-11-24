#!/usr/bin/env python3
"""Assemble a Gallery module from the four checksummed release archives."""
import argparse
import hashlib
import re
import shutil
import tarfile
import zipfile
from pathlib import Path

TARGETS = (
    'aarch64-apple-darwin', 'x86_64-apple-darwin',
    'x86_64-unknown-linux-gnu', 'x86_64-pc-windows-msvc',
)
ROOT = Path(__file__).resolve().parents[1]


def stage_module(output, version):
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Version must be a stable three-part version (e.g. 0.2.1)')
    module = output / 'WhereDNS'
    # Never mix stale binaries from a previous version into a package.
    module.mkdir(parents=True, exist_ok=False)
    for name in ('WhereDNS.psd1', 'WhereDNS.psm1'):
        shutil.copyfile(ROOT / 'powershell/WhereDNS' / name, module / name)
    manifest = module / 'WhereDNS.psd1'
    manifest.write_text(manifest.read_text().replace("ModuleVersion = '0.0.0'", f"ModuleVersion = '{version}'"))
    shutil.copyfile(ROOT / 'LICENSE', module / 'LICENSE')
    shutil.copyfile(ROOT / 'powershell/README.md', module / 'README.md')
    return module


def build(artifacts, output, version):
    sums = {}
    for line in (artifacts / 'SHA256SUMS').read_text().splitlines():
        digest, name = line.split(maxsplit=1)
        sums[name.lstrip('*')] = digest.lower()
    binaries = {}
    for target in TARGETS:
        windows = target.endswith('msvc')
        filename = f'wheredns-v{version}-{target}' + ('.zip' if windows else '.tar.gz')
        archive = artifacts / filename
        if hashlib.sha256(archive.read_bytes()).hexdigest() != sums.get(filename):
            raise ValueError(f'Checksum missing or mismatched: {filename}')
        executable = 'wheredns.exe' if windows else 'wheredns'
        # Read only the binary; never extract archive paths into the filesystem.
        if windows:
            with zipfile.ZipFile(archive) as bundle:
                matches = [i for i in bundle.infolist() if Path(i.filename).name == executable and not i.is_dir()]
                if len(matches) != 1:
                    raise ValueError(f'Expected one executable in {filename}')
                data = bundle.read(matches[0])
        else:
            with tarfile.open(archive) as bundle:
                matches = [i for i in bundle.getmembers() if Path(i.name).name == executable and i.isfile()]
                if len(matches) != 1:
                    raise ValueError(f'Expected one executable in {filename}')
                data = bundle.extractfile(matches[0]).read()
        if not data:
            raise ValueError(f'Empty executable in {filename}')
        binaries[target] = (executable, data)
    module = stage_module(output, version)
    for target, (name, data) in binaries.items():
        destination = module / 'bin' / target / name
        destination.parent.mkdir(parents=True)
        destination.write_bytes(data)
        destination.chmod(0o755)
    return module


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    print(build(args.artifacts, args.output, args.version))
