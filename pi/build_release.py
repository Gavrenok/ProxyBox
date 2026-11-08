#!/usr/bin/env python3
"""Build a reproducible public release from reviewed source files only.

No repository scan is used: runtime credentials, research, vendor firmware and
historical deployment scripts cannot enter a release through an extra file.
The manifest proves bundle integrity, not publisher authenticity.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]
APP_FILES = (
    'connectivity.py',
    'devices.py', 'fastswitch.py', 'geobox.nft', 'geobox.py',
    'ios_location_panel.py', 'ios_location.js', 'ios_location.py', 'ios_pairing.py',
    'ipv6_policy.py', 'ipv6_probe.py', 'ipv6-network-setup.sh',
    'library_panel.py', 'library.py', 'mimic.js', 'mimic.py', 'net-up.sh',
    'network_audit.py', 'notify.py', 'panel_runtime.py', 'panel.js',
    'speedtest.py', 'switching.py', 'traffic.py', 'tun-route.sh', 'udp_probe.py',
)
HELPERS = ('ios_device_bridge.py', 'ios_pairing_worker.py')
SYSTEM_FILES = (
    'geobox-net.service', 'geobox-singbox.service', 'geobox-panel.service',
    'geobox.conf', 'geobox-ipv6.conf',
)
FILES = {
    **{'app/' + name: 'pi/app/' + name for name in APP_FILES},
    **{'app/' + name: 'pi/' + name for name in HELPERS},
    **{'system/' + name: 'pi/system/' + name for name in SYSTEM_FILES},
    'install.py': 'pi/install.py',
    'README.md': 'README.md',
    'README.ru.md': 'README.ru.md',
}


def source_payload(root):
    root = Path(root).resolve(strict=True)
    payload = {}
    for destination, relative in sorted(FILES.items()):
        source = root / relative
        # Reject linked files AND linked parent directories, even if their
        # destination is currently inside the repository.
        cursor = source
        while cursor != root:
            if cursor.is_symlink():
                raise ValueError('Release source must not be a symlink: ' + relative)
            cursor = cursor.parent
        if not source.is_file():
            raise ValueError('Required release source missing: ' + relative)
        payload[destination] = source.read_bytes()
    manifest = {'format': 1, 'files': {
        name: hashlib.sha256(data).hexdigest() for name, data in payload.items()
    }}
    payload['manifest.json'] = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode('utf-8')
    return payload


def write_archive(stream, payload):
    # Suppress output filename and timestamp in gzip as well as all host file
    # metadata in tar. The same bytes produce the same artifact on every host.
    with gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0, compresslevel=9) as compressed:
        with tarfile.open(mode='w', fileobj=compressed, format=tarfile.USTAR_FORMAT) as archive:
            for name, data in sorted(payload.items()):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o755 if name.endswith('.sh') or name == 'install.py' else 0o644
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = ''
                archive.addfile(info, io.BytesIO(data))


def build(output, root=ROOT):
    root = Path(root).resolve(strict=True)
    output = Path(output).absolute()
    if output.resolve() in {(root / name).resolve() for name in FILES.values()}:
        raise ValueError('Output would overwrite a release source')
    payload = source_payload(root)  # Validate everything before changing output.
    output.parent.mkdir(parents=True, exist_ok=True)
    pending = None
    try:
        with tempfile.NamedTemporaryFile(mode='wb', dir=output.parent,
                                         prefix='.geobox-release-', delete=False) as stream:
            pending = Path(stream.name)
            write_archive(stream, payload)
            stream.flush()
            os.fsync(stream.fileno())
        digest = hashlib.sha256(pending.read_bytes()).hexdigest()
        os.replace(pending, output)
        return {'artifact': str(output), 'sha256': digest,
                'files': len(payload), 'bytes': output.stat().st_size}
    finally:
        if pending is not None:
            pending.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path,
                        help='Destination .tar.gz file; never includes local runtime data')
    args = parser.parse_args()
    try:
        result = build(args.output)
    except (OSError, ValueError) as exc:
        parser.exit(1, 'Release build failed: ' + str(exc) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
