"""Create a local, checksum-pinned Arch build input from manifest-listed files.

No runtime records, virtual environments or untracked files are collected.
Run makepkg separately as a normal user; this script does not install anything.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]
NAME = 'samsung-t7-ssd-linux-0.1.0.dev1'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((ROOT / 'SHA256.json').read_text())
    payloads = {}
    for name, expected in manifest.items():
        path = (ROOT / name).resolve()
        if not path.is_relative_to(ROOT) or not path.is_file():
            raise SystemExit(f'Invalid source path: {name}')
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise SystemExit(f'SHA-256 mismatch: {name}')
        payloads[name] = data
    payloads['SHA256.json'] = (ROOT / 'SHA256.json').read_bytes()
    args.out.mkdir(parents=True, exist_ok=True)
    archive = args.out / f'{NAME}.tar.gz'
    with tarfile.open(archive, 'w:gz') as output:
        for name, data in sorted(payloads.items()):
            entry = tarfile.TarInfo(f'{NAME}/{name}')
            entry.size = len(data)
            entry.mode = 0o644
            output.addfile(entry, io.BytesIO(data))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    template = (ROOT / 'packaging/arch/PKGBUILD.in').read_text()
    (args.out / 'PKGBUILD').write_text(template.replace('@SOURCE_SHA256@', digest))
    print(f'Prepared {args.out.resolve()}; run makepkg there as a normal user.')


if __name__ == '__main__':
    main()
