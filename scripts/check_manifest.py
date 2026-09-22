"""Check distribution hashes without importing t7 or accessing any device."""
import hashlib
import json
from pathlib import Path
import sys


def main():
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / 'SHA256.json').read_text())
    errors = []
    for name, expected in manifest.items():
        path = (root / name).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            errors.append(f'{name}: missing file or invalid path')
            continue
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            errors.append(f'{name}: SHA-256 mismatch')
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        return 1
    print(f'Verified {len(manifest)} files.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
