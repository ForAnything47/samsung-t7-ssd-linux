"""Keep packaged runtime records separate from installed program files.

An unpacked source tree retains its existing application-relative records.
Only the known Arch package location switches to the matching /var/opt tree;
no existing records are moved or removed.
"""

from pathlib import Path


BASE = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = Path("/opt/samsung-t7-ssd-linux")
PACKAGE_DATA_ROOT = Path("/var/opt/samsung-t7-ssd-linux")


def data_root():
    """Return the runtime-record root for this exact application location."""
    return PACKAGE_DATA_ROOT if BASE == PACKAGE_ROOT else BASE
