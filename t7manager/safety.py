"""Disk usage, exclusive access and local-output safety checks."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import stat
import subprocess

from t7manager import errors


# Gather all active-use indicators, not just the visible mount point.
# A zero inflight count is a snapshot; callers repeat the check before each I/O.
def usage_snapshot(device, sysroot=Path("/sys/class/block"), procroot=Path("/proc")):
    root = sysroot / Path(device).name
    if (root / "partition").exists():
        raise errors.Stop("whole_disk_required")
    nodes = [root] + [p for p in root.iterdir() if (p / "partition").exists()]
    numbers = {(p / "dev").read_text().strip(): p for p in nodes}
    mounts = []
    for line in (procroot / "self/mountinfo").read_text().splitlines():
        fields = line.split()
        if fields[2] in numbers:
            node = numbers[fields[2]]
            mounts.append(
                {
                    "device_number": fields[2],
                    "device": "/dev/" + node.name,
                    "mountpoint": fields[4],
                    "root": fields[3],
                    "fstype": fields[fields.index("-") + 1],
                    "partition": (node / "partition").exists(),
                    "size_bytes": int((node / "size").read_text()) * 512,
                }
            )
    holders = [p.name for n in nodes for p in (n / "holders").iterdir()]
    inflight = sum(
        (sum((int(v) for v in (n / "inflight").read_text().split())) for n in nodes)
    )
    swaps = []
    for line in (procroot / "swaps").read_text().splitlines()[1:]:
        path = line.split()[0]
        st = os.stat(path)
        number = st.st_rdev if stat.S_ISBLK(st.st_mode) else st.st_dev
        if f"{os.major(number)}:{os.minor(number)}" in numbers:
            swaps.append(path)
    return {
        "mounts": mounts,
        "holders": holders,
        "swaps": swaps,
        "inflight": inflight,
        "idle": not (mounts or holders or swaps or inflight),
    }


def require_idle(device):
    if not usage_snapshot(device)["idle"]:
        raise errors.Stop("device_in_use_unmount_or_stop_disk_work_first")


@contextmanager
def exclusive_device(device):
    fd = os.open(device, os.O_RDONLY | os.O_EXCL | os.O_CLOEXEC)
    try:
        if not stat.S_ISBLK(os.fstat(fd).st_mode):
            raise errors.Stop("not_a_block_device")
        yield
    finally:
        os.close(fd)


def backing_disks(number, sysroot=Path("/sys/dev/block"), seen=None):
    """Resolve partitions and stacked block devices to physical whole disks."""
    seen = set() if seen is None else set(seen)
    if number in seen:
        raise errors.Stop("output_block_topology_cycle")
    seen.add(number)
    node = (sysroot / number).resolve(strict=True)
    if (node / "partition").exists():
        return backing_disks((node.parent / "dev").read_text().strip(), sysroot, seen)
    slaves = list((node / "slaves").iterdir())
    if slaves:
        result = set()
        for slave in slaves:
            result |= backing_disks((slave / "dev").read_text().strip(), sysroot, seen)
        return result
    if not (node / "device").exists():
        raise errors.Stop("output_backing_device_unverified")
    return {str(node)}


# Keep operation logs and optional results off the SSD being modified.
# Resolve backing storage, including multi-device Btrfs, rather than trusting paths.
def local_output(out, info):
    ancestor = out.resolve()
    while not ancestor.exists():
        ancestor = ancestor.parent
    r = subprocess.run(
        [
            "findmnt",
            "--json",
            "--target",
            str(ancestor),
            "--output",
            "SOURCE,FSTYPE,UUID,MAJ:MIN",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    filesystems = json.loads(r.stdout)["filesystems"]
    if len(filesystems) != 1:
        raise errors.Stop("output_mount_ambiguous")
    fs = filesystems[0]
    if fs["fstype"] not in ("ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs"):
        raise errors.Stop("output_filesystem_not_supported")
    if fs["fstype"] == "btrfs":
        uuid = fs.get("uuid", "")
        if not uuid or any((c not in "0123456789abcdefABCDEF-" for c in uuid)):
            raise errors.Stop("output_btrfs_uuid_unverified")
        devices = Path("/sys/fs/btrfs") / uuid / "devices"
        numbers = [(p / "dev").read_text().strip() for p in devices.iterdir()]
        if not numbers:
            raise errors.Stop("output_btrfs_devices_unverified")
    else:
        numbers = [fs["maj:min"]]
    disks = set()
    for number in numbers:
        disks |= backing_disks(number)
    target = str(Path(info["sysfs"]).resolve(strict=True))
    if target in disks:
        raise errors.Stop("output_is_on_target_SSD")
    return fs["source"]


# Only the observed small FAT locking volume is eligible for automatic unmount.
# A mounted data filesystem must be handled explicitly by the user.
def auto_unmount_candidate(usage):
    mounts = usage.get("mounts", [])
    if usage.get("holders") or usage.get("swaps") or usage.get("inflight"):
        return None
    if len(mounts) != 1:
        return None
    m = mounts[0]
    if (
        m.get("partition") is True
        and m.get("fstype") == "vfat"
        and (m.get("root") == "/")
        and (m.get("size_bytes") == 34537472)
    ):
        return m["device"]
    return None
