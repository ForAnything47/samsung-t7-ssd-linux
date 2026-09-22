#!/usr/bin/env python3
"""Native Linux Samsung T7 Shield tools, distributed as a single Python file.

This publication candidate is self-contained. Edit this file directly.
See README.md for implementation provenance and reporting guidance.

Runtime dependencies are Python's standard library and host utilities (sg_raw,
findmnt, and udisksctl where applicable). Building also needs only the standard
library; an optional formatter must preserve the audited command semantics.

Reading order:
  1. Bounded TCG encoding/parsing and recovered command builders.
  2. Linux identity, disk usage, storage location, and response checks.
  3. Unlock/status transport and diagnostic collection.
  4. Authentication failure records and password/security workflows.
  5. Human/JSON presentation and the unified CLI.

Safety invariants: select a whole disk by its own serial; recheck identity and
connection generation before I/O; persist uncertainty before outbound commands;
validate each response before continuing; never log credentials or replay an
uncertain mutation. A successful transport is not a successful protocol method.
Only a bounded, observed protocol subset is supported; this is not a general
TCG Opal library. Real-device validation scope is in README.md.
"""

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
import argparse
import fcntl
import getpass
import hashlib
import json
import os
import resource
import shutil
import stat
import struct
import subprocess
import sys
import time
import uuid
import warnings

# === 1. TCG framing and bounded token parsing ===
# Wire layout: ComPacket (20), Packet (24), SubPacket (12), then payload.
# Offsets 20/24 retain their wire names to avoid reversing session identifiers.


class ProtocolError(ValueError):
    pass


class IncompleteResponse(ProtocolError):
    pass


def uint(value):
    if not 0 <= value < 1 << 64:
        raise ValueError("uint64 required")
    if value < 64:
        return bytes([value])
    size = next((n for n in (1, 2, 4, 8) if value < 1 << 8 * n))
    return bytes([128 | size]) + value.to_bytes(size, "big")


def byte_atom(value):
    value = bytes(value)
    size = len(value)
    if size <= 15:
        return bytes([160 | size]) + value
    if size <= 2047:
        return bytes([208 | size >> 8, size & 255]) + value
    raise ValueError("long byte atoms not implemented")


# Payload length excludes padding; enclosing packet lengths include it.
# Zero-filled reserved fields and four-byte alignment are part of the wire format.
def frame(payload, comid, session_at20=0, session_at24=0):
    payload = bytes(payload)
    if not payload or len(payload) > 1024 * 1024:
        raise ValueError("payload size")
    total = 56 + len(payload) + 3 & ~3
    out = bytearray(total)
    struct.pack_into(">H", out, 4, comid)
    struct.pack_into(">I", out, 16, total - 20)
    struct.pack_into(">II", out, 20, session_at20, session_at24)
    struct.pack_into(">I", out, 40, total - 44)
    struct.pack_into(">I", out, 52, len(payload))
    out[56 : 56 + len(payload)] = payload
    return bytes(out)


def tokens(data):
    """Strict unsigned tiny/short integer, short/medium bytes, control subset."""
    result = []
    offset = 0
    while offset < len(data):
        tag = data[offset]
        offset += 1
        if tag < 64:
            result.append(tag)
            continue
        if tag >= 240:
            if tag not in (240, 241, 242, 243, 248, 249, 250, 251, 252):
                raise ProtocolError("unknown control")
            result.append(("control", tag))
            continue
        if 128 <= tag <= 143:
            body_length = tag & 15
            kind = "uint"
            if not 1 <= body_length <= 8:
                raise ProtocolError("integer size")
        elif 160 <= tag <= 175:
            body_length = tag & 15
            kind = "bytes"
        elif 208 <= tag <= 215:
            if offset == len(data):
                raise ProtocolError("truncated atom header")
            body_length = (tag & 7) << 8 | data[offset]
            offset += 1
            kind = "bytes"
        else:
            raise ProtocolError("unsupported atom kind")
        if offset + body_length > len(data):
            raise ProtocolError("truncated atom body")
        body = data[offset : offset + body_length]
        offset += body_length
        result.append(int.from_bytes(body, "big") if kind == "uint" else bytes(body))
    return tuple(result)


@dataclass(frozen=True)
class Response:
    comid: int
    session_at20: int
    session_at24: int
    kind: str
    status: int
    values: tuple


# Reject unsupported framing instead of treating incomplete data as success.
# Callers separately validate method-specific tokens, status, and session identity.
def parse_response(data, *, expected_comid=None, expected_sessions=None):
    data = bytes(data)
    if len(data) < 20:
        raise ProtocolError("short ComPacket header")
    if any(data[:4]):
        raise ProtocolError("nonzero reserved ComPacket bytes")
    comid, extension = struct.unpack_from(">HH", data, 4)
    outstanding, minimum, clen = struct.unpack_from(">III", data, 8)
    if expected_comid is not None and comid != expected_comid:
        raise ProtocolError("ComID mismatch")
    if extension:
        raise ProtocolError("ComID extension unsupported")
    if outstanding or minimum:
        raise IncompleteResponse("continuation unsupported; not success")
    if not clen or 20 + clen > len(data):
        raise ProtocolError("ComPacket length")
    if any(data[20 + clen :]):
        raise ProtocolError("nonzero bytes after single ComPacket")
    if clen < 36:
        raise ProtocolError("missing nested headers")
    s0, s1 = struct.unpack_from(">II", data, 20)
    if expected_sessions is not None and (s0, s1) != tuple(expected_sessions):
        raise ProtocolError("session mismatch")
    plen = struct.unpack_from(">I", data, 40)[0]
    slen = struct.unpack_from(">I", data, 52)[0]
    if not slen or plen != 12 + (slen + 3 & ~3) or clen != 24 + plen:
        raise ProtocolError("nested lengths unsupported/inconsistent")
    end = 56 + slen
    if end > 20 + clen:
        raise ProtocolError("payload overruns packet")
    if any(data[end : 20 + clen]):
        raise ProtocolError("nonzero alignment padding")
    if any(data[28:40]) or any(data[44:52]):
        raise ProtocolError("extended header unsupported")
    payload = data[56:end]
    if payload == b"\xfa":
        return Response(comid, s0, s1, "end_session", 0, ())
    if len(payload) == 2 and payload[0] in (251, 252):
        return Response(comid, s0, s1, "transaction", payload[1], ())
    if (
        len(payload) < 5
        or payload[-5] != 240
        or payload[-1] != 241
        or (payload[-3:-1] != b"\x00\x00")
    ):
        raise ProtocolError("invalid method status trailer")
    if payload[-4] >= 64:
        raise ProtocolError("non-tiny status unsupported")
    return Response(comid, s0, s1, "method", payload[-4], tokens(payload[:-5]))


# --- Recovered UIDs and command builders ---
# Constants describe observed firmware requests; do not infer new commands from them.

UID = {
    0: "00000000000000ff",
    1: "0000080200000001",
    3: "0000020500000002",
    6: "0000000900010001",
    13: "0000080300000001",
    15: "0000100100000000",
    32: "000000000000ff02",
    33: "0000000600000016",
    34: "0000000600000017",
}
TAIL = b"\xf0\x00\x00\x00\xf1"


def uid(index):
    return byte_atom(bytes.fromhex(UID[index]))


def method(obj, method_id, args):
    return b"\xf8" + uid(obj) + uid(method_id) + b"\xf0" + args + b"\xf1\xf9" + TAIL


def start_session(credential=None):
    args = uint(1) + uid(3) + uint(1)
    if credential is not None:
        credential = bytes(credential)
        if not 4 <= len(credential) <= 16 or any(
            (not 33 <= v <= 126 for v in credential)
        ):
            raise ValueError("only observed UI ASCII password range 4..16 supported")
        args += b"\xf2\x00" + byte_atom(credential) + b"\xf3\xf2\x03" + uid(6) + b"\xf3"
    return method(0, 32, args)


def datastore_get():
    return method(
        15, 33, b"\xf0\xf2\x01" + uint(0) + b"\xf3\xf2\x02" + uint(143) + b"\xf3\xf1"
    )


def unlock_payloads():
    """Offline reference sequence; responses must gate each next command."""
    result = [("transaction_start", b"\xfb\x00")]
    for name, obj, col, val in [
        ("mbr_done", 13, 2, 1),
        ("read_unlock", 1, 7, 0),
        ("write_unlock", 1, 8, 0),
    ]:
        result.append(
            (
                name,
                method(
                    obj,
                    34,
                    b"\xf2\x01\xf0\xf2" + uint(col) + uint(val) + b"\xf3\xf1\xf3",
                ),
            )
        )
    result.append(
        (
            "datastore_mode",
            method(
                15,
                34,
                b"\xf2\x00" + uint(2) + b"\xf3\xf2\x01" + byte_atom(b"\x03") + b"\xf3",
            ),
        )
    )
    result.extend([("transaction_end", b"\xfc\x00"), ("end_session", b"\xfa")])
    return tuple(result)


def security_cdb(opcode, protocol, specific, length):
    if (
        opcode not in (162, 181)
        or not 0 <= protocol <= 255
        or (not 0 <= specific <= 65535)
        or (not 0 < length < 2**32)
    ):
        raise ValueError("invalid Security Protocol CDB fields")
    return (
        bytes([opcode, protocol])
        + specific.to_bytes(2, "big")
        + b"\x00\x00"
        + length.to_bytes(4, "big")
        + b"\x00\x00"
    )


DISCOVERY_CDB = security_cdb(162, 1, 1, 4096)
RELINK_CDB = bytes.fromhex("e8 00 00 00 00 00")


@dataclass(frozen=True)
class Discovery:
    comid: int
    locking_supported: bool
    locking_enabled: bool
    locked: bool
    mbr_enabled: bool
    mbr_done: bool
    header_length: int


def parse_discovery(raw):
    """Bounded allocation scan like SILU07; zero tail ends the feature list.

    Header length is reported, not used to guess truncation conventions.
    Unsupported/missing required features are errors, never unlocked status.
    """
    raw = bytes(raw)
    if not 48 <= len(raw) <= 4096:
        raise ProtocolError("Discovery allocation length")
    offset = 48
    found = {}
    while offset < len(raw):
        if not any(raw[offset:]):
            break
        if offset + 4 > len(raw):
            raise ProtocolError("truncated feature header")
        code = int.from_bytes(raw[offset : offset + 2], "big")
        payload_length = raw[offset + 3]
        if code == 0 or offset + 4 + payload_length > len(raw):
            raise ProtocolError("invalid feature boundary")
        if code in found:
            raise ProtocolError("duplicate feature")
        found[code] = raw[offset + 4 : offset + 4 + payload_length]
        offset += 4 + payload_length
    lock = found.get(2, b"")
    opal = found.get(515, b"")
    if len(lock) < 1 or len(opal) < 2:
        raise ProtocolError("missing Locking/Opal2 feature")
    comid = int.from_bytes(opal[:2], "big")
    if comid in (0, 65535):
        raise ProtocolError("invalid ComID")
    flags = lock[0]
    return Discovery(
        comid,
        *(bool(flags & 1 << b) for b in (0, 1, 2, 4, 5)),
        int.from_bytes(raw[:4], "big"),
    )


# === 2. Linux host checks and strict response validation ===


def device_serials(node):
    """Accept SCSI device or nearest USB device serial, never a parent hub's."""
    serials = []
    candidate = node / "device/serial"
    if candidate.is_file():
        value = candidate.read_text().strip()
        if value:
            serials.append(value)
    resolved = node.resolve()
    for parent in [resolved, *resolved.parents]:
        if (parent / "idVendor").is_file() and (parent / "idProduct").is_file():
            candidate = parent / "serial"
            if candidate.is_file():
                value = candidate.read_text().strip()
                if value and value not in serials:
                    serials.append(value)
            break
    return serials


# Resolve the whole-disk sysfs identity before constructing any device command.
# A partition path is not an interchangeable transport target.
def identity(device, family=False):
    p = Path(device).resolve(strict=True)
    if p.parent != Path("/dev") or not p.name.startswith("sd"):
        raise ValueError(
            "a Linux whole SCSI disk /dev/sdX or its by-id link is required"
        )
    node = Path("/sys/class/block") / p.name
    if (node / "partition").exists():
        raise ValueError("partition devices are not accepted")
    model = (node / "device/model").read_text().strip()
    accepted = (
        is_t7_family(model)
        if family
        else is_supported_model(model)
    )
    if not accepted:
        raise ValueError("sysfs model is outside the requested scope: " + model)
    serials = device_serials(node)
    return {
        "device": str(p),
        "model": model,
        "serials": serials,
        "sysfs": str(node.resolve()),
    }


def session_numbers(raw, comid):
    r = parse_response(raw, expected_comid=comid)
    c = lambda v: ("control", v)
    v = r.values
    if r.kind != "method" or r.status:
        raise ProtocolError("StartSession failed")
    if len(v) != 8 or v[0] != c(248) or v[3] != c(240) or (v[6:] != (c(241), c(249))):
        raise ProtocolError("unsupported StartSession result shape")
    if not all((isinstance(x, bytes) and len(x) == 8 for x in v[1:3])):
        raise ProtocolError("bad result UIDs")
    if not all((type(x) is int and 0 < x < 2**32 for x in v[4:6])):
        raise ProtocolError("bad session numbers")
    return (v[5], v[4])


def validate_start(raw, comid):
    response = parse_response(raw, expected_comid=comid, expected_sessions=(0, 0))
    sessions = session_numbers(raw, comid)
    if response.values[1:3] != (
        bytes.fromhex("00000000000000ff"),
        bytes.fromhex("000000000000ff03"),
    ):
        raise ProtocolError("unsupported SyncSession UIDs; inspect capture")
    if sessions[1] != 1:
        raise ProtocolError("host session mismatch")
    return sessions


def validate_get(raw, comid, sessions):
    response = parse_response(raw, expected_comid=comid, expected_sessions=sessions)
    control = lambda n: ("control", n)
    if response.kind != "method" or response.status or len(response.values) != 4:
        raise ProtocolError("unsupported DataStore response")
    if response.values[0] != control(240) or response.values[2:] != (control(241), control(249)):
        raise ProtocolError("unsupported DataStore token shape")
    data = response.values[1]
    if not isinstance(data, bytes) or len(data) != 144:
        raise ProtocolError("expected 144 DataStore bytes")
    return data


class Stop(Exception):
    pass


def hidden_password_prompt(prompt):
    """Keep interrupted prompts off JSON stdout and preserve cancellation."""
    try:
        return getpass.getpass(prompt, stream=sys.stderr)
    except KeyboardInterrupt:
        # Use the same stream as the prompt. Reporting failure must not replace
        # the interruption or let the caller continue with a password value.
        try:
            print(file=sys.stderr, flush=True)
        except OSError:
            pass
        raise


def read_password():
    if not sys.stdin.isatty():
        raise Stop("interactive_terminal_required")
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        first = hidden_password_prompt(
            tr("T7 SSD password (hidden; NOT your Linux sudo password): ")
        )
    try:
        credential = first.encode("ascii")
    except UnicodeError:
        raise Stop("unsupported_password_format_no_auth_sent") from None
    if not 4 <= len(credential) <= 16 or any((not 33 <= b <= 126 for b in credential)):
        raise Stop("unsupported_password_format_no_auth_sent")
    return credential


# Gather all active-use indicators, not just the visible mount point.
# A zero inflight count is a snapshot; callers repeat the check before each I/O.
def usage_snapshot(device, sysroot=Path("/sys/class/block"), procroot=Path("/proc")):
    root = sysroot / Path(device).name
    if (root / "partition").exists():
        raise Stop("whole_disk_required")
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
        raise Stop("device_in_use_unmount_or_stop_disk_work_first")


@contextmanager
def exclusive_device(device):
    fd = os.open(device, os.O_RDONLY | os.O_EXCL | os.O_CLOEXEC)
    try:
        if not stat.S_ISBLK(os.fstat(fd).st_mode):
            raise Stop("not_a_block_device")
        yield
    finally:
        os.close(fd)


def backing_disks(number, sysroot=Path("/sys/dev/block"), seen=None):
    """Resolve partitions and stacked block devices to physical whole disks."""
    seen = set() if seen is None else set(seen)
    if number in seen:
        raise Stop("output_block_topology_cycle")
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
        raise Stop("output_backing_device_unverified")
    return {str(node)}


# Prevent result/pending writes from depending on the SSD being modified.
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
        raise Stop("output_mount_ambiguous")
    fs = filesystems[0]
    if fs["fstype"] not in ("ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs"):
        raise Stop("output_filesystem_not_supported")
    if fs["fstype"] == "btrfs":
        uuid = fs.get("uuid", "")
        if not uuid or any((c not in "0123456789abcdefABCDEF-" for c in uuid)):
            raise Stop("output_btrfs_uuid_unverified")
        devices = Path("/sys/fs/btrfs") / uuid / "devices"
        numbers = [(p / "dev").read_text().strip() for p in devices.iterdir()]
        if not numbers:
            raise Stop("output_btrfs_devices_unverified")
    else:
        numbers = [fs["maj:min"]]
    disks = set()
    for number in numbers:
        disks |= backing_disks(number)
    target = str(Path(info["sysfs"]).resolve(strict=True))
    if target in disks:
        raise Stop("output_is_on_target_SSD")
    return fs["source"]


def validate_change(name, raw, comid, sessions):
    response = parse_response(raw, expected_comid=comid, expected_sessions=sessions)
    if name in ("transaction_start", "transaction_end"):
        opcode = 251 if name == "transaction_start" else 252
        if response.kind != "transaction" or response.status != 0 or raw[56] != opcode:
            raise Stop("unsupported_or_failed_transaction_response")
    elif name == "end_session":
        if response.kind != "end_session":
            raise Stop("end_session_not_verified")
    else:
        empty_result = (("control", 240), ("control", 241), ("control", 249))
        if response.kind != "method" or response.status != 0 or response.values != empty_result:
            raise Stop("unsupported_or_failed_set_response")
    return response


# Write, fsync, rename, then fsync the directory so pending survives a crash.
# Failure before transmission must stop the command; a final report failure must
# not hide a device outcome already observed.
def checked_record(directory_fd, name):
    """Reject linked or foreign records without following their target."""
    try:
        entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if (not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1
            or entry.st_uid != os.getuid() or entry.st_mode & 0o022):
        raise Stop("unsafe_local_record")


def open_record_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    entry = os.fstat(fd)
    if entry.st_uid != os.getuid() or entry.st_mode & 0o022:
        os.close(fd)
        raise Stop("unsafe_local_directory")
    return fd


def save(path, value):
    directory_fd = open_record_directory(path.parent)
    temporary = None
    try:
        checked_record(directory_fd, path.name)
        name = "." + path.name + "." + uuid.uuid4().hex + ".tmp"
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=directory_fd)
        temporary = name
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        checked_record(directory_fd, path.name)
        os.replace(name, path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        temporary = None
        os.fsync(directory_fd)
    finally:
        try:
            if temporary is not None:
                os.unlink(temporary, dir_fd=directory_fd)
        finally:
            os.close(directory_fd)


def generation(info):
    return (
        (Path("/sys/class/block") / Path(info["device"]).name / "diskseq")
        .read_text()
        .strip()
    )


def is_supported_model(model):
    """Supported operation scope, not cryptographic device authentication."""
    return model.strip().lower() == "pssd t7 shield"


def is_t7_family(model):
    return model.strip().lower() in ("pssd t7", "pssd t7 touch", "pssd t7 shield")


def list_devices(family=False):
    found = []
    for node in Path("/sys/class/block").glob("sd*"):
        if (node / "partition").exists():
            continue
        try:
            model = (node / "device/model").read_text().lower()
            if family:
                if not is_t7_family(model):
                    continue
                info = identity("/dev/" + node.name, family=True)
            else:
                if not is_supported_model(model):
                    continue
                info = identity("/dev/" + node.name)
            found.append(info)
        except FileNotFoundError:
            continue
    return sorted(found, key=lambda info: info["device"])


def find_device(serial, family=False):
    found = [info for info in list_devices(family=family) if serial in info["serials"]]
    if len(found) > 1:
        raise Stop("ambiguous_serial_multiple_devices")
    return found[0] if found else None


def wait_reenumeration(
    before,
    old_generation,
    serial,
    finder=find_device,
    gen=generation,
    clock=time.monotonic,
    sleep=time.sleep,
):
    deadline = clock() + 30
    stable = 0
    previous = None
    while clock() < deadline:
        current = finder(serial)
        if current is not None:
            try:
                seq = gen(current)
            except FileNotFoundError:
                current = None
        if current is not None:
            key = (current["device"], current["sysfs"], seq)
            changed = seq != old_generation
            stable = stable + 1 if changed and key == previous else 1 if changed else 0
            previous = key
            if stable >= 3:
                return (current, seq)
        else:
            stable = 0
            previous = None
        sleep(0.5)
    raise Stop("new_disk_generation_not_observed_do_not_repeat_relink")


def parse_state(raw, expected):
    if len(raw) != 4096 or int.from_bytes(raw[:4], "big") != 160 or any(raw[164:]):
        raise Stop("discovery_layout_changed")
    discovery = parse_discovery(raw[:164])
    if (
        discovery.comid != 4100
        or not discovery.locking_supported
        or (not discovery.locking_enabled)
        or (not discovery.mbr_enabled)
    ):
        raise Stop("security_configuration_changed")
    if discovery.locked != (expected == "locked") or discovery.mbr_done != (expected == "unlocked"):
        raise Stop("unexpected_lock_state")
    return asdict(discovery)


# === 3. Unlock/status execution and host adapters ===

BASE = Path(__file__).resolve().parent


def select(serial, finder=find_device):
    if serial is None:
        candidates = list_devices()
        if len(candidates) != 1:
            raise Stop(
                "specify_serial_from_list" if candidates else "matching_T7_not_found"
            )
        info = candidates[0]
        if not info["serials"]:
            raise Stop("device_serial_unavailable")
        serial = info["serials"][0]
    info = finder(serial)
    if info is None:
        raise Stop("matching_T7_not_found")
    if not serial or serial not in info["serials"]:
        raise Stop("serial_mismatch")
    return info


def partition_paths(info):
    root = Path("/sys/class/block") / Path(info["device"]).name
    return [
        {"device": "/dev/" + p.name, "size_bytes": int((p / "size").read_text()) * 512}
        for p in sorted(root.iterdir())
        if (p / "partition").exists()
    ]


@contextmanager
# Serialize CLI operations on the serial-derived state directory.
# This complements the per-device exclusive claim; it does not replace it.
def run_lock(state):
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory_fd = open_record_directory(state)
    lock_fd = None
    try:
        checked_record(directory_fd, "lock")
        lock_fd = os.open("lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                          0o600, dir_fd=directory_fd)
        entry = os.fstat(lock_fd)
        if (not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1
                or entry.st_uid != os.getuid() or entry.st_mode & 0o022):
            raise Stop("unsafe_local_record")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Stop("another_T7_command_is_running") from None
        checked_record(directory_fd, "pending.json")
        yield
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
        os.close(directory_fd)


def clear_pending(state):
    (state / "pending.json").unlink()
    fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


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


class Host:
    usage = staticmethod(usage_snapshot)
    identify = staticmethod(identity)
    gen = staticmethod(generation)
    idle = staticmethod(require_idle)
    claim = staticmethod(exclusive_device)
    wait = staticmethod(wait_reenumeration)
    password = staticmethod(read_password)
    partitions = staticmethod(partition_paths)
    run = staticmethod(subprocess.run)


class UnverifiedModelHost(Host):
    """Explicit per-run model opt-in; transport and response checks stay unchanged.

    Re-identification and Relink discovery must use the same scope as initial
    selection. No global model whitelist is changed by this adapter.
    """

    allow_unverified_model = True
    identify = staticmethod(lambda device: identity(device, family=True))

    @staticmethod
    def wait(before, old_generation, serial):
        return wait_reenumeration(
            before, old_generation, serial,
            finder=lambda value: find_device(value, family=True),
        )


def operation_model_allowed(model, host):
    """Only exact T7 family names can opt in, never arbitrary USB devices."""
    return is_supported_model(model) or (
        getattr(host, "allow_unverified_model", False) is True
        and is_t7_family(model)
    )


# Keep transport ordering explicit: Discovery, anonymous status, authentication,
# transactional unlock, EndSession, Discovery, one Relink, then rediscovery.
# The host adapter makes every stage testable without a real SSD.
def execute_unlock(info, serial, action, out, state, host=None):
    host = host or Host()
    if out is not None:
        out.mkdir(parents=True, exist_ok=False, mode=448)
    report = {
        "complete": False,
        "action": action,
        "identity": info,
        "commands": [],
        "session_may_be_open": False,
        "transaction_may_be_open": False,
        "changes_may_have_occurred": False,
        "relink_attempted": False,
    }
    current_identity = info
    initial_generation = host.gen(current_identity)
    boot = boot_identity()

    def checkpoint():
        if out is not None:
            save(out / "result.json", report)

    def transfer(name, cdb, payload=None, request=None, mounted_candidate=None):
        report["error_stage"] = name
        if host.identify(current_identity["device"]) != current_identity or host.gen(current_identity) != initial_generation:
            raise Stop("device_identity_or_generation_changed")
        if mounted_candidate is not None:
            if (
                name != "discovery-before-unmount"
                or cdb != DISCOVERY_CDB
                or payload is not None
                or (request != 4096)
            ):
                raise Stop("invalid_mounted_query")
            if (
                auto_unmount_candidate(host.usage(current_identity["device"]))
                != mounted_candidate
            ):
                raise Stop("mounted_partition_changed")
        else:
            host.idle(current_identity["device"])
        if payload is not None or name == "relink":
            save(
                state / "pending.json",
                {
                    "schema": 2,
                    "kind": "uncertain",
                    "identity": current_identity,
                    "diskseq": initial_generation,
                    "boot_id": boot,
                    "run": str(out) if out is not None else None,
                    "serial": serial,
                    "last_attempt": name,
                },
            )
        command_record = {"name": name, "phase": "attempting"}
        report["commands"].append(command_record)
        if name in ("anonymous-start-out", "auth-out"):
            report["session_may_be_open"] = True
        if name == "transaction_start-out":
            report["transaction_may_be_open"] = True
        if name in (
            "mbr_done-out",
            "read_unlock-out",
            "write_unlock-out",
            "datastore_mode-out",
        ):
            report["changes_may_have_occurred"] = True
        if name == "relink":
            report["relink_attempted"] = True
        checkpoint()
        command = ["sg_raw", "--readonly", "--cmdset=1", "--timeout=30"]
        if payload is not None:
            command += ["--send=" + str(len(payload))]
        elif request:
            command += ["--request=" + str(request), "--outfile=-"]
        command += [current_identity["device"], *[f"{b:02x}" for b in cdb]]
        try:
            transport_result = host.run(
                command,
                input=payload if payload is not None else b"",
                capture_output=True,
                timeout=45,
                check=False,
            )
        except subprocess.TimeoutExpired:
            command_record["phase"] = "timeout"
            raise Stop("transport_timeout_no_retry") from None
        command_record.update(phase="returned", returncode=transport_result.returncode)
        if transport_result.returncode:
            raise Stop("transport_failed_no_retry")
        if request:
            command_record["received"] = len(transport_result.stdout)
            if len(transport_result.stdout) > request:
                raise Stop("oversized_response")
            return transport_result.stdout

    def exchange(name, payload, sessions):
        packet = frame(payload, 4100, *sessions)
        transfer(name + "-out", security_cdb(181, 1, 4100, len(packet)), payload=packet)
        return transfer(name + "-in", security_cdb(162, 1, 4100, 2048), request=2048)

    def discovery(name, expected=None):
        raw = transfer(name, DISCOVERY_CDB, request=4096)
        if action == "status":
            return security_discovery(raw)
        if expected:
            return parse_state(raw, expected)
        try:
            return parse_state(raw, "locked")
        except Stop:
            return parse_state(raw, "unlocked")

    try:
        checkpoint()
        if action == "unlock" and (state / "pending.json").exists():
            report["recovery"] = recover_pending(state, current_identity, initial_generation, boot, host, discovery)
        usage = host.usage(current_identity["device"])
        if action == "unlock" and usage.get("mounts"):
            candidate = auto_unmount_candidate(usage)
            if candidate is None:
                raise Stop("mounted_partition_not_verified_locking_volume")
            raw = transfer(
                "discovery-before-unmount",
                DISCOVERY_CDB,
                request=4096,
                mounted_candidate=candidate,
            )
            report["before_unmount"] = parse_state(raw, "locked")
            if host.identify(current_identity["device"]) != current_identity or host.gen(current_identity) != initial_generation:
                raise Stop("device_identity_or_generation_changed")
            if auto_unmount_candidate(host.usage(current_identity["device"])) != candidate:
                raise Stop("mounted_partition_changed")
            record = {"device": candidate, "phase": "attempting"}
            report["unmount"] = record
            checkpoint()
            try:
                unmounted = host.run(
                    [
                        "udisksctl",
                        "unmount",
                        "--block-device",
                        candidate,
                        "--no-user-interaction",
                    ],
                    input=b"",
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                record["phase"] = "timeout"
                raise Stop("unmount_timeout_no_unlock") from None
            record.update(phase="returned", returncode=unmounted.returncode)
            checkpoint()
            if unmounted.returncode:
                raise Stop("unmount_failed_close_files_no_unlock")
            if host.identify(current_identity["device"]) != current_identity or host.gen(current_identity) != initial_generation:
                raise Stop("device_identity_or_generation_changed")
            host.idle(current_identity["device"])
        with host.claim(current_identity["device"]):
            report["before"] = discovery("discovery-before")
            if action == "status" or not report["before"]["locked"]:
                report.pop("error_stage", None)
                report.update(
                    complete=True,
                    outcome="locked" if report["before"]["locked"] else "already_unlocked",
                    partitions=host.partitions(current_identity),
                )
                return report
            credential = host.password()
            discovery("discovery-before-session", "locked")
            sessions = validate_start(
                exchange("anonymous-start", start_session(), (0, 0)), 4100
            )
            validate_get(
                exchange("anonymous-get", datastore_get(), sessions), 4100, sessions
            )
            reply = parse_response(
                exchange("anonymous-end", b"\xfa", sessions),
                expected_comid=4100,
                expected_sessions=sessions,
            )
            if reply.kind != "end_session":
                raise Stop("anonymous_end_not_verified")
            report["session_may_be_open"] = False
            discovery("discovery-before-auth", "locked")
            raw = exchange("auth", start_session(credential), (0, 0))
            del credential
            auth = parse_response(raw, expected_comid=4100, expected_sessions=(0, 0))
            if auth.kind == "method":
                report["auth_method_status"] = auth.status
            if auth.kind != "method" or auth.status != 0:
                report["auth_response_diagnostic"] = auth_failure_diagnostic(auth, len(raw))
                report["recovery_eligible_after_reconnection"] = False
            if supported_auth_rejection(auth, len(raw)) and rejected_sync_checks_match(
                sync_session_checks(auth)
            ):
                # Exact refusal with no device session: resolve the pre-send marker.
                clear_pending(state)
                report["pending_cleared"] = True
                report["session_may_be_open"] = False
                report["retry_without_reconnection"] = True
                raise Stop("authentication_rejected")
            if supported_auth_rejection(auth, len(raw)):
                # Only the exact supported rejection shape; malformed/other statuses stay uncertain.
                proof_result = dict(report)
                proof_result["commands"] = [
                    c for c in report["commands"] if c["name"] != "discovery-recovery"
                ]
                save(
                    state / "pending.json",
                    rejection_record(info, serial, initial_generation, boot, out, proof_result),
                )
                report["recovery_eligible_after_reconnection"] = True
                report["retry_without_reconnection"] = rejected_sync_checks_match(
                    sync_session_checks(auth)
                )
                if report["retry_without_reconnection"]:
                    report["session_may_be_open"] = False
                raise Stop("authentication_rejected_no_retry")
            sessions = validate_start(raw, 4100)
            report["authenticated"] = True
            for name, payload in unlock_payloads():
                raw = exchange(name, payload, sessions)
                diagnostic = parse_response(
                    raw, expected_comid=4100, expected_sessions=sessions
                )
                report["commands"][-1].update(
                    response_kind=diagnostic.kind, response_status=diagnostic.status
                )
                validate_change(name, raw, 4100, sessions)
                report["commands"][-1]["validated"] = True
                if name == "transaction_end":
                    report["transaction_may_be_open"] = False
                if name == "end_session":
                    report["session_may_be_open"] = False
                checkpoint()
            report["after_unlock"] = discovery("discovery-after-unlock", "unlocked")
            transfer("relink", RELINK_CDB)
            report["relink_transport_success"] = True
            checkpoint()
        new, newseq = host.wait(current_identity, initial_generation, serial)
        if (
            serial not in new["serials"]
            or new["model"] != info["model"]
            or newseq == initial_generation
        ):
            raise Stop("reenumeration_not_verified")
        current_identity = new
        initial_generation = newseq
        report["identity_after"] = current_identity
        report["reenumeration_verified"] = True
        with host.claim(current_identity["device"]):
            report["after"] = discovery("discovery-after-relink", "unlocked")
            report["partitions"] = host.partitions(current_identity)
        report["outcome"] = "unlocked"
        report["complete"] = True
        checkpoint()
        clear_pending(state)
        report.pop("error_stage", None)
    except Stop as e:
        report.update(complete=False, error=str(e))
    except KeyboardInterrupt:
        report.update(complete=False, error="interrupted_no_retry")
    except ProtocolError:
        report.update(
            complete=False, error="unsupported_or_failed_protocol_response_no_retry"
        )
    except Exception:
        report.update(complete=False, error="local_error_details_suppressed_no_retry")
    finally:
        try:
            checkpoint()
        except (OSError, KeyboardInterrupt):
            report["result_save_error"] = "result_checkpoint_failed"
    return report


# --- T7 family diagnostic collection (does not prove unlock compatibility) ---

INQUIRY_CDB = bytes.fromhex("12 00 00 00 24 00")
QUERIES = (("inquiry", INQUIRY_CDB, 36), ("discovery", DISCOVERY_CDB, 4096))


def analyze(raw, model):
    declared = int.from_bytes(raw[:4], "big") if len(raw) >= 4 else None
    if (
        declared is None
        or not 48 <= declared + 4 <= len(raw)
        or any(raw[declared + 4 :])
    ):
        raise Stop("unsupported_discovery_length_convention")
    d = parse_discovery(raw[: declared + 4])
    features = []
    pos = 48
    while pos < declared + 4:
        if not any(raw[pos : declared + 4]):
            break
        size = raw[pos + 3]
        features.append(
            {
                "code": f"{int.from_bytes(raw[pos:pos + 2], 'big'):04x}",
                "version_byte": raw[pos + 2],
                "payload_length": size,
            }
        )
        pos += 4 + size
    matches = False
    for state in ("locked", "unlocked"):
        try:
            parse_state(raw, state)
            matches = True
            break
        except Stop:
            pass
    return {
        "discovery": asdict(d),
        "features": features,
        "classification": (
            "observed_profile_match_unverified_device"
            if matches
            else "parsed_profile_differs"
        ),
        "model_has_prior_validation": model.strip().lower() == "pssd t7 shield",
        "unlock_compatibility_proven": False,
        "note": "Discovery similarity does not prove authentication, unlock or Relink compatibility.",
    }


class QueryHost:
    identify = staticmethod(lambda device: identity(device, family=True))
    gen = staticmethod(generation)
    idle = staticmethod(require_idle)
    claim = staticmethod(exclusive_device)
    run = staticmethod(subprocess.run)


def collect(info, out, host=None):
    host = host or QueryHost()
    if out is not None:
        out.mkdir(parents=True, exist_ok=False, mode=448)
    result = {
        "complete": False,
        "identity": info,
        "commands": [],
        "unlock_compatibility_proven": False,
    }
    try:
        seq = host.gen(info)
        host.idle(info["device"])
        with host.claim(info["device"]):
            for name, cdb, count in QUERIES:
                if host.identify(info["device"]) != info or host.gen(info) != seq:
                    raise Stop("device_identity_or_generation_changed")
                host.idle(info["device"])
                rec = {
                    "name": name,
                    "cdb": cdb.hex(),
                    "requested": count,
                    "phase": "attempting",
                }
                result["commands"].append(rec)
                if out is not None:
                    save(out / "result.json", result)
                cmd = [
                    "sg_raw",
                    "--readonly",
                    "--cmdset=1",
                    "--timeout=30",
                    f"--request={count}",
                    "--outfile=-",
                    info["device"],
                    *[f"{b:02x}" for b in cdb],
                ]
                response = host.run(
                    cmd, input=b"", capture_output=True, timeout=45, check=False
                )
                rec.update(
                    phase="returned",
                    returncode=response.returncode,
                    received=len(response.stdout),
                    stderr=response.stderr.decode("utf-8", "replace"),
                )
                if out is not None:
                    (out / (name + ".bin")).write_bytes(response.stdout)
                if response.returncode:
                    raise Stop("transport_failed_no_retry")
                if len(response.stdout) != count:
                    raise Stop("unexpected_response_length_no_retry")
                if name == "inquiry":
                    raw = response.stdout
                    result["inquiry"] = {
                        "vendor": raw[8:16].decode("ascii", "replace").strip(),
                        "product": raw[16:32].decode("ascii", "replace").strip(),
                        "revision": raw[32:36].decode("ascii", "replace").strip(),
                    }
                else:
                    result.update(analyze(response.stdout, info["model"]))
            if host.identify(info["device"]) != info or host.gen(info) != seq:
                raise Stop("device_identity_or_generation_changed")
            result["complete"] = True
    except subprocess.TimeoutExpired:
        result["error"] = "transport_timeout_no_retry"
        result["commands"][-1]["phase"] = "timeout"
    except (Stop, ProtocolError) as e:
        result.update(error=str(e), classification="unsupported_or_incomplete")
    except KeyboardInterrupt:
        result["error"] = "interrupted_no_retry"
    except Exception:
        result["error"] = "local_error_no_retry"
    finally:
        if out is not None:
            try:
                save(out / "result.json", result)
            except (OSError, KeyboardInterrupt):
                result["result_save_error"] = "result_checkpoint_failed"
    return result


# === 4. Pending records and credential workflows ===
# Older schema-2 records remain supported for users upgrading in place.
AUTH_PREFIX = [
    "discovery-before",
    "discovery-before-session",
    "anonymous-start-out",
    "anonymous-start-in",
    "anonymous-get-out",
    "anonymous-get-in",
    "anonymous-end-out",
    "anonymous-end-in",
    "discovery-before-auth",
    "auth-out",
    "auth-in",
]


def boot_identity():
    value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    return str(uuid.UUID(value))


def auth_prefix_valid(commands):
    all_commands = commands
    names = [c.get("name") for c in commands]
    if names[:1] == ["discovery-before-unmount"]:
        commands = commands[1:]
        names = names[1:]
    if names != AUTH_PREFIX:
        return False
    for c in all_commands:
        if c.get("phase") != "returned" or c.get("returncode") != 0:
            return False
        if c["name"].startswith("discovery") and c.get("received") != 4096:
            return False
        if c["name"].endswith("-in") and c.get("received") != 2048:
            return False
    return True


def rejection_record(info, serial, seq, boot, out, result):
    if not auth_prefix_valid(result["commands"]):
        raise Stop("auth_rejection_evidence_incomplete")
    return {
        "schema": 2,
        "kind": "validated_auth_rejection",
        "identity": info,
        "serial": serial,
        "diskseq": seq,
        "boot_id": boot,
        "run": str(out) if out is not None else None,
        "last_attempt": "auth-out",
        "auth_status": 1,
        "response_validated": True,
        "anonymous_session_closed": True,
        "changes_started": False,
        "before": result["before"],
        "commands": result["commands"],
        "same_connection_retry_verified": rejected_sync_checks_match(
            result.get("auth_response_diagnostic", {}).get("sync_session_checks", {})
        ),
    }


def assess_pending(record, info, seq, boot):
    if record.get("schema") != 2 or record.get("kind") != "validated_auth_rejection":
        return "legacy_or_uncertain_evidence"
    old = record.get("identity", {})
    if (
        old.get("model") != info["model"]
        or not old.get("serials")
        or set(old["serials"]) != set(info["serials"])
    ):
        return "pending_device_mismatch"
    if record.get("serial") not in info["serials"]:
        return "pending_device_mismatch"
    if (
        record.get("auth_status") != 1
        or record.get("response_validated") is not True
        or record.get("anonymous_session_closed") is not True
        or record.get("changes_started") is not False
        or record.get("last_attempt") != "auth-out"
        or not auth_prefix_valid(record.get("commands", []))
    ):
        return "incomplete_auth_rejection_evidence"
    before = record.get("before", {})
    if not (
        before.get("locked") is True
        and before.get("locking_enabled") is True
        and before.get("mbr_done") is False
        and before.get("comid") == 4100
    ):
        return "previous_security_state_unverified"
    # diskseq is only comparable within one boot. A reboot is not proof of power cycling.
    if record.get("boot_id") != boot:
        return "boot_changed_requires_review"
    oldseq = record.get("diskseq")
    if (
        not isinstance(oldseq, str)
        or not oldseq.isdecimal()
        or not str(seq).isdecimal()
    ):
        return "generation_evidence_missing"
    if int(seq) < int(oldseq):
        return "generation_regressed"
    if (
        int(seq) == int(oldseq)
        and record.get("same_connection_retry_verified") is not True
    ):
        return "reconnection_not_observed"
    return "fresh_locked_discovery_required"


# A pending record is evidence of uncertainty, not permission to retry.
# Only the explicitly supported rejection proof can be resolved here.
def recover_pending(state, info, seq, boot, host, discovery):
    path = state / "pending.json"
    original = path.read_bytes()
    record = json.loads(original)
    reason = assess_pending(record, info, seq, boot)
    if reason != "fresh_locked_discovery_required":
        raise Stop("pending_recovery_blocked:" + reason)
    host.idle(info["device"])
    with host.claim(info["device"]):
        checked = discovery("discovery-recovery", "locked")
        host.idle(info["device"])
        if (
            host.identify(info["device"]) != info
            or host.gen(info) != seq
            or boot_identity() != boot
        ):
            raise Stop("recovery_device_changed")
        if path.read_bytes() != original:
            raise Stop("pending_record_changed")
        history = state / "history"
        history.mkdir(exist_ok=True, mode=0o700)
        archive = history / (
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + "-"
            + uuid.uuid4().hex
            + ".json"
        )
        # Keep the original evidence intact. No reset or authentication in recovery.
        path.replace(archive)
        for folder in (history, state):
            fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    return {
        "applied": True,
        "archived_pending": str(archive),
        "checked_state": checked,
        "note": "Verified rejection and fresh locked state; retry may use the same connection.",
    }


def auth_failure_diagnostic(response, received):
    """Structural metadata only: never serialize token values or packet bytes."""
    shapes = []
    for token in response.values:
        if isinstance(token, bytes):
            shapes.append({"kind": "bytes", "length": len(token)})
        elif type(token) is int:
            shapes.append({"kind": "integer"})
        elif isinstance(token, tuple) and len(token) == 2 and token[0] == "control":
            shapes.append({"kind": "control"})
        else:
            shapes.append({"kind": "unsupported"})
    reasons = []
    if response.kind != "method":
        reasons.append("response_kind_not_method")
    if response.status != 1:
        reasons.append("status_not_supported_rejection")
    if response.values != () and not rejected_sync_checks_match(
        sync_session_checks(response)
    ):
        reasons.append("unsupported_return_tokens")
    if received != 2048:
        reasons.append("unexpected_receive_length")
    return {
        "response_kind": response.kind,
        "received_bytes": received,
        "token_count": len(shapes),
        "token_shapes": shapes,
        "sync_session_checks": sync_session_checks(response),
        "recovery_exclusion_reasons": reasons,
    }


def sync_session_checks(response):
    """Diagnostic comparisons only, not authorization to recover or continue."""
    v = response.values
    eight = len(v) == 8
    integers = eight and all(type(x) is int for x in v[4:6])
    return {
        "eight_tokens": eight,
        "control_tokens_match": eight
        and v[0] == ("control", 248)
        and v[3] == ("control", 240)
        and v[6:] == (("control", 241), ("control", 249)),
        "invoking_uid_match": eight and v[1] == bytes.fromhex("00000000000000ff"),
        "sync_session_uid_match": eight and v[2] == bytes.fromhex("000000000000ff03"),
        "header_sessions_zero": response.session_at20 == 0
        and response.session_at24 == 0,
        "session_values_uint32": integers and all(0 <= x < 2**32 for x in v[4:6]),
        "host_session_matches_request": integers and v[4] == 1,
        "device_session_zero": integers and v[5] == 0,
        "device_session_positive_uint32": integers and 0 < v[5] < 2**32,
    }


def rejected_sync_checks_match(checks):
    expected = {
        "eight_tokens": True,
        "control_tokens_match": True,
        "invoking_uid_match": True,
        "sync_session_uid_match": True,
        "header_sessions_zero": True,
        "session_values_uint32": True,
        "host_session_matches_request": True,
        "device_session_zero": True,
        "device_session_positive_uint32": False,
    }
    return set(checks) == set(expected) and all(
        checks[k] is v for k, v in expected.items()
    )


def supported_auth_rejection(response, received):
    return (
        response.kind == "method"
        and response.status == 1
        and received == 2048
        and response.session_at20 == 0
        and response.session_at24 == 0
        and (
            response.values == ()
            or rejected_sync_checks_match(sync_session_checks(response))
        )
    )


# ---- Experimental password change ----
def password_authentication_payload(credential, authority):
    """Build one StartSession for an explicitly supported credential authority."""
    if authority not in (6, 7):
        raise Stop("unsupported_password_authority")
    start_session(credential)
    authority_uid = bytes.fromhex(
        "0000000900010001" if authority == 6 else "0000000900010002"
    )
    arguments = uint(1) + uid(3) + uint(1)
    arguments += b"\xf2\x00" + byte_atom(credential) + b"\xf3"
    arguments += b"\xf2\x03" + byte_atom(authority_uid) + b"\xf3"
    return method(0, 32, arguments)


def password_pin_set(target, credential):
    """Encode a Set of PIN column 3 for one of the two recovered targets."""
    if target not in (19, 20):
        raise Stop("unsupported_password_target")
    start_session(credential)  # Reuse the observed credential format validation.
    target_uid = bytes.fromhex(
        "0000000b00010001" if target == 19 else "0000000b00010002"
    )
    return (
        b"\xf8"
        + byte_atom(target_uid)
        + uid(34)
        + b"\xf0\xf2\x01\xf0\xf2\x03"
        + byte_atom(credential)
        + b"\xf3\xf1\xf3\xf1\xf9"
        + TAIL
    )


def change_password_inputs():
    """Collect all inputs before opening a session or changing credentials."""
    if not sys.stdin.isatty():
        raise Stop("interactive_terminal_required")
    values = []
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        for label in (
            "Current T7 password: ",
            "New T7 password: ",
            "Re-enter new T7 password: ",
        ):
            try:
                value = hidden_password_prompt(tr(label)).encode("ascii")
            except UnicodeError:
                raise Stop("unsupported_password_format_no_auth_sent") from None
            try:
                start_session(value)
            except ValueError:
                raise Stop("unsupported_password_format_no_auth_sent") from None
            values.append(value)
    current_password, new_password, confirmed_password = values
    if new_password != confirmed_password:
        raise Stop("password_entries_differ_no_auth_sent")
    if current_password == new_password:
        raise Stop("new_password_same_no_changes")
    return current_password, new_password


def archive_pending_record(state, raw, purpose, prior_origin=None):
    """Preserve exact incident bytes before verification writes a new marker."""
    history = state / "history" / (purpose + "-" + uuid.uuid4().hex)
    history.mkdir(parents=True, mode=0o700)
    with (history / "pending-original.json").open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    save(history / "review.json", {
        "prior_origin": prior_origin,
        "purpose": purpose + "; verification only; no changes",
    })
    for directory in (history.parent, state):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return history


# Collect inputs before authentication; record every potentially open session.
# After a possible Set, verification failure must retain pending: neither the old
# nor the new password can be assumed to describe both credential objects.
def execute_password_change(info, serial, out, state, host=None, verify_only=False):
    host = host or Host()
    result = {
        "action": "change-password",
        "complete": False,
        "experimental": True,
        "identity": info,
        "commands": [],
        "session_may_be_open": False,
        "transaction_may_be_open": False,
        "changes_may_have_occurred": False,
        "commit_confirmed": False,
        "relink_attempted": False,
    }
    current_password = new_password = None
    verification_origin = None
    verification_archive = None
    initial_generation = host.gen(info)
    boot = boot_identity()
    pending = state / "pending.json"

    def checkpoint():
        if out is not None:
            save(out / "result.json", result)

    def marker(stage):
        save(
            pending,
            {
                "schema": 3,
                "kind": "password_change",
                "identity": info,
                "serial": serial,
                "diskseq": initial_generation,
                "boot_id": boot,
                "stage": stage,
                "run": str(out) if out else None,
                "commit_confirmed": result["commit_confirmed"],
                "changes_may_have_occurred": result["changes_may_have_occurred"],
                "verification_origin": verification_origin,
                "verification_archive": str(verification_archive) if verification_archive else None,
            },
        )

    def transfer(name, cdb, payload=None, request=None):
        result["error_stage"] = name
        if (
            host.identify(info["device"]) != info
            or host.gen(info) != initial_generation
        ):
            raise Stop("device_identity_or_generation_changed")
        host.idle(info["device"])
        if payload is not None:
            marker(name)
        command_record = {"name": name, "phase": "attempting"}
        result["commands"].append(command_record)
        checkpoint()
        command = ["sg_raw", "--readonly", "--cmdset=1", "--timeout=30"]
        if payload is not None:
            command += ["--send=" + str(len(payload))]
        else:
            command += ["--request=" + str(request), "--outfile=-"]
        command += [info["device"], *[f"{b:02x}" for b in cdb]]
        try:
            transport_result = host.run(
                command,
                input=payload or b"",
                capture_output=True,
                timeout=45,
                check=False,
            )
        except subprocess.TimeoutExpired:
            command_record["phase"] = "timeout"
            raise Stop("transport_timeout_no_retry") from None
        command_record.update(phase="returned", returncode=transport_result.returncode)
        if transport_result.returncode:
            raise Stop("transport_failed_no_retry")
        if request:
            command_record["received"] = len(transport_result.stdout)
            if len(transport_result.stdout) != request:
                raise Stop("unexpected_receive_length")
            return transport_result.stdout

    def exchange(name, payload, sessions):
        raw = frame(payload, 4100, *sessions)
        transfer(name + "-out", security_cdb(181, 1, 4100, len(raw)), payload=raw)
        return transfer(name + "-in", security_cdb(162, 1, 4100, 2048), request=2048)

    def auth(name, password, authority=6):
        result["session_may_be_open"] = True
        payload = password_authentication_payload(password, authority)
        raw = exchange(name, payload, (0, 0))
        parsed = parse_response(raw, expected_comid=4100, expected_sessions=(0, 0))
        if parsed.status:
            if supported_auth_rejection(
                parsed, len(raw)
            ) and rejected_sync_checks_match(sync_session_checks(parsed)):
                result["session_may_be_open"] = False
                if not verify_only and not result["changes_may_have_occurred"]:
                    clear_pending(state)
                raise Stop(
                    "authentication_rejected"
                    if not result["commit_confirmed"]
                    else "new_password_verification_rejected"
                )
            raise Stop("unsupported_auth_response")
        return validate_start(raw, 4100)

    def end(sessions, name):
        raw = exchange(name, b"\xfa", sessions)
        parsed = parse_response(raw, expected_comid=4100, expected_sessions=sessions)
        if parsed.kind != "end_session":
            raise Stop("end_session_not_verified")
        result["session_may_be_open"] = False

    try:
        if out is not None:
            out.mkdir(parents=True, exist_ok=False, mode=0o700)
        result["error_stage"] = "pending inspection"
        if verify_only:
            if not pending.exists():
                raise Stop("password_change_pending_required")
            previous_raw = pending.read_bytes()
            previous = json.loads(previous_raw)
            verification_origin = previous.get("verification_origin") or dict(previous)
            if previous.get("schema") != 3 or previous.get("kind") != "password_change":
                raise Stop("unsupported_pending_for_verification")
            if previous.get("identity", {}).get("model") != info["model"] or set(
                previous.get("identity", {}).get("serials", [])
            ) != set(info["serials"]):
                raise Stop("pending_device_mismatch")
            if (
                previous.get("boot_id") != boot
                or not str(previous.get("diskseq", "")).isdecimal()
                or int(initial_generation) <= int(previous["diskseq"])
            ):
                raise Stop("verification_requires_reconnection_same_boot")
            result["changes_may_have_occurred"] = previous.get(
                "changes_may_have_occurred", True
            )
            result["commit_confirmed"] = previous.get("commit_confirmed", False)
            verification_archive = archive_pending_record(
                state, previous_raw, "password-change-verification",
                previous.get("verification_archive"),
            )
            result["pending_archive"] = str(verification_archive)
        elif pending.exists():
            raise Stop("pending_requires_review_use_status_no_changes")
        with host.claim(info["device"]):
            if verify_only:
                raw = transfer("discovery-before", DISCOVERY_CDB, request=4096)
                try:
                    result["before"] = parse_state(raw, "locked")
                except Stop:
                    result["before"] = parse_state(raw, "unlocked")
                result["error_stage"] = "candidate password input"
                new_password = host.password()
                for authority in (6, 7):
                    sessions = auth(
                        "verify-authority-" + str(authority), new_password, authority
                    )
                    end(sessions, "end-authority-" + str(authority))
                new_password = None
                result["after"] = parse_state(
                    transfer("discovery-after", DISCOVERY_CDB, request=4096),
                    "locked" if result["before"]["locked"] else "unlocked",
                )
                # Evidence is mandatory even when optional result saving is off.
                save(verification_archive / "verification.json", {
                    **result, "outcome": "password_verified",
                    "both_credentials_verified": True,
                })
                clear_pending(state)
                result.update(
                    complete=True,
                    outcome="password_verified",
                    both_credentials_verified=True,
                )
                result.pop("error_stage", None)
                return result
            result["before"] = parse_state(
                transfer("discovery-before", DISCOVERY_CDB, request=4096), "unlocked"
            )
            result["error_stage"] = "password input"
            current_password, new_password = (
                host.change_password_inputs()
                if hasattr(host, "change_password_inputs")
                else change_password_inputs()
            )
            password_pin_set(19, new_password)
            start_session(current_password)
            if current_password == new_password:
                raise Stop("new_password_same_no_changes")
            result["before_auth"] = parse_state(
                transfer("discovery-before-auth", DISCOVERY_CDB, request=4096),
                "unlocked",
            )
            sessions = auth("auth-current", current_password)
            current_password = None
            result["transaction_may_be_open"] = True
            validate_change(
                "transaction_start",
                exchange("transaction-start", b"\xfb\x00", sessions),
                4100,
                sessions,
            )
            for target in (19, 20):
                result["changes_may_have_occurred"] = True
                raw = exchange(
                    "set-pin-" + str(target),
                    password_pin_set(target, new_password),
                    sessions,
                )
                validate_change("pin_set", raw, 4100, sessions)
            validate_change(
                "transaction_end",
                exchange("commit", b"\xfc\x00", sessions),
                4100,
                sessions,
            )
            result["commit_confirmed"] = True
            result["transaction_may_be_open"] = False
            marker("commit-confirmed")
            end(sessions, "end-current")
            sessions = auth("verify-new", new_password)
            new_password = None
            end(sessions, "end-verification")
            result["after"] = parse_state(
                transfer("discovery-after", DISCOVERY_CDB, request=4096), "unlocked"
            )
            clear_pending(state)
            result.update(
                complete=True, outcome="password_changed", new_password_verified=True
            )
            result.pop("error_stage", None)
    except KeyboardInterrupt:
        result["error"] = "interrupted"
    except (Stop, ProtocolError, ValueError) as exc:
        result["error"] = (
            str(exc) if isinstance(exc, Stop) else "unsupported_protocol_response"
        )
    except Exception:
        result["error"] = "local_error"
    finally:
        current_password = new_password = None
        if not result["complete"]:
            result["recovery_required"] = pending.exists()
            if result["changes_may_have_occurred"]:
                result["next_step"] = "verify_change_result_do_not_repeat_set"
            elif result["recovery_required"]:
                result["next_step"] = "session_state_requires_review"
        try:
            checkpoint()
        except (OSError, KeyboardInterrupt):
            result["result_save_error"] = "result_checkpoint_failed"
    return result


# ---- Default credential structure probe (never logs credential bytes) ----
def admin_sp_anonymous_start():
    return method(
        0, 32, uint(1) + byte_atom(bytes.fromhex("0000020500000001")) + uint(1)
    )


def default_credential_get():
    target = byte_atom(bytes.fromhex("0000000b00008402"))
    return (
        b"\xf8"
        + target
        + uid(33)
        + b"\xf0\xf0\xf2\x03\x03\xf3\xf2\x04\x03\xf3\xf1\xf1\xf9"
        + TAIL
    )


def default_credential_structure(response):
    """Return structural facts, never a credential, hash, or token value."""
    values = response.values
    control = lambda value: ("control", value)
    shape_matches = (
        len(values) == 9
        and values[:3] == (control(240), control(240), control(242))
        and type(values[3]) is int
        and values[3] == 3
        and isinstance(values[4], bytes)
        and values[5:] == (control(243), control(241), control(241), control(249))
    )
    return {
        "token_shapes": [
            (
                {"kind": "bytes", "length": len(value)}
                if isinstance(value, bytes)
                else (
                    {"kind": "integer"}
                    if type(value) is int
                    else (
                        {"kind": "control"}
                        if isinstance(value, tuple)
                        and len(value) == 2
                        and value[0] == "control"
                        else {"kind": "unsupported"}
                    )
                )
            )
            for value in values
        ],
        "expected_column_structure": shape_matches,
        "nonempty_credential": shape_matches and len(values[4]) > 0,
        "credential_bytes_saved": False,
    }


# The returned value is an authentication secret, even though Get is anonymous.
# Persist only structural metadata, never token values or raw response packets.
def probe_default_credential(info, serial, out, state, host=None):
    """Anonymous AdminSP Get only. Unsupported replies stop without retries."""
    host = host or Host()
    result = {
        "action": "probe-default-credential",
        "complete": False,
        "identity": info,
        "commands": [],
        "session_may_be_open": False,
        "changes_may_have_occurred": False,
        "credential_bytes_saved": False,
    }
    sequence = host.gen(info)
    boot = boot_identity()
    pending = state / "pending.json"

    def transfer(name, cdb, payload=None, receive_bytes=None):
        result["error_stage"] = name
        if host.identify(info["device"]) != info or host.gen(info) != sequence:
            raise Stop("device_identity_or_generation_changed")
        host.idle(info["device"])
        if payload is not None:
            save(
                pending,
                {
                    "schema": 4,
                    "kind": "default_credential_probe",
                    "identity": info,
                    "serial": serial,
                    "diskseq": sequence,
                    "boot_id": boot,
                    "last_attempt": name,
                },
            )
        record = {"name": name, "phase": "attempting"}
        result["commands"].append(record)
        command = ["sg_raw", "--readonly", "--cmdset=1", "--timeout=30"]
        if payload is not None:
            command += ["--send=" + str(len(payload))]
        else:
            command += ["--request=" + str(receive_bytes), "--outfile=-"]
        command += [info["device"], *[f"{value:02x}" for value in cdb]]
        try:
            reply = host.run(
                command,
                input=payload or b"",
                capture_output=True,
                timeout=45,
                check=False,
            )
        except subprocess.TimeoutExpired:
            record["phase"] = "timeout"
            raise Stop("transport_timeout_no_retry") from None
        record.update(phase="returned", returncode=reply.returncode)
        if reply.returncode:
            raise Stop("transport_failed_no_retry")
        if receive_bytes is not None:
            record["received"] = len(reply.stdout)
            if len(reply.stdout) != receive_bytes:
                raise Stop("unexpected_receive_length")
            return reply.stdout

    def exchange(name, payload, sessions):
        packet = frame(payload, 4100, *sessions)
        transfer(name + "-out", security_cdb(181, 1, 4100, len(packet)), payload=packet)
        return transfer(
            name + "-in", security_cdb(162, 1, 4100, 2048), receive_bytes=2048
        )

    def discovery(name):
        raw = transfer(name, DISCOVERY_CDB, receive_bytes=4096)
        if int.from_bytes(raw[:4], "big") != 160 or any(raw[164:]):
            raise Stop("discovery_layout_changed")
        decoded = parse_discovery(raw[:164])
        if decoded.comid != 4100 or not decoded.locking_supported:
            raise Stop("unsupported_security_profile")
        return asdict(decoded)

    try:
        if out is not None:
            out.mkdir(parents=True, exist_ok=False, mode=0o700)
        if pending.exists():
            raise Stop("pending_requires_review_use_status_no_changes")
        with host.claim(info["device"]):
            result["before"] = discovery("discovery-before")
            result["session_may_be_open"] = True
            sessions = validate_start(
                exchange("anonymous-admin-start", admin_sp_anonymous_start(), (0, 0)),
                4100,
            )
            raw = exchange("default-get", default_credential_get(), sessions)
            response = parse_response(
                raw, expected_comid=4100, expected_sessions=sessions
            )
            result["structure"] = default_credential_structure(response)
            result["method_status"] = response.status
            if response.kind != "method" or response.status != 0:
                raise Stop("default_credential_query_rejected")
            if not result["structure"]["nonempty_credential"]:
                raise Stop("unsupported_default_credential_structure")
            del raw, response
            end = parse_response(
                exchange("anonymous-admin-end", b"\xfa", sessions),
                expected_comid=4100,
                expected_sessions=sessions,
            )
            if end.kind != "end_session":
                raise Stop("end_session_not_verified")
            result["session_may_be_open"] = False
            result["after"] = discovery("discovery-after")
            if result["before"] != result["after"]:
                raise Stop("security_state_changed_during_probe")
            clear_pending(state)
            result.update(complete=True, outcome="credential_structure_verified")
            result.pop("error_stage", None)
    except KeyboardInterrupt:
        result["error"] = "interrupted"
    except Stop as exc:
        result["error"] = str(exc)
    except ProtocolError:
        result["error"] = "unsupported_protocol_response"
    except Exception:
        result["error"] = "local_error"
    finally:
        result["recovery_required"] = pending.exists()
        if out is not None and out.exists():
            try:
                save(out / "result.json", result)
            except (OSError, KeyboardInterrupt):
                result["result_save_error"] = "result_checkpoint_failed"
    return result


# ---- Experimental security setup/removal ----
def security_discovery(raw):
    """Decode this Shield profile without requiring password security enabled."""
    if len(raw) != 4096 or int.from_bytes(raw[:4], "big") != 160 or any(raw[164:]):
        raise Stop("discovery_layout_changed")
    decoded = parse_discovery(raw[:164])
    if decoded.comid != 4100 or not decoded.locking_supported:
        raise Stop("unsupported_security_profile")
    return asdict(decoded)


# LockingEnabled remains true on the tested SSD after password removal.
# For disabled security, require unlocked/MBR-disabled here; callers also verify
# DataStore mode and credentials before declaring the operation complete.
def require_security_mode(snapshot, enabled):
    if snapshot["locked"] or (enabled and not snapshot["locking_enabled"]):
        raise Stop("security_mode_precondition_failed")
    if snapshot["mbr_enabled"] != enabled:
        raise Stop("security_mode_precondition_failed")
    # MBRDone is not prescribed when shadowing is disabled.
    if enabled and not snapshot["mbr_done"]:
        raise Stop("security_mode_precondition_failed")


def device_credential(value):
    """Only the observed 32-byte device value, with no text conversion."""
    if not isinstance(value, bytes) or len(value) != 32:
        raise Stop("unsupported_default_credential_length")
    return value


def security_auth_payload(credential, authority=6, default=False):
    if not default:
        return password_authentication_payload(credential, authority)
    device_credential(credential)
    if authority not in (6, 7):
        raise Stop("unsupported_password_authority")
    authority_uid = bytes.fromhex(
        "0000000900010001" if authority == 6 else "0000000900010002"
    )
    return method(
        0,
        32,
        uint(1)
        + uid(3)
        + uint(1)
        + b"\xf2\x00"
        + byte_atom(credential)
        + b"\xf3"
        + b"\xf2\x03"
        + byte_atom(authority_uid)
        + b"\xf3",
    )


def default_pin_set(target, credential):
    device_credential(credential)
    if target not in (19, 20):
        raise Stop("unsupported_password_target")
    target_uid = bytes.fromhex(
        "0000000b00010001" if target == 19 else "0000000b00010002"
    )
    return (
        b"\xf8"
        + byte_atom(target_uid)
        + uid(34)
        + b"\xf0\xf2\x01\xf0\xf2\x03"
        + byte_atom(credential)
        + b"\xf3\xf1\xf3\xf1\xf9"
        + TAIL
    )


# The order below is recovered from Samsung host code, not a generic reset.
# The caller sends one payload at a time and checks its response before advancing.
def security_mutations(action, credential):
    """Build the recovered order; callers must validate each individual reply."""

    def integer(target, column, value):
        return method(
            target,
            34,
            b"\xf2\x01\xf0\xf2" + uint(column) + uint(value) + b"\xf3\xf1\xf3",
        )

    if action == "set-password":
        pins = [
            (f"pin-{target}", password_pin_set(target, credential))
            for target in (19, 20)
        ]
        fields = [
            ("enable-read-lock", 1, 5, 1),
            ("enable-write-lock", 1, 6, 1),
            ("read-unlocked", 1, 7, 0),
            ("write-unlocked", 1, 8, 0),
            ("mbr-enabled", 13, 1, 1),
            ("mbr-done", 13, 2, 1),
        ]
        writes = pins + [
            (name, integer(target, column, value))
            for name, target, column, value in fields
        ]
        mode = b"\x03"
    elif action == "remove-password":
        fields = [
            ("mbr-disabled", 13, 1, 0),
            ("read-unlocked", 1, 7, 0),
            ("write-unlocked", 1, 8, 0),
            ("disable-read-lock", 1, 5, 0),
            ("disable-write-lock", 1, 6, 0),
        ]
        writes = [
            (name, integer(target, column, value))
            for name, target, column, value in fields
        ]
        writes += [
            (f"pin-{target}", default_pin_set(target, credential))
            for target in (19, 20)
        ]
        mode = b"\x02"
    else:
        raise Stop("unsupported_security_action")
    writes.append(
        (
            "datastore-mode",
            method(15, 34, b"\xf2\x00\x02\xf3\xf2\x01" + byte_atom(mode) + b"\xf3"),
        )
    )
    return writes


def new_security_password():
    if not sys.stdin.isatty():
        raise Stop("interactive_terminal_required")
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            first = hidden_password_prompt(tr("New T7 password: ")).encode("ascii")
            second = hidden_password_prompt(tr("Re-enter new T7 password: ")).encode("ascii")
            start_session(first)
            start_session(second)
        except (UnicodeError, ValueError):
            raise Stop("unsupported_password_format_no_auth_sent") from None
    if first != second:
        raise Stop("password_entries_differ_no_auth_sent")
    return first


# Do not merge this with unlock merely because the transport looks similar.
# Security setup changes credentials and policy; its pending/recovery contract
# differs from an unlock. Readonly sg_raw access does not make B5 non-mutating.
class SecuritySetupFlow:
    """One transaction; uncertain outcomes require review, never automatic Set replay."""

    def __init__(self, action, info, serial, out, state, host):
        self.action, self.info, self.serial = action, info, serial
        self.out, self.state, self.host = out, state, host
        self.generation = host.gen(info)
        self.boot = boot_identity()
        self.pending = state / "pending.json"
        self.result = dict(
            action=action,
            complete=False,
            experimental=True,
            identity=info,
            commands=[],
            session_may_be_open=False,
            transaction_may_be_open=False,
            changes_may_have_occurred=False,
            commit_confirmed=False,
            relink_attempted=False,
            credential_bytes_saved=False,
        )

    def checkpoint(self):
        if self.out is not None:
            save(self.out / "result.json", self.result)

    def marker(self, stage):
        save(
            self.pending,
            dict(
                schema=5,
                kind="security_setup",
                action=self.action,
                identity=self.info,
                serial=self.serial,
                diskseq=self.generation,
                boot_id=self.boot,
                stage=stage,
                run=str(self.out) if self.out else None,
                commit_confirmed=self.result["commit_confirmed"],
                changes_may_have_occurred=self.result["changes_may_have_occurred"],
            ),
        )

    def transfer(self, name, cdb, payload=None, request=None):
        self.result["error_stage"] = name
        if (
            self.host.identify(self.info["device"]) != self.info
            or self.host.gen(self.info) != self.generation
        ):
            raise Stop("device_identity_or_generation_changed")
        self.host.idle(self.info["device"])
        if payload is not None:
            self.marker(name)
        record = dict(name=name, phase="attempting")
        self.result["commands"].append(record)
        self.checkpoint()
        command = ["sg_raw", "--readonly", "--cmdset=1", "--timeout=30"]
        command += (
            ["--send=" + str(len(payload))]
            if payload is not None
            else ["--request=" + str(request), "--outfile=-"]
        )
        command += [self.info["device"], *[f"{value:02x}" for value in cdb]]
        try:
            reply = self.host.run(
                command,
                input=payload or b"",
                capture_output=True,
                timeout=45,
                check=False,
            )
        except subprocess.TimeoutExpired:
            record["phase"] = "timeout"
            raise Stop("transport_timeout_no_retry") from None
        record.update(phase="returned", returncode=reply.returncode)
        if reply.returncode:
            raise Stop("transport_failed_no_retry")
        if request is not None:
            record["received"] = len(reply.stdout)
            if len(reply.stdout) != request:
                raise Stop("unexpected_receive_length")
            return reply.stdout

    def exchange(self, name, payload, sessions):
        packet = frame(payload, 4100, *sessions)
        self.transfer(
            name + "-out", security_cdb(181, 1, 4100, len(packet)), payload=packet
        )
        return self.transfer(
            name + "-in", security_cdb(162, 1, 4100, 2048), request=2048
        )

    def discovery(self, name, enabled):
        snapshot = security_discovery(self.transfer(name, DISCOVERY_CDB, request=4096))
        self.result[name.replace("discovery-", "")] = snapshot
        require_security_mode(snapshot, enabled)
        return snapshot

    def auth(self, name, credential, authority=6, default=False):
        payload = security_auth_payload(credential, authority, default)
        self.result["session_may_be_open"] = True
        raw = self.exchange(name, payload, (0, 0))
        response = parse_response(raw, expected_comid=4100, expected_sessions=(0, 0))
        if response.status:
            if supported_auth_rejection(
                response, len(raw)
            ) and rejected_sync_checks_match(sync_session_checks(response)):
                self.result["session_may_be_open"] = False
                if not self.result["changes_may_have_occurred"]:
                    clear_pending(self.state)
                raise Stop(
                    "credential_verification_rejected"
                    if self.result["changes_may_have_occurred"]
                    else "authentication_rejected"
                )
            raise Stop("unsupported_auth_response")
        return validate_start(raw, 4100)

    def end(self, name, sessions):
        validate_change(
            "end_session", self.exchange(name, b"\xfa", sessions), 4100, sessions
        )
        self.result["session_may_be_open"] = False

    def read_default(self):
        self.result["session_may_be_open"] = True
        sessions = validate_start(
            self.exchange("anonymous-admin-start", admin_sp_anonymous_start(), (0, 0)),
            4100,
        )
        response = parse_response(
            self.exchange("default-get", default_credential_get(), sessions),
            expected_comid=4100,
            expected_sessions=sessions,
        )
        structure = default_credential_structure(response)
        if (
            response.kind != "method"
            or response.status != 0
            or not structure["nonempty_credential"]
        ):
            raise Stop("unsupported_default_credential_structure")
        credential = device_credential(response.values[4])
        self.end("anonymous-admin-end", sessions)
        return credential

    def verify_mode(self, name, enabled):
        """Read Samsung DataStore mode; do not infer it from LockingEnabled."""
        self.result["session_may_be_open"] = True
        sessions = validate_start(
            self.exchange(name + "-start", start_session(), (0, 0)), 4100
        )
        data = validate_get(
            self.exchange(name + "-get", datastore_get(), sessions), 4100, sessions
        )
        mode = data[2]
        self.result[name] = {"datastore_byte2": mode}
        self.end(name + "-end", sessions)
        if mode != (3 if enabled else 2):
            raise Stop("unexpected_datastore_security_mode")

    def run(self):
        credential = default = target = None
        try:
            if self.action not in ("set-password", "remove-password"):
                raise Stop("unsupported_security_action")
            if not operation_model_allowed(self.info["model"], self.host):
                raise Stop("unsupported_security_profile")
            if self.out is not None:
                self.out.mkdir(parents=True, exist_ok=False, mode=0o700)
            self.result["error_stage"] = "pending inspection"
            if self.pending.exists():
                raise Stop("pending_requires_review_use_status_no_changes")
            enabled_before = self.action == "remove-password"
            with self.host.claim(self.info["device"]):
                self.discovery("discovery-before", enabled_before)
                self.result["error_stage"] = "password input"
                credential = (
                    self.host.password()
                    if enabled_before
                    else (
                        self.host.new_security_password()
                        if hasattr(self.host, "new_security_password")
                        else new_security_password()
                    )
                )
                start_session(credential)
                self.discovery("discovery-before-auth", enabled_before)
                # Match the recovered upper layer's separate current-password validation.
                if enabled_before:
                    sessions = self.auth("verify-current", credential)
                    self.end("end-current-verification", sessions)
                default = self.read_default()
                self.discovery("discovery-before-change", enabled_before)
                self.verify_mode("mode-before", enabled_before)
                sessions = self.auth(
                    "auth-change",
                    credential if enabled_before else default,
                    default=not enabled_before,
                )
                target = default if enabled_before else credential
                self.result["transaction_may_be_open"] = True
                validate_change(
                    "transaction_start",
                    self.exchange("transaction-start", b"\xfb\x00", sessions),
                    4100,
                    sessions,
                )
                for name, payload in security_mutations(self.action, target):
                    self.result["changes_may_have_occurred"] = True
                    validate_change(
                        "set",
                        self.exchange("set-" + name, payload, sessions),
                        4100,
                        sessions,
                    )
                validate_change(
                    "transaction_end",
                    self.exchange("commit", b"\xfc\x00", sessions),
                    4100,
                    sessions,
                )
                self.result.update(commit_confirmed=True, transaction_may_be_open=False)
                self.marker("commit-confirmed")
                self.end("end-change", sessions)
                for authority in (6, 7):
                    sessions = self.auth(
                        f"verify-target-{authority}",
                        target,
                        authority,
                        default=enabled_before,
                    )
                    self.end(f"end-target-{authority}", sessions)
                self.result["both_credentials_verified"] = True
                self.verify_mode("mode-after", not enabled_before)
                self.discovery("discovery-after", not enabled_before)
                self.result["password_security"] = (
                    "disabled" if enabled_before else "enabled"
                )
                clear_pending(self.state)
                self.result.update(
                    complete=True,
                    both_credentials_verified=True,
                    outcome="password_removed" if enabled_before else "password_set",
                )
                self.result.pop("error_stage", None)
        except KeyboardInterrupt:
            self.result["error"] = "interrupted"
        except Stop as exc:
            self.result["error"] = str(exc)
        except (ProtocolError, ValueError):
            self.result["error"] = "unsupported_protocol_response"
        except Exception:
            self.result["error"] = "local_error"
        finally:
            credential = default = target = None
            self.result["recovery_required"] = self.pending.exists()
            if self.result["recovery_required"]:
                self.result["next_step"] = (
                    "review_security_setup_pending_do_not_repeat_changes"
                )
            try:
                self.checkpoint()
            except (OSError, KeyboardInterrupt):
                self.result["result_save_error"] = "result_checkpoint_failed"
        return self.result


def execute_security_setup(action, info, serial, out, state, host=None):
    return SecuritySetupFlow(action, info, serial, out, state, host or Host()).run()


# Verification resolves only a committed removal after a new connection.
# It archives the original record before new session traffic and writes evidence
# before removing pending. It must never send Set, transaction, or Relink commands.
class RemovedPasswordVerification(SecuritySetupFlow):
    """Verify a committed removal after reconnection; no Set/transaction/Relink."""

    def marker(self, stage):
        save(
            self.pending,
            dict(
                schema=5,
                kind="security_setup",
                action="remove-password",
                identity=self.info,
                serial=self.serial,
                diskseq=self.generation,
                boot_id=self.boot,
                stage=stage,
                run=str(self.out) if self.out else None,
                commit_confirmed=True,
                changes_may_have_occurred=True,
                verification_origin=self.origin,
            ),
        )

    def run(self):
        credential = None
        self.result["verify_only"] = True
        try:
            if not operation_model_allowed(self.info["model"], self.host):
                raise Stop("unsupported_security_profile")
            self.result["error_stage"] = "pending inspection"
            raw = self.pending.read_bytes()
            previous = json.loads(raw)
            identity = previous.get("identity", {})
            if (
                previous.get("schema") != 5
                or previous.get("kind") != "security_setup"
                or previous.get("action") != "remove-password"
                or previous.get("commit_confirmed") is not True
                or previous.get("changes_may_have_occurred") is not True
            ):
                raise Stop("unsupported_pending_for_verification")
            if (
                identity.get("model") != self.info["model"]
                or set(identity.get("serials", [])) != set(self.info["serials"])
                or previous.get("serial") not in self.info["serials"]
            ):
                raise Stop("pending_device_mismatch")
            if (
                previous.get("boot_id") != self.boot
                or not str(previous.get("diskseq", "")).isdecimal()
                or not str(self.generation).isdecimal()
                or int(self.generation) <= int(previous["diskseq"])
            ):
                raise Stop("verification_requires_reconnection_same_boot")
            if self.out is not None:
                self.out.mkdir(parents=True, exist_ok=False, mode=0o700)
            history = archive_pending_record(
                self.state, raw, "removal-verification",
                previous.get("verification_origin"),
            )
            self.origin = str(history)
            self.result["pending_archive"] = self.origin
            self.result.update(commit_confirmed=True, changes_may_have_occurred=True)
            with self.host.claim(self.info["device"]):
                self.discovery("discovery-before", False)
                credential = self.read_default()
                for authority in (6, 7):
                    sessions = self.auth(
                        f"verify-default-{authority}",
                        credential,
                        authority,
                        default=True,
                    )
                    self.end(f"end-default-{authority}", sessions)
                credential = None
                self.result["both_credentials_verified"] = True
                self.verify_mode("mode-after", False)
                self.discovery("discovery-after", False)
                self.result["password_security"] = "disabled"
                self.result["outcome"] = "password_removal_verified"
                # Evidence must be durable even without --save-results.
                save(history / "verification.json", self.result)
                clear_pending(self.state)
                self.result["complete"] = True
                self.result.pop("error_stage", None)
        except KeyboardInterrupt:
            self.result["error"] = "interrupted"
        except Stop as exc:
            self.result["error"] = str(exc)
        except (ProtocolError, ValueError):
            self.result["error"] = "unsupported_protocol_response"
        except Exception:
            self.result["error"] = "local_error"
        finally:
            credential = None
            self.result["recovery_required"] = self.pending.exists()
            try:
                if self.out is not None and self.out.exists():
                    self.checkpoint()
            except (OSError, KeyboardInterrupt):
                self.result["result_save_error"] = "result_checkpoint_failed"
        return self.result


# Exact message lookup keeps device data, paths and machine error codes intact.
# Library callers retain Korean defaults; main selects a language per invocation.
LANGUAGE = "ko"
EN_MESSAGES = {
    "T7/T7 Touch 미검증 작업 허용; 후보가 한 대면 자동 선택. 안전 검사는 유지됩니다.": "Allow unverified T7/T7 Touch operations; select automatically when exactly one candidate exists. Safety checks remain enabled.",
    "미검증 모델: 호환성과 데이터 안전성은 확인되지 않았습니다.": "Unverified model: compatibility and data safety have not been established.",
    "상태 파일의 링크·소유권·권한을 확인하세요. 자동으로 변경하지 않았습니다.": "Check record links, ownership and permissions. They were not changed automatically.",
    "저장 디렉터리의 소유권·쓰기 권한이 안전 조건과 다릅니다. 기존 기록을 보존하고 확인하세요.": "Storage directory ownership or write permissions are unsafe. Preserve existing records and inspect the directory.","--lang에는 en 또는 ko를 지정하세요.": "Use en or ko with --lang.",
    "옵션을 해석할 수 없습니다. --help로 사용법을 확인하세요.": "Invalid arguments. Use --help to check the syntax.",
    "암호 숨김 입력을 위해 대화형 터미널에서 실행하세요.": "Use an interactive terminal for hidden password input.",
    "장치가 여러 개입니다. list에서 확인한 일련번호를 --serial로 지정하세요.": "Multiple devices found. Select a serial from list using --serial.",' (마지막 관측)': ' (last observed)',
 ' (전송 또는 응답 검증)': ' (transport or response validation)',
 'Discovery → 현재 암호 1회 → 익명 상태·인증·잠금 해제 → Relink → 상태 확인': 'Discovery → current password once → '
                                                           'anonymous status/authentication/unlock '
                                                           '→ Relink → state verification',
 'Discovery 길이 형식을 해석할 수 없습니다. 원본 응답 검토가 필요합니다.': 'Unsupported Discovery length convention. Review '
                                                  'the response.',
 'Discovery로 잠금 상태 조회 (비밀번호 보안 여부 단독 확정 불가)': 'Query lock state using Discovery (cannot establish '
                                              'password security alone)',
 'INQUIRY·Discovery 조회 및 프로파일 비교 (unlock 호환성 검증 아님)': 'Query INQUIRY/Discovery and compare '
                                                      'profiles (does not prove unlock '
                                                      'compatibility)',
 'T7 계열 후보를 호스트에서 조회합니다. 장치 명령은 전송하지 않습니다.': 'List T7 family candidates from the host without '
                                             'device commands.',
 'T7 후보 장치가 없습니다.': 'No T7 candidate devices found.',
 'sg_raw를 찾지 못했습니다. sg3_utils 설치 여부를 확인하세요.': 'sg_raw was not found. Check your sg3_utils '
                                              'installation.',
 '검증 전용 실행': 'Verification only',
 '결과 JSON 저장; probe만 INQUIRY/Discovery 원본도 저장. 안전 기록은 이 옵션과 별개': 'Save result JSON; probe also '
                                                                 'saves raw INQUIRY/Discovery. '
                                                                 'Safety records are independent.',
 '결과 저장 오류: 화면 결과를 보존하세요. 파일은 최신 상태가 아닐 수 있습니다.': 'Result saving failed: preserve the console '
                                                  'output. The file may be stale.',
 '결과 파일 저장': 'Result file saving',
 '결과 파일 저장 안 함 (--save-results로 저장 가능; 안전 기록은 별도)': 'Result file not saved (use --save-results; '
                                                    'safety records are separate)',
 '결과 파일: ': 'Result file: ',
 '계획: ': 'Plan: ',
 '계획과 조건을 확인한 뒤 --execute로 실행하세요.': 'Review the plan and preconditions, then use --execute.',
 '기본 credential 구조 조회 완료 (값 저장 없음)': 'Default credential structure queried (value not saved)',
 '기본 출력은 요약입니다. --json: JSON 출력, --execute: 선택한 장치 작업 실행.': 'Default output is a summary. --json: '
                                                            'JSON output; --execute: run the '
                                                            'selected device operation.',
 '기존 암호 변경 pending·재연결 검사 → 후보 암호 1회 → 두 authority 인증·상태 검사 → 증거 보관·pending 해소 (Set 없음)': 'Check '
                                                                                          'password-change '
                                                                                          'pending/reconnection '
                                                                                          '→ '
                                                                                          'candidate '
                                                                                          'password '
                                                                                          'once → '
                                                                                          'authenticate '
                                                                                          'both '
                                                                                          'authorities/check '
                                                                                          'state → '
                                                                                          'archive '
                                                                                          'evidence/resolve '
                                                                                          'pending '
                                                                                          '(no '
                                                                                          'Set)',
 '기존 응답 형식과 일치 (unlock 호환성 입증 아님)': 'Matches observed profile (does not prove unlock '
                                    'compatibility)',
 '다음 조치: ': 'Next action: ',
 '동시 실행 검사': 'Concurrent execution check',
 '로그 저장 위치 검사': 'Local storage location check',
 '로컬 검사 또는 파일 처리에 실패했습니다. 권한과 경로를 확인하세요. 원인은 확정되지 않았습니다.': 'Local checks or file handling failed. '
                                                           'Check permissions and paths; the cause '
                                                           'is not established.',
 '마운트: ': 'Mount: ',
 '명령 반환 코드: ': 'Command return code: ',
 '미지원 형식 또는 수집 미완료': 'Unsupported format or incomplete collection',
 '미해결 세션·pending이 없는지 확인한 뒤 새 실행을 시작하세요.': 'Check for unresolved sessions or pending records '
                                           'before starting a new run.',
 '발생했을 수 있음': 'Possible',
 '변경 명령을 반복하거나 pending을 삭제하지 말고 기록과 상태를 검토하세요.': 'Review records and state. Do not repeat '
                                                 'mutations or delete pending records.',
 '보안 상태가 작업 조건과 다릅니다. 설정은 보안 비활성, 제거는 보안 활성·잠금 해제 상태여야 합니다.': 'Security preconditions do not '
                                                              'match. Setting requires disabled '
                                                              'security; removal requires enabled '
                                                              'security and an unlocked device.',
 '보안 활성·잠금 해제 확인 → 현재 암호 1회 → 제거·커밋 → 두 기본 credential 인증·모드·상태 확인': 'Check enabled '
                                                                    'security/unlocked state → '
                                                                    'current password once → '
                                                                    'remove/commit → verify both '
                                                                    'default '
                                                                    'credentials/mode/state',
 '보안 활성·잠금 해제 확인 → 현재 암호 1회·새 암호 2회 → 변경·커밋 → 새 암호 인증': 'Check enabled security/unlocked state → '
                                                        'current password once/new password twice '
                                                        '→ change/commit → authenticate new '
                                                        'password',
 '비밀번호 보안 제거 완료': 'Password security removed',
 '비밀번호 보안: ': 'Password security: ',
 '비활성': 'Disabled',
 '비활성 보안 모드 확인 → 새 암호 2회 → 기본 credential 인증·설정·커밋 → 두 인증·모드·상태 확인': 'Check disabled security mode '
                                                                    '→ new password twice → '
                                                                    'default credential '
                                                                    'authentication/set/commit → '
                                                                    'verify both '
                                                                    'credentials/mode/state',
 '사용자가 실행을 중단했습니다. 변경 여부와 복구 필요 상태를 확인하세요.': 'Execution interrupted. Check possible changes and '
                                             'recovery requirements.',
 '새 암호 두 입력이 다릅니다. 인증을 전송하지 않았습니다.': 'The two new password entries differ. No authentication was '
                                     'sent.',
 '실제 장치 작업 실행; 생략하면 dry-run': 'Execute the device operation; omit for dry-run',
 '실패 기록 검사: ': 'Failure record check: ',
 '실행 계획만 확인했습니다. 실제 잠금 상태는 조회하지 않았습니다.': 'Plan only. The actual device lock state was not queried.',
 '실행 중단 — ': 'Stopped — ',
 '실행 환경 검사': 'Execution environment check',
 '암호 변경 및 새 암호 인증 완료': 'Password changed and new password authenticated',
 '암호 설정 완료': 'Password set',
 '암호 제거 결과 검증 완료': 'Password removal verified',
 '암호는 공백 없는 ASCII 4~16자여야 합니다. 인증을 전송하지 않았습니다.': 'Password must contain 4–16 non-space ASCII '
                                                 'characters. No authentication was sent.',
 '없음': 'None',
 '오류 원인과 실행 조건을 확인하세요. 장치 통신 오류라면 반복 실행 전에 결과를 검토하세요.': 'Check the error and preconditions. Review '
                                                        'device communication failures before '
                                                        'another run.',
 '오류 코드: ': 'Error code: ',
 '옵션 해석': 'Argument parsing',
 '요약 대신 JSON 하나 출력': 'Output one JSON object instead of a summary',
 '요약 대신 stdout에 JSON 하나 출력': 'Output one JSON object to stdout instead of a summary',
 '응답 비교: ': 'Profile comparison: ',
 '이 조회만으로 확정하지 않음': 'Not established by this query alone',
 '이미 잠금 해제 상태입니다.': 'Already unlocked.',
 '이번 실행의 설정 변경: ': 'Settings changes in this run: ',
 '이전 실패 기록이 있어 중단했습니다. 상태 조회와 기록 검토가 필요하며 pending을 삭제해 우회하지 마세요.': 'An unresolved previous attempt '
                                                                   'blocks execution. Review state '
                                                                   'and records; do not bypass it '
                                                                   'by deleting pending.',
 '이전 인증 거부 기록을 검증 후 보관했습니다.': 'Previous authentication rejection verified and archived.',
 '이전 작업의 변경 가능성: 있음 (검증 전용 실행이 이어받은 기록)': 'Prior changes possible: yes (record inherited by '
                                          'verification-only run)',
 '이전 작업의 불확실한 결과를 검토해야 합니다. pending을 삭제하거나 변경 명령을 반복하지 마세요.': 'Review the uncertain previous '
                                                              'outcome. Do not delete pending or '
                                                              'repeat mutations.',
 '익명 AdminSP → 기본 credential 구조 조회 → 종료·상태 확인 (값 저장 없음)': 'Anonymous AdminSP → query default '
                                                          'credential structure → end/check state '
                                                          '(value not saved)',
 '인증 응답 status: ': 'Authentication response status: ',
 '인증이 거부됐습니다. 이번 실행에서는 재시도하지 않습니다. 같은 부팅에서 안전하게 전원을 차단·재연결한 뒤 새 unlock 실행으로 복구 조건을 확인할 수 있습니다.': 'Authentication '
                                                                                                 'was '
                                                                                                 'rejected; '
                                                                                                 'no '
                                                                                                 'retry '
                                                                                                 'in '
                                                                                                 'this '
                                                                                                 'run. '
                                                                                                 'After '
                                                                                                 'a '
                                                                                                 'safe '
                                                                                                 'power '
                                                                                                 'cycle '
                                                                                                 'within '
                                                                                                 'the '
                                                                                                 'same '
                                                                                                 'boot, '
                                                                                                 'a '
                                                                                                 'new '
                                                                                                 'unlock '
                                                                                                 'run '
                                                                                                 'can '
                                                                                                 'check '
                                                                                                 'recovery '
                                                                                                 'eligibility.',
 '일련번호: ': 'Serial: ',
 '일련번호로 대상 장치 선택': 'Select the device by serial',
 '일련번호로 목록 필터': 'Filter the list by serial',
 '일련번호로 장치 선택': 'Select by serial',
 '일치하는 장치를 찾지 못했습니다. 연결 상태와 일련번호를 확인하세요.': 'No matching device found. Check the connection and '
                                           'serial.',
 '입력을 수정해 다시 실행하세요. 인증은 전송하지 않았습니다.': 'Correct the input and start a new run. No authentication '
                                      'was sent.',
 '잠금 상태: ': 'Lock state: ',
 '잠금 해제 완료': 'Unlock complete',
 '잠금 해제됨': 'Unlocked',
 '잠김': 'Locked',
 '장치 revision: ': 'Device revision: ',
 '장치 명령 실행에는 관리자 권한이 필요합니다. sudo로 실행하세요.': 'Device commands require administrator privileges. Use '
                                           'sudo.',
 '장치 명령이 실패했습니다. 반환 코드와 sense 정보를 검토하세요. 자동 재시도하지 않습니다.': 'Device command failed. Review the '
                                                          'return code and sense information. No '
                                                          'automatic retry.',
 '장치 사용 여부 검사': 'Device usage check',
 '장치 선택': 'Device selection',
 '장치 응답 대기 시간이 초과됐습니다. 결과를 검토하고 반복 실행하지 마세요.': 'Device response timed out. Review the result; do '
                                               'not repeat the operation.',
 '장치 조회': 'Device query',
 '장치: ': 'Device: ',
 '장치가 사용 중입니다. 파일 작업을 끝내고 정상 언마운트하세요.': 'Device is in use. Finish file operations and unmount '
                                        'normally.',
 '조회 완료': 'Query complete',
 '조회 중 장치 식별 정보가 변경됐습니다.': 'Device identity changed during the query.',
 '추가 조치가 필요하지 않습니다.': 'No further action required.',
 '커밋 확인된 제거 pending·재연결 검사 → 기본 credential 조회·두 인증·모드·상태 검사 → 증거 보관·pending 해소 (암호 입력·Set 없음)': 'Check '
                                                                                                'committed-removal '
                                                                                                'pending/reconnection '
                                                                                                '→ '
                                                                                                'query '
                                                                                                'default '
                                                                                                'credential/verify '
                                                                                                'both '
                                                                                                'authorities/mode/state '
                                                                                                '→ '
                                                                                                'archive '
                                                                                                'evidence/resolve '
                                                                                                'pending '
                                                                                                '(no '
                                                                                                'password '
                                                                                                'input '
                                                                                                'or '
                                                                                                'Set)',
 '파일 작업을 끝내고 대상 파티션을 정상 언마운트한 뒤 실행하세요.': 'Finish file operations and unmount the target partition '
                                         'normally before running again.',
 '현재 unlock 조건과 다른 응답': 'Response differs from current unlock preconditions',
 '현재 비밀번호 인증이 거부됐습니다. 변경 명령은 진행하지 않았습니다.': 'Current password authentication was rejected. No '
                                           'mutation commands were sent.',
 '현재 암호 입력과 새 암호 입력이 같습니다. 변경하지 않았습니다.': 'Current and new password entries are identical. No '
                                         'changes made.',
 '현재 암호를 확인하고 새 실행으로 다시 시도할 수 있습니다.': 'Check the current password and start a new run.',
 '호스트 목록 조회 완료 · 장치 명령 전송 없음': 'Host listing complete; no device commands sent',
 '호스트 준비 상태: 통과 (장치 상태·pending 검증은 실행 시 수행)': 'Host checks passed (device state and pending '
                                              'verification occur during execution)',
 '화면 결과를 보존하고 저장 위치를 점검하세요. 저장 실패만으로 장치 작업을 반복하지 마세요.': 'Preserve the console result and check the '
                                                        'storage location. Do not repeat device '
                                                        'operations solely because saving failed.',
 '확인 불가': 'Unknown',
 '확인된 오류: ': 'Reported error: ',
 '활성': 'Enabled',
 '후보 암호의 두 credential 검증 완료': 'Candidate password verified for both credentials',
 '언어 선택 (기본: 시스템 로캘)': 'Output language (default: system locale)'}
KO_MESSAGES = {"password input": "암호 입력", "candidate password input": "후보 암호 입력", "pending inspection": "이전 작업 기록 검사",'T7 SSD password (hidden; NOT your Linux sudo password): ': 'T7 SSD 암호 (숨김 입력; Linux sudo 암호가 '
                                                             '아닙니다): ',
 'Current T7 password: ': '현재 T7 암호: ',
 'New T7 password: ': '새 T7 암호: ',
 'Re-enter new T7 password: ': '새 T7 암호 재입력: ',
 'Direct relock is quarantined. Unmount and safely disconnect the SSD.': '직접 재잠금 기능은 격리되어 있습니다. 정상 '
                                                                         '언마운트 후 SSD를 안전하게 분리하세요.',
 'Usage: python3 t7.py [unlock|status|probe|list|change-password|set-password|remove-password|probe-default-credential] [--serial SERIAL] [--execute] [--json] [--save-results]\nDefault: host-only unlock dry-run. --execute enables device commands.\nunlock: T7 Shield by default; one hidden password prompt when locked.\nstatus: Discovery query (Shield by default). probe/list: T7 family diagnostic tools.\nlist / --list: host-only summary; add --json for machine output.\nchange-password/remove-password: --verify-only checks eligible pending; no Set.\nUse COMMAND --help for options. No direct relock or saved credentials.': '사용법: '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'python3 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 't7.py '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '[unlock|status|probe|list|change-password|set-password|remove-password|probe-default-credential] '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '[옵션]\n'
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '기본: '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'unlock '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'dry-run. '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '--execute: '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '장치 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '작업 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '실행.\n'
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'unlock: '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '잠긴 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'Shield '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '암호 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '숨김 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '입력 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '1회.\n'
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'status: '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'Discovery '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '조회. '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'probe/list: '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'T7 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '계열 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '진단/목록.\n'
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '--json: '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'JSON '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '출력. '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '--save-results: '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '결과 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '저장. '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '--serial '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'SERIAL: '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '대상 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '선택.\n'
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'change-password/remove-password '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '--verify-only: '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '지원되는 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'pending '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '검증 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '(Set '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '없음).\n'
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 'COMMAND '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '--help로 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '옵션 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '확인. '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '직접 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '재잠금 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '및 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '암호 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '저장 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '기능 '
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 '없음.'}


def tr(message):
    """Translate known presentation text only; never rewrite arbitrary data."""
    return (EN_MESSAGES if LANGUAGE == "en" else KO_MESSAGES).get(message, message)


def locale_language():
    """Follow LC_ALL > LC_MESSAGES > LANG without mutating process locale."""
    value = next((os.environ[k] for k in ("LC_ALL", "LC_MESSAGES", "LANG") if os.environ.get(k)), "C")
    return "ko" if value.lower().split(".")[0].split("_")[0].split("-")[0] == "ko" else "en"


def stage_text(value):
    """Translate stage labels; keep the protocol command name unchanged."""
    suffix = " (전송 또는 응답 검증)"
    if value.endswith(suffix):
        return value[:-len(suffix)] + tr(suffix)
    return tr(value)


def localized_report(result):
    """Localize a copy of display fields, preserving journal and protocol data."""
    result = dict(result)
    result["language"] = LANGUAGE
    for key in ("plan", "error_stage", "result_save_error_stage"):
        if isinstance(result.get(key), str):
            result[key] = stage_text(result[key]) if key.endswith("stage") else tr(result[key])
    if "diagnostic" in result:
        result["diagnostic"] = dict(result["diagnostic"])
        for key in ("failure_stage", "next_action_message"):
            if isinstance(result["diagnostic"].get(key), str):
                result["diagnostic"][key] = stage_text(result["diagnostic"][key]) if key == "failure_stage" else tr(result["diagnostic"][key])
    return result


# === 5. Presentation and unified command-line interface ===
ERROR_MESSAGES = {
    "unsafe_local_record": "상태 파일의 링크·소유권·권한을 확인하세요. 자동으로 변경하지 않았습니다.",
    "unsafe_local_directory": "저장 디렉터리의 소유권·쓰기 권한이 안전 조건과 다릅니다. 기존 기록을 보존하고 확인하세요.",
    "invalid_language": "--lang에는 en 또는 ko를 지정하세요.",
    "invalid_arguments": "옵션을 해석할 수 없습니다. --help로 사용법을 확인하세요.",
    "interactive_terminal_required": "암호 숨김 입력을 위해 대화형 터미널에서 실행하세요.",
    "specify_serial_from_list": "장치가 여러 개입니다. list에서 확인한 일련번호를 --serial로 지정하세요.",
    "device_in_use_unmount_or_stop_disk_work_first": "장치가 사용 중입니다. 파일 작업을 끝내고 정상 언마운트하세요.",
    "execute_requires_sudo": "장치 명령 실행에는 관리자 권한이 필요합니다. sudo로 실행하세요.",
    "sg_raw_required": "sg_raw를 찾지 못했습니다. sg3_utils 설치 여부를 확인하세요.",
    "transport_failed_no_retry": "장치 명령이 실패했습니다. 반환 코드와 sense 정보를 검토하세요. 자동 재시도하지 않습니다.",
    "transport_timeout_no_retry": "장치 응답 대기 시간이 초과됐습니다. 결과를 검토하고 반복 실행하지 마세요.",
    "device_identity_or_generation_changed": "조회 중 장치 식별 정보가 변경됐습니다.",
    "matching_T7_not_found": "일치하는 장치를 찾지 못했습니다. 연결 상태와 일련번호를 확인하세요.",
    "unsupported_discovery_length_convention": "Discovery 길이 형식을 해석할 수 없습니다. 원본 응답 검토가 필요합니다.",
    "previous_attempt_needs_inspection_use_status_no_retry": "이전 실패 기록이 있어 중단했습니다. 상태 조회와 기록 검토가 필요하며 pending을 삭제해 우회하지 마세요.",
    "authentication_rejected_no_retry": "인증이 거부됐습니다. 이번 실행에서는 재시도하지 않습니다. 같은 부팅에서 안전하게 전원을 차단·재연결한 뒤 새 unlock 실행으로 복구 조건을 확인할 수 있습니다.",
    "authentication_rejected": "현재 비밀번호 인증이 거부됐습니다. 변경 명령은 진행하지 않았습니다.",
    "new_password_same_no_changes": "현재 암호 입력과 새 암호 입력이 같습니다. 변경하지 않았습니다.",
    "unsupported_password_format_no_auth_sent": "암호는 공백 없는 ASCII 4~16자여야 합니다. 인증을 전송하지 않았습니다.",
    "password_entries_differ_no_auth_sent": "새 암호 두 입력이 다릅니다. 인증을 전송하지 않았습니다.",
    "interrupted": "사용자가 실행을 중단했습니다. 변경 여부와 복구 필요 상태를 확인하세요.",
    "security_mode_precondition_failed": "보안 상태가 작업 조건과 다릅니다. 설정은 보안 비활성, 제거는 보안 활성·잠금 해제 상태여야 합니다.",
    "pending_requires_review_use_status_no_changes": "이전 작업의 불확실한 결과를 검토해야 합니다. pending을 삭제하거나 변경 명령을 반복하지 마세요.",
    "local_error": "로컬 검사 또는 파일 처리에 실패했습니다. 권한과 경로를 확인하세요. 원인은 확정되지 않았습니다.",
}


# Presentation is derived from evidence; it must not initiate device traffic or
# infer Samsung password security from Discovery's LockingEnabled flag alone.
def diagnostic_summary(result):
    action = result.get("action")
    error = result.get("error")
    verification = result.get("verify_only", False)
    read_only_action = action in ("list", "status", "probe", "probe-default-credential")
    host_stage = result.get("error_stage") in (
        "옵션 해석", "장치 선택", "로그 저장 위치 검사", "장치 사용 여부 검사",
        "실행 환경 검사", "동시 실행 검사",
    ) or result.get("error_stage") in tuple(EN_MESSAGES[k] for k in (
        "옵션 해석", "장치 선택", "로그 저장 위치 검사", "장치 사용 여부 검사", "실행 환경 검사", "동시 실행 검사"
    ))
    if result.get("dry_run") or read_only_action or verification or host_stage:
        changes = "none"
    elif result.get("changes_may_have_occurred") is True:
        changes = "possible"
    elif result.get("changes_may_have_occurred") is False:
        changes = "none"
    else:
        changes = "unknown"

    # Session traffic can be uncertain even when no data/policy Set was sent.
    uncertain = (
        result.get("recovery_required") is True
        or result.get("session_may_be_open") is True
        or result.get("transaction_may_be_open") is True
        or str(error).startswith("pending_")
        or error == "previous_attempt_needs_inspection_use_status_no_retry"
    )
    # Use the engine's completed cleanup evidence, not the error code alone.
    # This affects reporting only; it must never clear a journal or allow I/O.
    rejection_resolved = (
        action == "unlock"
        and error == "authentication_rejected"
        and result.get("pending_cleared") is True
        and result.get("retry_without_reconnection") is True
        and result.get("session_may_be_open") is False
        and result.get("transaction_may_be_open") is False
        and result.get("changes_may_have_occurred") is False
    )
    if not error and not result.get("result_save_error"):
        next_code = "execute_after_review" if result.get("dry_run") else "none"
        message = "계획과 조건을 확인한 뒤 --execute로 실행하세요." if result.get("dry_run") else "추가 조치가 필요하지 않습니다."
    elif uncertain or (error and changes in ("possible", "unknown")):
        next_code = "review_required"
        message = "변경 명령을 반복하거나 pending을 삭제하지 말고 기록과 상태를 검토하세요."
    elif error == "authentication_rejected":
        next_code = "correct_password_new_run"
        message = "현재 암호를 확인하고 새 실행으로 다시 시도할 수 있습니다."
    elif error in ("unsupported_password_format_no_auth_sent", "password_entries_differ_no_auth_sent", "new_password_same_no_changes"):
        next_code = "correct_input"
        message = "입력을 수정해 다시 실행하세요. 인증은 전송하지 않았습니다."
    elif error == "device_in_use_unmount_or_stop_disk_work_first":
        next_code = "unmount_normally"
        message = "파일 작업을 끝내고 대상 파티션을 정상 언마운트한 뒤 실행하세요."
    elif result.get("result_save_error") and not error:
        next_code = "preserve_console_result"
        message = "화면 결과를 보존하고 저장 위치를 점검하세요. 저장 실패만으로 장치 작업을 반복하지 마세요."
    elif error in ("interrupted", "interrupted_no_retry") and changes == "none":
        next_code = "new_run_after_checks"
        message = "미해결 세션·pending이 없는지 확인한 뒤 새 실행을 시작하세요."
    else:
        next_code = "check_error"
        message = "오류 원인과 실행 조건을 확인하세요. 장치 통신 오류라면 반복 실행 전에 결과를 검토하세요."
    return {
        "failure_stage": result.get("error_stage") if error else result.get("result_save_error_stage") if result.get("result_save_error") else None,
        "cause": error or result.get("result_save_error"),
        "changes_this_run": changes,
        "prior_changes_possible": bool(verification and result.get("changes_may_have_occurred")),
        "recovery": "required" if uncertain else "not_assessed" if result.get("dry_run") or host_stage or action in ("status", "probe", "list") else "not_required" if rejection_resolved or result.get("recovery_required") is False or (not error and result.get("complete")) else "unknown",
        "next_action": next_code,
        "next_action_message": tr(message),
    }


def display_diagnostic(result, as_json):
    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    if result.get("action") == "list" and not result.get("error"):
        candidates = result.get("candidates", [])
        if not candidates:
            print(tr("T7 후보 장치가 없습니다."))
        for info in candidates:
            print(tr("장치: ") + f"{info['model']} ({info['device']})")
            print(tr("일련번호: ") + ", ".join(info["serials"]))
        print(tr("호스트 목록 조회 완료 · 장치 명령 전송 없음"))
        return
    info = result.get("identity", {})
    if result.get("model_warning"):
        print(result["model_warning"])
    if info:
        print(tr("장치: ") + f"{info.get('model', '?')} ({info.get('device', '?')})")
        print(tr("일련번호: ") + ", ".join(info.get("serials", [])))
    if result.get("dry_run"):
        print(tr("실행 계획만 확인했습니다. 실제 잠금 상태는 조회하지 않았습니다."))
        if result.get("plan"):
            print(tr("계획: ") + result["plan"])
    state = result.get("after") or result.get("discovery") or result.get("before")
    if state:
        print(tr("잠금 상태: ") + (tr("잠김") if state["locked"] else tr("잠금 해제됨")) + tr(" (마지막 관측)"))
        security = result.get("password_security")
        print(tr("비밀번호 보안: ") + ({"enabled": tr("활성"), "disabled": tr("비활성")}.get(security, tr("이 조회만으로 확정하지 않음"))))
        if security not in ("enabled", "disabled"):
            print("TCG LockingEnabled: " + str(state["locking_enabled"]))
    if result.get("action") == "probe":
        if "inquiry" in result:
            print(tr("장치 revision: ") + result["inquiry"]["revision"])
        if state:
            print(f"ComID: 0x{state['comid']:04X}")
        if result.get("classification"):
            labels = {
                "observed_profile_match_unverified_device": tr("기존 응답 형식과 일치 (unlock 호환성 입증 아님)"),
                "parsed_profile_differs": tr("현재 unlock 조건과 다른 응답"),
                "unsupported_or_incomplete": tr("미지원 형식 또는 수집 미완료"),
            }
            print(tr("응답 비교: ") + tr(labels.get(result["classification"], result["classification"])))
    if result.get("recovery", {}).get("applied"):
        print(tr("이전 인증 거부 기록을 검증 후 보관했습니다."))
    if result.get("pending_recovery"):
        print(tr("실패 기록 검사: ") + result["pending_recovery"]["reason"])
    summary = result.get("diagnostic") or diagnostic_summary(result)
    if result.get("error"):
        error = result["error"]
        print(tr("실행 중단 — ") + (summary["failure_stage"] or tr("확인 불가")))
        print(tr(ERROR_MESSAGES.get(error, tr("확인된 오류: ") + error)))
        print(tr("오류 코드: ") + error)
        for mount in result.get("usage", {}).get("mounts", []):
            print(tr("마운트: ") + f"{mount.get('device', mount.get('device_number', '?'))} → {mount['mountpoint']}")
        for command in result.get("commands", [])[-1:]:
            if command.get("returncode"):
                print(tr("명령 반환 코드: ") + str(command["returncode"]))
        if result.get("auth_method_status"):
            print(tr("인증 응답 status: ") + str(result["auth_method_status"]))
    elif result.get("complete"):
        outcomes = {
            "already_unlocked": tr("이미 잠금 해제 상태입니다."),
            "unlocked": tr("잠금 해제 완료"),
            "password_changed": tr("암호 변경 및 새 암호 인증 완료"),
            "password_verified": tr("후보 암호의 두 credential 검증 완료"),
            "password_set": tr("암호 설정 완료"),
            "password_removed": tr("비밀번호 보안 제거 완료"),
            "password_removal_verified": tr("암호 제거 결과 검증 완료"),
            "credential_structure_verified": tr("기본 credential 구조 조회 완료 (값 저장 없음)"),
        }
        print(outcomes.get(result.get("outcome"), tr("조회 완료")))
    elif result.get("dry_run"):
        print(tr("호스트 준비 상태: 통과 (장치 상태·pending 검증은 실행 시 수행)"))
    if result.get("error") or result.get("result_save_error"):
        print(tr("이번 실행의 설정 변경: ") + {"none": tr("없음"), "possible": tr("발생했을 수 있음"), "unknown": tr("확인 불가")}[summary["changes_this_run"]])
        if summary["prior_changes_possible"]:
            print(tr("이전 작업의 변경 가능성: 있음 (검증 전용 실행이 이어받은 기록)"))
        print(tr("다음 조치: ") + summary["next_action_message"])
    if result.get("result_save_error"):
        print(tr("결과 저장 오류: 화면 결과를 보존하세요. 파일은 최신 상태가 아닐 수 있습니다."))
    elif result.get("result_path"):
        print(tr("결과 파일: ") + result["result_path"])
    elif not result.get("dry_run"):
        print(tr("결과 파일 저장 안 함 (--save-results로 저장 가능; 안전 기록은 별도)"))


ACTION_PLANS = {
    "unlock": "Discovery → 현재 암호 1회 → 익명 상태·인증·잠금 해제 → Relink → 상태 확인",
    "status": "Discovery로 잠금 상태 조회 (비밀번호 보안 여부 단독 확정 불가)",
    "probe": "INQUIRY·Discovery 조회 및 프로파일 비교 (unlock 호환성 검증 아님)",
    "probe-default-credential": "익명 AdminSP → 기본 credential 구조 조회 → 종료·상태 확인 (값 저장 없음)",
    "change-password": "보안 활성·잠금 해제 확인 → 현재 암호 1회·새 암호 2회 → 변경·커밋 → 새 암호 인증",
    "set-password": "비활성 보안 모드 확인 → 새 암호 2회 → 기본 credential 인증·설정·커밋 → 두 인증·모드·상태 확인",
    "remove-password": "보안 활성·잠금 해제 확인 → 현재 암호 1회 → 제거·커밋 → 두 기본 credential 인증·모드·상태 확인",
}
VERIFICATION_PLANS = {
    "change-password": "기존 암호 변경 pending·재연결 검사 → 후보 암호 1회 → 두 authority 인증·상태 검사 → 증거 보관·pending 해소 (Set 없음)",
    "remove-password": "커밋 확인된 제거 pending·재연결 검사 → 기본 credential 조회·두 인증·모드·상태 검사 → 증거 보관·pending 해소 (암호 입력·Set 없음)",
}


def list_cli(argv):
    """Host-only list with explicit options; never silently drop arguments."""
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            raise Stop("invalid_arguments")
    parser = Parser(description=tr("T7 계열 후보를 호스트에서 조회합니다. 장치 명령은 전송하지 않습니다."))
    parser.add_argument("--lang", choices=("en", "ko"), help=tr("언어 선택 (기본: 시스템 로캘)"))
    parser.add_argument("--serial", help=tr("일련번호로 목록 필터"))
    parser.add_argument("--json", action="store_true", help=tr("요약 대신 JSON 하나 출력"))
    report = {"action": "list", "complete": False, "commands": [], "dry_run": False,
              "save_results": False, "result_path": None, "device_commands_sent": False}
    as_json = "--json" in argv
    try:
        args = parser.parse_args(argv)
        candidates = list_devices(family=True)
        report["candidates"] = [info for info in candidates if args.serial in info["serials"]] if args.serial else candidates
        report["complete"] = True
    except Stop as exc:
        report.update(error=str(exc), error_stage="옵션 해석")
    except KeyboardInterrupt:
        report.update(error="interrupted", error_stage="장치 선택")
    except Exception:
        report.update(error="local_error", error_stage="장치 선택")
    report["diagnostic"] = diagnostic_summary(report)
    report = localized_report(report)
    display_diagnostic(report, as_json)
    return 0 if report["complete"] else 1


# Dry-run performs host checks only. It neither proves device security state
# nor resolves pending. JSON output and optional reports are separate from the
# mandatory safety journal stored under state/.
def diagnostic_cli(action, argv):
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            raise Stop("invalid_arguments")

    parser = Parser(
        description=tr("기본 출력은 요약입니다. --json: JSON 출력, --execute: 선택한 장치 작업 실행.")
    )
    parser.add_argument("--lang", choices=("en", "ko"), help=tr("언어 선택 (기본: 시스템 로캘)"))
    parser.add_argument("--allow-unverified-model", action="store_true",
                        help=tr("T7/T7 Touch 미검증 작업 허용; 후보가 한 대면 자동 선택. 안전 검사는 유지됩니다."))
    parser.add_argument("--serial", help=tr("일련번호로 대상 장치 선택"))
    if action in ("change-password", "remove-password"):
        parser.add_argument(
            "--verify-only",
            action="store_true",
            help=tr(VERIFICATION_PLANS.get(action, "검증 전용 실행")),
        )
    parser.add_argument("--execute", action="store_true", help=tr("실제 장치 작업 실행; 생략하면 dry-run"))
    parser.add_argument("--json", action="store_true", help=tr("요약 대신 stdout에 JSON 하나 출력"))
    parser.add_argument(
        "--save-results",
        action="store_true",
        help=tr("결과 JSON 저장; probe만 INQUIRY/Discovery 원본도 저장. 안전 기록은 이 옵션과 별개"),
    )
    result = {"action": action, "complete": False, "commands": [], "dry_run": "--execute" not in argv, "save_results": "--save-results" in argv, "result_path": None}
    stage = "옵션 해석"
    out = None
    as_json = "--json" in argv
    try:
        args = parser.parse_args(argv)
        as_json = args.json
        result["dry_run"] = not args.execute
        result["save_results"] = args.save_results
        result["verify_only"] = getattr(args, "verify_only", False)
        stage = "장치 선택"
        candidates = list_devices(family=action == "probe" or args.allow_unverified_model)
        selected = (
            [i for i in candidates if args.serial in i["serials"]]
            if args.serial
            else candidates
        )
        if len(selected) != 1:
            result["candidates"] = candidates
            raise Stop(
                "matching_T7_not_found" if not selected else "specify_serial_from_list"
            )
        info = selected[0]
        result["identity"] = info
        if not (is_supported_model(info["model"]) or
                ((action == "probe" or args.allow_unverified_model) and is_t7_family(info["model"]))):
            raise Stop("unsupported_security_profile")
        result["allow_unverified_model"] = args.allow_unverified_model
        result["unverified_model"] = not is_supported_model(info["model"])
        if result["unverified_model"]:
            result["model_warning"] = tr("미검증 모델: 호환성과 데이터 안전성은 확인되지 않았습니다.")
        host = UnverifiedModelHost() if args.allow_unverified_model else Host()
        host_options = {"host": host} if args.allow_unverified_model else {}
        if not info["serials"]:
            raise Stop("device_serial_unavailable")
        key = info["model"] + "\0" + "\0".join(sorted(set(info["serials"])))
        state = BASE / "state" / hashlib.sha256(key.encode()).hexdigest()[:24]
        runroot = BASE / ("compatibility-runs" if action == "probe" else "runs")
        stage = "로그 저장 위치 검사"
        for path in ((BASE, state, runroot) if args.save_results else (BASE, state)):
            local_output(path, info)
        if action == "unlock" and not args.execute:
            try:
                pending = state / "pending.json"
                if pending.exists():
                    reason = assess_pending(
                        json.loads(pending.read_text()),
                        info,
                        generation(info),
                        boot_identity(),
                    )
                    result["pending_recovery"] = {
                        "reason": reason,
                        "applied": False,
                        "device_state_checked": False,
                    }
            except PermissionError:
                result["pending_recovery"] = {
                    "reason": "pending_access_requires_sudo",
                    "applied": False,
                    "device_state_checked": False,
                }
        stage = "장치 사용 여부 검사"
        result["usage"] = usage_snapshot(info["device"])
        candidate = (
            auto_unmount_candidate(result["usage"]) if action == "unlock" else None
        )
        result["host_checks_passed"] = result["usage"]["idle"] or candidate is not None
        if action == "unlock":
            result["planned_unmount"] = candidate
            result["automatic_unmount"] = True
        if not result["host_checks_passed"]:
            raise Stop("device_in_use_unmount_or_stop_disk_work_first")
        if args.execute:
            stage = "실행 환경 검사"
            if os.geteuid() != 0:
                raise Stop("execute_requires_sudo")
            if not shutil.which("sg_raw"):
                raise Stop("sg_raw_required")
            os.umask(0o077)
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            stage = "동시 실행 검사"
            with run_lock(state):
                out = (
                    runroot
                    / (
                        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                        + "-"
                        + uuid.uuid4().hex[:8]
                    )
                    if args.save_results
                    else None
                )
                stage = "장치 조회"
                if action == "probe":
                    collected = collect(info, out)
                elif action == "probe-default-credential":
                    collected = probe_default_credential(
                        info, args.serial or info["serials"][0], out, state, **host_options
                    )
                elif action in ("set-password", "remove-password"):
                    if action == "remove-password" and args.verify_only:
                        collected = RemovedPasswordVerification(
                            action,
                            info,
                            args.serial or info["serials"][0],
                            out,
                            state,
                            host,
                        ).run()
                    else:
                        collected = execute_security_setup(
                            action, info, args.serial or info["serials"][0], out, state, **host_options
                        )
                elif action == "change-password":
                    collected = execute_password_change(
                        info,
                        args.serial or info["serials"][0],
                        out,
                        state,
                        verify_only=args.verify_only,
                        **host_options,
                    )
                else:
                    collected = execute_unlock(
                        info, args.serial or info["serials"][0], action, out, state, **host_options
                    )
                result.update(collected)
                result["action"] = action
                if not result["complete"]:
                    last = result.get("commands", [])[-1:]
                    if result.get("error") in (
                        "unsupported_password_format_no_auth_sent",
                        "password_entries_differ_no_auth_sent",
                        "new_password_same_no_changes",
                    ):
                        result["error_stage"] = "password input"
                    result["error_stage"] = result.get("error_stage") or (
                        last[0]["name"] + " (전송 또는 응답 검증)" if last else stage
                    )
        else:
            result["planned_queries"] = (
                ["INQUIRY", "Discovery"] if action == "probe" else ["Discovery"]
            )
            result["plan"] = VERIFICATION_PLANS[action] if result["verify_only"] else ACTION_PLANS[action]
            if action in ("set-password", "remove-password", "change-password"):
                result["experimental"] = True
    except Stop as e:
        result.update(error=str(e), error_stage=stage)
    except KeyboardInterrupt:
        result.update(error="interrupted", error_stage=stage)
    except Exception:
        result.update(error="local_error", error_stage=stage, complete=False)
    if out is not None and out.exists():
        result["result_path"] = str(out / "result.json")
    result["diagnostic"] = diagnostic_summary(result)
    result = localized_report(result)
    if result["result_path"] is not None:
        try:
            save(out / "result.json", result)
        except (Exception, KeyboardInterrupt):
            # Preserve an already observed device outcome, error and stage.
            # The process exit code still reports unsuccessful report delivery.
            result["result_save_error"] = "result_save_failed"
            result["result_save_error_stage"] = "결과 파일 저장"
    result["diagnostic"] = diagnostic_summary(result)
    result = localized_report(result)
    display_diagnostic(result, as_json)
    return (
        1
        if result.get("error") or result.get("result_save_error") or (not result.get("dry_run") and not result["complete"])
        else 0
    )


# ---- Unified command line ----
def _main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in ("lock", "relock"):
        print(
            tr("Direct relock is quarantined. Unmount and safely disconnect the SSD."),
            file=sys.stderr,
        )
        return 1
    if args and args[0] in (
        "status",
        "probe",
        "unlock",
        "change-password",
        "probe-default-credential",
        "set-password",
        "remove-password",
    ):
        return diagnostic_cli(args[0], args[1:])
    if args and args[0] == "list":
        return list_cli(args[1:])
    if args in (["--help"], ["-h"]):
        print(
            tr("Usage: python3 t7.py [unlock|status|probe|list|change-password|set-password|remove-password|probe-default-credential] [--serial SERIAL] [--execute] [--json] [--save-results]\n"
            "Default: host-only unlock dry-run. --execute enables device commands.\n"
            "unlock: T7 Shield by default; one hidden password prompt when locked.\n"
            "status: Discovery query (Shield by default). probe/list: T7 family diagnostic tools.\n"
            "list / --list: host-only summary; add --json for machine output.\n"
            "change-password/remove-password: --verify-only checks eligible pending; no Set.\n"
            "Use COMMAND --help for options. No direct relock or saved credentials.")
        )
        print(tr("T7/T7 Touch 미검증 작업 허용; 후보가 한 대면 자동 선택. 안전 검사는 유지됩니다.") + " (--allow-unverified-model)")
        print("--lang en|ko: output language; default follows LC_ALL / LC_MESSAGES / LANG." if LANGUAGE == "en" else "--lang en|ko: 출력 언어. 기본값은 LC_ALL / LC_MESSAGES / LANG을 따릅니다.")
        return 0
    if args and args[0] == "--list":
        return list_cli(args[1:])
    return diagnostic_cli("unlock", args)


def main(argv=None):
    """Select language before parsing/help/prompts, and restore library context."""
    global LANGUAGE
    previous = LANGUAGE
    args = list(sys.argv[1:] if argv is None else argv)
    LANGUAGE = locale_language()
    clean = []
    try:
        index = 0
        while index < len(args):
            token = args[index]
            if token == "--lang" or token.startswith("--lang="):
                if token == "--lang":
                    index += 1
                    value = args[index] if index < len(args) else None
                else:
                    value = token.split("=", 1)[1]
                if value not in ("en", "ko"):
                    report = {"action": "cli", "complete": False, "commands": [],
                              "error": "invalid_language", "error_stage": "옵션 해석",
                              "dry_run": "--execute" not in args, "result_path": None}
                    report["diagnostic"] = diagnostic_summary(report)
                    display_diagnostic(localized_report(report), "--json" in args)
                    return 1
                LANGUAGE = value
            else:
                clean.append(token)
            index += 1
        return _main(clean)
    finally:
        LANGUAGE = previous


if __name__ == "__main__":
    raise SystemExit(main())
