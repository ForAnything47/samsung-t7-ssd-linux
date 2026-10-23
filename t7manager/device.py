"""Linux whole-disk discovery, identity and connection generation."""

from pathlib import Path
import time
import uuid

from t7manager import errors


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
        raise errors.Stop("ambiguous_serial_multiple_devices")
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
    raise errors.Stop("new_disk_generation_not_observed_do_not_repeat_relink")


def select(serial, finder=find_device):
    if serial is None:
        candidates = list_devices()
        if len(candidates) != 1:
            raise errors.Stop(
                "specify_serial_from_list" if candidates else "matching_T7_not_found"
            )
        info = candidates[0]
        if not info["serials"]:
            raise errors.Stop("device_serial_unavailable")
        serial = info["serials"][0]
    info = finder(serial)
    if info is None:
        raise errors.Stop("matching_T7_not_found")
    if not serial or serial not in info["serials"]:
        raise errors.Stop("serial_mismatch")
    return info


def partition_paths(info):
    root = Path("/sys/class/block") / Path(info["device"]).name
    return [
        {"device": "/dev/" + p.name, "size_bytes": int((p / "size").read_text()) * 512}
        for p in sorted(root.iterdir())
        if (p / "partition").exists()
    ]


def boot_identity():
    value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    return str(uuid.UUID(value))
