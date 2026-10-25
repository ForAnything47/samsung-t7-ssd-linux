"""Durable operation logs and short-lived execution locks."""

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import re
import stat
import uuid
from datetime import datetime, timezone

from t7manager import errors, paths


# Write, fsync, rename, then fsync the directory so a log survives a crash.
# Failure before transmission must stop the command; a final report failure must
# not hide a device outcome already observed.
def checked_record(directory_fd, name):
    """Reject linked or foreign records without following their target."""
    try:
        entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if (not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1
            or entry.st_uid != os.getuid() or entry.st_mode & 0o077):
        raise errors.Stop("unsafe_local_record")


def open_record_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    entry = os.fstat(fd)
    if entry.st_uid != os.getuid() or entry.st_mode & 0o022:
        os.close(fd)
        raise errors.Stop("unsafe_local_directory")
    return fd


def ensure_private_directory(path):
    """Create one installed-data directory and reject a public replacement."""
    path.mkdir(mode=0o700, exist_ok=True)
    fd = open_record_directory(path)
    try:
        if os.fstat(fd).st_mode & 0o077:
            raise errors.Stop("unsafe_local_directory")
    finally:
        os.close(fd)


def ensure_state_directory(state):
    """Avoid mkdir(parents=True) creating public /var/opt intermediates."""
    runtime = paths.data_root()
    if runtime != paths.BASE and state.parent == runtime / "state":
        for directory in (runtime, state.parent, state):
            ensure_private_directory(directory)
    else:
        state.mkdir(parents=True, mode=0o700, exist_ok=True)


def ensure_result_root(runroot):
    """Keep installed optional results private without changing source records."""
    if paths.data_root() != paths.BASE and runroot.parent == paths.data_root():
        ensure_private_directory(runroot)
    else:
        runroot.mkdir(parents=True, mode=0o700, exist_ok=True)


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


LOG_FIELDS = (
    "action", "complete", "identity", "commands", "before", "after",
    "outcome", "error", "error_stage", "session_may_be_open",
    "transaction_may_be_open", "changes_may_have_occurred",
    "commit_confirmed", "relink_attempted", "reenumeration_verified",
    "authenticated", "new_password_verified", "both_credentials_verified",
    "password_security", "recovery_required", "next_step", "result_save_error",
    # Parsed diagnostics only; never include credential queries or raw packets.
    "discovery", "inquiry", "features", "classification",
    "model_has_prior_validation", "unlock_compatibility_proven",
)
COMMAND_FIELDS = ("name", "phase", "returncode", "received", "validated",
                  "response_kind", "response_status")
IDENTITY_FIELDS = ("device", "model", "serials", "sysfs")
LOG_NAME = re.compile(r"[0-9a-f]{32}\.json\Z")


def operation_checkpoint(state, report, out=None):
    """Persist a bounded, credential-free checkpoint before device transfers.

    The run identifier is private to this process. Existing incident files are
    never read or changed, and the log has no authority over the next run.
    """
    ensure_state_directory(state)
    log_dir = state / "logs"
    if paths.data_root() != paths.BASE and state.parent == paths.data_root() / "state":
        ensure_private_directory(log_dir)
    else:
        log_dir.mkdir(mode=0o700, exist_ok=True)
    run_id = report.setdefault("run_id", uuid.uuid4().hex)
    report.setdefault("started_at", datetime.now(timezone.utc).isoformat())
    record = {key: report[key] for key in LOG_FIELDS if key in report}
    if "identity" in record:
        record["identity"] = {
            key: record["identity"][key]
            for key in IDENTITY_FIELDS if key in record["identity"]
        }
    record["schema"] = 1
    record["run_id"] = run_id
    record["started_at"] = report["started_at"]
    record["updated_at"] = datetime.now(timezone.utc).isoformat()
    record["commands"] = [
        {key: command[key] for key in COMMAND_FIELDS if key in command}
        for command in report.get("commands", [])
    ]
    log_path = log_dir / (run_id + ".json")
    save(log_path, record)
    report["log_path"] = str(log_path)
    if out is not None:
        try:
            save(out / "result.json", report)
        except (OSError, errors.Stop):
            report["result_save_error"] = "result_checkpoint_failed"
            record["result_save_error"] = report["result_save_error"]
            save(log_path, record)
            raise


def state_for_identity(info):
    """Use the same stable key as the CLI, independent of /dev/sdX."""
    key = info["model"] + "\0" + "\0".join(sorted(set(info["serials"])))
    return paths.data_root() / "state" / hashlib.sha256(key.encode()).hexdigest()[:24]


def read_log_record(directory_fd, name):
    """Read one private regular file without following links or blocking on FIFOs."""
    checked_record(directory_fd, name)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                 dir_fd=directory_fd)
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1
                or meta.st_uid != os.getuid() or meta.st_mode & 0o077):
            raise errors.Stop("unsafe_local_record")
        if meta.st_size > 65536:
            raise errors.Stop("operation_log_too_large")
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            fd = None
            return json.load(stream)
    finally:
        if fd is not None:
            os.close(fd)


def validate_log_display_fields(record):
    """Reject malformed display fields while allowing missing/unknown fields.

    Logs are evidence: validation never repairs or deletes the source file.
    This is a shape check, not a claim that the recorded device state is true.
    """
    for key in ("action", "outcome", "error", "error_stage", "classification",
                "updated_at"):
        if key in record and not isinstance(record[key], str):
            raise errors.Stop("invalid_operation_log_fields")
    for key in ("identity", "identity_after", "before", "after", "discovery",
                "inquiry", "diagnostic", "launch_diagnostic"):
        if key in record and not isinstance(record[key], dict):
            raise errors.Stop("invalid_operation_log_fields")
    for key in ("commands", "partitions", "candidates", "features"):
        if key in record and (not isinstance(record[key], list)
                              or not all(isinstance(item, dict) for item in record[key])):
            raise errors.Stop("invalid_operation_log_fields")
    if "complete" in record and type(record["complete"]) is not bool:
        raise errors.Stop("invalid_operation_log_fields")


def read_operation_logs(info, day=None):
    """Read root-owned logs for one selected SSD; never touch the SSD."""
    if day is not None:
        try:
            if datetime.strptime(day, "%Y-%m-%d").strftime("%Y-%m-%d") != day:
                raise ValueError()
        except ValueError:
            raise errors.Stop("invalid_log_date") from None
    directory = state_for_identity(info) / "logs"
    if not directory.exists():
        return {"action": "logs", "complete": True, "dates": [], "entries": [], "day": day, "device_commands_sent": False}
    fd = open_record_directory(directory)
    try:
        names = [name for name in os.listdir(fd) if LOG_NAME.fullmatch(name)]
        if len(names) > 10000:
            raise errors.Stop("too_many_operation_logs")
        dates = set()
        entries = []
        selected_day = day
        warnings = []
        skipped_count = 0
        for name in names:
            # One unreadable record must not hide other dates or operations.
            # Never follow an unsafe entry or repair/delete it during review.
            try:
                record = read_log_record(fd, name)
                if isinstance(record, dict):
                    validate_log_display_fields(record)
            except (OSError, errors.Stop, ValueError) as exc:
                skipped_count += 1
                if len(warnings) < 100:
                    reason = str(exc) if isinstance(exc, errors.Stop) else "unreadable_or_invalid_json"
                    warnings.append({"file": name, "reason": reason})
                continue
            if not isinstance(record, dict) or record.get("schema") != 1 or record.get("run_id") != name[:-5]:
                continue
            identity = record.get("identity") or {}
            if (not isinstance(identity, dict) or not isinstance(identity.get("serials"), list)
                    or not all(isinstance(value, str) for value in identity["serials"])):
                continue
            if not set(identity["serials"]).intersection(info["serials"]):
                continue
            try:
                local_day = datetime.fromisoformat(record["started_at"]).astimezone().date().isoformat()
            except (KeyError, ValueError, TypeError):
                continue
            dates.add(local_day)
            if day is None and (selected_day is None or local_day > selected_day):
                selected_day = local_day
                entries.clear()
            if selected_day == local_day:
                entries.append(record)
        entries.sort(key=lambda value: value.get("started_at", ""), reverse=True)
        truncated = len(entries) > 100
        selected = []
        remaining = 600000
        for entry in entries[:100]:
            size = len(json.dumps(entry).encode("utf-8"))
            if size > remaining:
                truncated = True
                break
            selected.append(entry)
            remaining -= size
        return {"action": "logs", "complete": True, "dates": sorted(dates, reverse=True),
                "entries": selected, "day": selected_day, "truncated": truncated,
                "skipped_count": skipped_count, "warnings": warnings,
                "device_commands_sent": False}
    finally:
        os.close(fd)


@contextmanager
# Serialize CLI operations on the serial-derived state directory.
# This complements the per-device exclusive claim; it does not replace it.
def run_lock(state):
    ensure_state_directory(state)
    directory_fd = open_record_directory(state)
    lock_fd = None
    try:
        checked_record(directory_fd, "lock")
        lock_fd = os.open("lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                          0o600, dir_fd=directory_fd)
        entry = os.fstat(lock_fd)
        if (not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1
                or entry.st_uid != os.getuid() or entry.st_mode & 0o077):
            raise errors.Stop("unsafe_local_record")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise errors.Stop("another_T7_command_is_running") from None
        yield
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
        os.close(directory_fd)
