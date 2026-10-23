# Operation logs

## Storage

An `--execute` operation that passes host checks and reaches the device flow
writes a JSON log to `state/<device-key>/logs/<run-id>.json`. Installed packages
store `state/` under `/var/opt/samsung-t7-ssd-linux/`; source-tree runs keep it
in the application directory. Keep the logs off the SSD being managed.

Failures before the device flow, such as a mounted partition or missing
administrator rights, appear in CLI or GUI output without a device log. Logs
are therefore not a complete audit of attempted commands.

Log files use mode `0600` inside `0700` directories. `--json` changes terminal
output only. `--save-results` separately saves a more detailed result under
`runs/` or `compatibility-runs/` at the same runtime root.

## Contents

Each log records a schema version, random run ID, UTC timestamps, action and
device identity. It includes attempted command stages, their phase and known
return details, the last observed device state, the outcome or error, and flags
for uncertain sessions, transactions or device changes. `probe` logs also
include parsed INQUIRY, Discovery, feature and profile diagnostics.

Before each SSD transfer, the tool saves an `attempting` checkpoint to disk.
It saves another checkpoint after a return or timeout. If the process stops
between those points, the log cannot establish whether the SSD accepted the
command.

Passwords, credential values, raw packets and transport stdout/stderr are
excluded. Logs still contain serial numbers and local paths; review and redact
them before sharing.

## GUI review

**Operation logs** opens a resizable, read-only window for the selected device.
Choose a local date and an operation to view its summary or JSON. Reading logs
uses administrator authorization but sends no SSD commands. Authorization may
be requested again after the app's retained session expires.

The viewer shows at most the latest 100 entries for a date and marks a
truncated list. It skips unreadable, oversized or unsafe individual files,
reports how many were skipped, and leaves them untouched. An unsafe log
directory prevents the entire read. The viewer cannot open arbitrary paths or
legacy pending records.

## Interrupted work

If a final log write fails after a device outcome was observed, the result
retains that outcome and reports a storage warning. Preserve the displayed
result; do not repeat a password operation just to recreate its log. A failed
checkpoint before transmission stops that transfer.

Logs support human review; they do not block or authorize later operations.
Older `pending.json` files remain untouched and do not block this version.
The separate per-device OS lock prevents concurrent processes and is released
when an operation exits.
