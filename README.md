# samsung-t7-ssd-linux

An unofficial Linux password manager for Samsung T7 SSDs. The CLI and optional PySide6
GUI can unlock a device and change, set, or remove password security.

Only one 2 TB **T7 Shield** has been tested with password operations. T7 and T7 Touch
can be listed and probed, but password operations on those models require
`--allow-unverified-model` and remain unverified on hardware.

Licensed under [MIT](LICENSE). Read [validation and limits](#validation-and-limits)
before using a device that holds important data.

## Start from source

Requirements: Linux, Python 3, `sg_raw` (sg3_utils), `findmnt` (util-linux), and
`udisksctl` (udisks2).

The CLI needs no third-party Python packages. The GUI additionally needs PySide6,
polkit, and a desktop authentication agent.

```bash
git clone https://github.com/ForAnything47/samsung-t7-ssd-linux.git
cd samsung-t7-ssd-linux
python3 t7.py list
python3 t7.py unlock
sudo python3 t7.py status --execute
sudo python3 t7.py unlock --execute
```

`list` reads host information only. Other commands are dry-runs unless `--execute` is
present. Use `--serial YOUR_SERIAL` when more than one candidate is found. `--json`
prints JSON to the terminal; `--save-results` saves a detailed result. See
[CLI examples](docs/CLI-USAGE.md).

To run the GUI from source as a **normal desktop user**:

```bash
python3 -m venv .venv-gui
.venv-gui/bin/python -m pip install -r requirements-gui.txt
.venv-gui/bin/python t7_gui.py
```

The GUI uses the same CLI checks and asks for administrator authorization through the
desktop authentication service. It asks separately for the SSD password and does not
save passwords. See [GUI usage](docs/GUI-USAGE.md).

A local Arch package provides `t7` and `t7-gui` commands; see
[packaging](docs/PACKAGING.md). No package is published yet.

## Validation and limits

On one 2 TB T7 Shield running CachyOS, unlock, password change/removal/setup, locking
after reconnection, and file reading succeeded. The four password operations also
completed through the installed GUI.

Whole-drive hash comparison, deliberate power loss, and recovery from real connection
failures were not tested. See the [validation record](docs/VALIDATION.md).

A successful `probe` does not prove password-operation compatibility. Do not test an
unverified model on the sole copy of important data.

The tool supports passwords of **4–16 non-space ASCII bytes**, following the analyzed
Samsung Magician UI input range. This is a tool support limit, not a proven protocol
requirement.

It cannot recover a forgotten password, bypass security, perform a factory reset, or
manage fingerprints.

## Before and after operations

Keep a backup, finish other disk work, and keep code and logs off the target SSD.

Unmount data partitions normally before status or password-management operations. The
unlock flow can unmount a locked announcement partition, but it does not unmount an
unlocked data partition.

After unlocking, check the partitions and read important files. Unmount before
disconnecting.

Every executed operation that reaches the device flow writes a root-owned JSON
[operation log](docs/OPERATION-LOGS.md), independent of `--save-results`.

Logs may contain serials and local paths, so redact them before sharing. They omit
passwords and raw authentication packets.

If a configuration result is uncertain, inspect the log and check current status before
another change. The tool does not automatically retry configuration requests; Ctrl+C
cannot cancel a request already received by the SSD.

## Language, development and reporting

Use `--lang en` or `--lang ko` for messages and prompts; otherwise the locale selects
the language. JSON keys and technical error codes remain stable.

The entry point is `t7.py`; implementation lives in `t7manager/`, and the GUI lives in
`gui/`. See [architecture](docs/ARCHITECTURE.md) and [changelog](CHANGELOG.md).

Offline verification:

```bash
python3 scripts/check_manifest.py
python3 -m unittest discover -s tests -p 'test_*.py'
```

Offline tests use synthetic responses and cannot establish hardware safety.

The implementation was developed with extensive Codex assistance using static analysis
of Samsung Magician Windows files and user-provided T7 Shield observations.

Samsung binaries, analysis dumps, runtime records and credentials are not distributed.
AI-written code and tests can share incorrect assumptions; independent external review
has not been completed.

The MIT license covers this project's code and documentation, not Samsung products,
trademarks or third-party material.

When reporting an issue, include the model, capacity, Linux version, USB connection and
driver, command, error code and stage, and last observed state.

**Do not publish complete logs without review**, entire `state/` or `runs/` directories,
passwords, credential values, authentication packets, or file lists.
