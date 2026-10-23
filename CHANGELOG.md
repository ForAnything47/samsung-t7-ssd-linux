# Changelog

## Unreleased

- Split the CLI into `t7.py` and `t7manager/`, retaining explicit commands
  and the `--execute` boundary.
- Added a PySide6 GUI for status, unlock and password management, with separate
  administrator authorization and hidden SSD password input.
- Added root-owned operation logs and a read-only GUI log viewer. Persistent
  pending-file creation and blocking were removed; an OS lock still prevents
  concurrent operations.
- Added a local Arch package with `t7` and `t7-gui` launchers. Code installs to
  `/opt/samsung-t7-ssd-linux/`, and runtime records use
  `/var/opt/samsung-t7-ssd-linux/`.
- Expanded offline tests, English/Korean CLI output and documentation.
