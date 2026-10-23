# Validation record and remaining checks

This document separates observed hardware behavior from offline tests and untested cases.

| Area | Observed result |
| --- | --- |
| Device | One 2 TB T7 Shield on CachyOS, connected directly and through a USB hub using UAS. |
| Password operations | Unlock, remove password, set password and change password completed through the installed GUI. The CLI flows had also been tested on this device. |
| Reconnection and data | Locking after reconnection, unlock with the applicable password and opening an existing file were observed. This is a sample read, not a drive-wide data-integrity comparison. |
| Runtime records | A privileged audit of 13 operation logs found parseable records, `complete: true`, no reported errors, no nonzero command returns, and expected `0700` directory/`0600` file permissions. This checks recorded fields, not every internal SSD response independently. |
| Package | A locally installed development package passed `pacman -Qkk` with zero altered package files. |
| Offline | Protocol, CLI, GUI and record tests passed in the source tree; the source manifest also passed its hash check. These use synthetic responses and mock hosts, not an SSD. |

GUI log date/run selection, Summary/JSON correspondence, selected-device isolation and window resizing still need a complete hands-on check. Package upgrade, uninstall and multi-user use are not release-tested. Other T7/T7 Touch hardware, whole-drive hash comparison, deliberate power interruption, and real communication-loss recovery are unverified. Do not deliberately disrupt a live SSD transaction merely to check an error path.
