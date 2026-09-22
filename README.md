# samsung-t7-ssd-linux

An experimental, single-file Linux CLI for Samsung T7 Shield. Unlock using an existing password, change it, set initial password security, or remove password security.
This is an independent project, not an official Samsung product.

Licensed under the MIT License. See [LICENSE](LICENSE) and [provenance](#provenance-and-reporting).

## Requirements and quick start

Requirements:

- Linux and Python 3
- `sg_raw` and `findmnt`
- `udisksctl` for automatic unmounting of the locked announcement partition

No third-party Python packages are needed. Passwords are entered through hidden terminal prompts.

Clone the repository to get started:

```bash
git clone https://github.com/ForAnything47/samsung-t7-ssd-linux.git
cd samsung-t7-ssd-linux
```

Alternatively, use **Code → Download ZIP** on GitHub and open the extracted directory.
Run the following commands from that directory. Replace `YOUR_SERIAL` with the SSD serial shown by `list`; `--serial` is optional when exactly one candidate exists:

```bash
python3 t7.py list
python3 t7.py unlock --serial YOUR_SERIAL
sudo python3 t7.py status --serial YOUR_SERIAL --execute
sudo python3 t7.py unlock --serial YOUR_SERIAL --execute
```

- `--execute`: run device operations. Without it, the command is a host-only dry-run.
- `--json`: print results as JSON.
- `--save-results`: save results to a file.

See [all examples](CLI-USAGE.md).

Following the input range observed in the analyzed Samsung Magician UI, this implementation supports passwords of 4–16 non-space ASCII bytes.
This is an implementation support limit, not an established maximum or mandatory restriction of the SSD authentication protocol.
Do not modify an existing password to make it fit this restriction.

Existing users must preserve their original working state, including `state`, before moving execution to another directory. Do not switch directories to bypass pending checks. No state migration tool is provided.

## Validation and limits

| Area | Evidence |
|---|---|
| Hardware | One 2 TB T7 Shield, CachyOS, direct USB and USB hub/UAS |
| Observed operations | Unlock, password change/removal/initial setup, relocking after reconnection, file reading |
| T7 / T7 Touch | Listing and diagnostics supported; other operations require explicit opt-in and remain unverified on hardware |
| Forgotten passwords | No recovery, bypass or factory reset |
| Failure recovery | Limited verification paths; no firmware rollback or lossless recovery guarantee |

Password removal and setup were verified on one T7 Shield. After setting a password again, reconnecting the device locked it, and unlocking it with the new password allowed existing files to be read.

However, file hashes were not compared across the entire drive before and after these operations, and power loss during configuration changes was not tested. Full data integrity, recovery from failures, and equivalent behavior on other devices therefore remain unverified.

## Unverified T7 / T7 Touch models

`list` and `probe` support T7, T7 Touch and T7 Shield. Other operations default to T7 Shield.

To test a T7 or T7 Touch, explicitly pass `--allow-unverified-model` on every invocation.

- One candidate: selected automatically.
- Multiple candidates: specify `--serial YOUR_SERIAL`.
- No candidates: the operation stops.

The option expands only the allowed model scope. Response validation, serial identity, usage and pending checks remain enabled. Fingerprint enrollment, removal and authentication are not supported.

Actual compatibility and data safety on T7/T7 Touch have not been verified. Users must decide whether to test and verify the results themselves; do not test on the only copy of important data.

A successful probe does not establish unlock or configuration compatibility. Start with the [staged examples](CLI-USAGE.md#testing-unverified-models).

## Before and after an operation

Confirm backups, finish concurrent disk work and do not swap cables during execution. Keep the script and state/results on local storage other than the target SSD.
Normal data partitions are neither mounted nor unmounted automatically.

After use, unmount normally and safely disconnect the device.

`--readonly` does not make B5 configuration requests harmless.

If an operation fails with an uncertain outcome, the program preserves pending state and stops. Follow the [pending recovery procedure](CLI-USAGE.md#when-a-pending-record-remains) before starting another operation. Do not delete pending or replay failed configuration packets. Ctrl+C cannot cancel requests already received by the SSD.

Discovery `LockingEnabled` is not equivalent to user password security and may remain true after removal. Distinguish last-observed state from verified outcomes.

## English and Korean

Use `--lang en` for English or `--lang ko` for Korean messages and prompts.
Specify the option to keep your preferred language when running with sudo.

If omitted, the first nonempty value of `LC_ALL`, `LC_MESSAGES`, then `LANG` is used.
Korean locales select Korean; all others select English.

```bash
sudo python3 t7.py status --serial YOUR_SERIAL --execute --lang en
sudo python3 t7.py status --serial YOUR_SERIAL --execute --lang ko --json
```

JSON keys and machine codes remain stable. Descriptions and stage labels are translated; `language` identifies the selected language. Device output and user data are not translated.

## Development

Edit the root `t7.py` in this standalone package; no code generation or project module imports are required. Implementation provenance and reporting guidance are described below.

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

The public package has **145 passing offline tests**. Synthetic responses and mock hosts do not establish hardware safety. Password strings in tests are fabricated.

See [provenance and reporting](#provenance-and-reporting) for issue reports and sensitive information handling.

On the same device, cancellation at each of the three change-password input prompts and mismatched new entries were tested: only initial Discovery was sent, with no authentication or settings changes. After reconnection the previous password still unlocked the drive.

This does not validate interruption during Set/commit. Interrupted prompts now end with a newline on stderr, preserving JSON stdout.


Check hashes with `python3 scripts/check_manifest.py`. Update the corresponding entries in `SHA256.json` after editing files.
GitHub Actions is configured to check hashes and run offline tests on Python 3.10, 3.12 and 3.14 for pushes and pull requests. It uses neither an SSD nor sudo.

## Provenance and reporting

This project's Python implementation was developed from command sequences recovered through static analysis of Samsung Magician Windows files and user-provided T7 Shield hardware results. Samsung binaries, analysis dumps, third-party source, credentials and actual runtime records are not distributed.

The MIT license covers this project's code and documentation, not rights to Samsung products, trademarks or third-party material.

Include the following in reports:

- Device model and capacity
- OS, direct/hub USB connection and driver
- Command used
- Error code, failure stage and last-observed state

**JSON output is not anonymized.** Remove passwords, default credentials, authentication packets, actual serials, personal paths and file lists. Do not upload entire `state/` or `runs/` directories or disclose sensitive information in public issues.

Run offline tests when changing code and explain effects on command bytes/order and failure handling. Do not accept unsupported responses as success or add automatic retries. Deliberate power interruption on a real SSD is not part of routine validation.

### AI assistance and review scope

Codex was used extensively for protocol analysis assistance, implementation, refactoring, tests and documentation. The maintainer tested major operations and file reading on one T7 Shield.

AI-written implementation and tests may share incorrect assumptions; no independent external code review has been completed. Compatibility with other devices and data safety during real failures remain unproven.

