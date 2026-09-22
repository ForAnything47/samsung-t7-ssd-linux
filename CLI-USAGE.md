# CLI and result interpretation

See [README](README.md#requirements-and-quick-start) for download instructions. Run commands from the script directory; for ZIP downloads, use the actual extracted directory. Replace `YOUR_SERIAL` with the SSD serial from `list`.

```bash
cd samsung-t7-ssd-linux
```

## Basic usage

### Options

| Option | Meaning |
|---|---|
| `--serial SERIAL` | Select by serial; optional with one candidate, required with multiple candidates |
| `--allow-unverified-model` | Opt in to unverified T7/T7 Touch operations; safety checks remain enabled |
| `--lang en` / `--lang ko` | Select message/prompt language; default: LC_ALL > LC_MESSAGES > LANG, Korean locales only select Korean |
| `--execute` | Perform the selected operation; otherwise host-only dry-run |
| `--json` | Emit one JSON object on stdout instead of a summary |
| `--save-results` | Save result JSON; probe also saves raw INQUIRY/Discovery |
| `--verify-only` | Supported change-password/remove-password verification path for a prior operation; not a general replacement for mutation |

`list` and its `--list` alias accept `--serial`, `--json` and `--lang`. They reject `--execute` and `--save-results`. `--help` displays help. Language can precede or follow the command; `--lang=en` also works. If repeated, the last valid language wins. Invalid or missing language values stop before device selection.

Password input is hidden and is not included in JSON stdout. Use an explicit language if sudo changes the locale environment.

### Queries and unlock

```bash
python3 t7.py list
python3 t7.py --list --json
python3 t7.py --serial YOUR_SERIAL --lang en
sudo python3 t7.py status --serial YOUR_SERIAL --execute --lang en
sudo python3 t7.py probe --serial YOUR_SERIAL --execute --json --save-results --lang en
sudo python3 t7.py unlock --serial YOUR_SERIAL --execute --lang ko
```

Omitting the command selects unlock. A dry-run performs no password input, device commands or result-file creation. `status` queries Discovery; `probe` queries INQUIRY and Discovery. Neither establishes user password security alone. `LockingEnabled=true` is not displayed as proof of a configured password. Lock state is the last observation.

Actual queries require an unused device. status/probe do not unmount automatically. The existing restricted announcement-partition unmount policy and authentication/configuration/Relink sequence for unlock are unchanged.

### Password operations

First review the plan by omitting `--execute`. Change and removal require an unlocked, unused device under the existing procedure.

```bash
python3 t7.py change-password --serial YOUR_SERIAL --json --lang en
sudo python3 t7.py change-password --serial YOUR_SERIAL --execute --save-results --lang en
sudo python3 t7.py set-password --serial YOUR_SERIAL --execute --save-results --lang en
sudo python3 t7.py remove-password --serial YOUR_SERIAL --execute --save-results --lang en
```

These are separate operation examples, not a sequence to run together. set-password requires disabled security and prompts for the new password twice. change-password prompts for the current password once and the new password twice. remove-password requests the current password. Experimental status and precondition checks remain in place.

## Testing unverified models

Test T7/T7 Touch one step at a time. Replace `YOUR_SERIAL` with the SSD serial from `list`. Unmount data partitions normally and verify backups first.

```bash
python3 t7.py list --lang en
python3 t7.py probe --serial YOUR_SERIAL --lang en
sudo python3 t7.py probe --serial YOUR_SERIAL --execute --json --save-results --lang en
python3 t7.py unlock --serial YOUR_SERIAL --allow-unverified-model --lang en
sudo python3 t7.py status --serial YOUR_SERIAL --allow-unverified-model --execute --lang en
sudo python3 t7.py unlock --serial YOUR_SERIAL --allow-unverified-model --execute --lang en
```

Do not run these commands as a batch. Review each result and stop on errors, unsupported responses or pending state. After unlock, check partition enumeration and read-only file access, then unmount normally, reconnect and verify locking. Password change, initial setup and removal are separate unverified operations even after unlock succeeds. Each also requires the flag. The serial is optional with exactly one candidate and required with multiple candidates. Existing recovery conditions still apply to `--verify-only`; the flag does not bypass failure records.

Redact identifiers and personal paths before reporting. Never share authentication packets or entire state/runs directories. See README for reporting details.

Automatic selection with exactly one candidate:

```bash
python3 t7.py unlock --allow-unverified-model --lang en
sudo python3 t7.py unlock --allow-unverified-model --execute --lang en
```

## When a pending record remains

A `state/<device-key>/pending.json` file records an operation whose outcome still needs to be resolved. It does not necessarily mean the SSD is damaged or that its password changed. It can be written even without `--save-results`.

### 1. Stop and preserve evidence

Wait for the current process to finish. Do not start another settings change, delete or edit pending, or run a fresh copy from another directory to bypass it. Preserve the existing `state/` directory, terminal output and any saved result files locally. Do not upload those directories wholesale.

From the same script directory, locate pending records without modifying them:

```bash
sudo find ./state -type f -name pending.json -print
```

Review the failed operation's `action`, `error`, `error_stage`, `diagnostic.next_action`, `changes_may_have_occurred` and `commit_confirmed`. Where present, also check `recovery_required`, `session_may_be_open` and `transaction_may_be_open`. A missing field is not proof of a safe outcome.

The pending record's `kind`, `schema`, `stage` or `last_attempt`, and optional `run` path help identify the original operation. Read these locally; do not alter them. Some records have no saved run directory.

### 2. Identify the same SSD and query its current state

Finish disk work and unmount mounted partitions normally. Use `list` to confirm the SSD serial; a `/dev/sdX` name can change after reconnection. Explicit serial selection is recommended during recovery.

```bash
python3 t7.py list
sudo python3 t7.py status --serial YOUR_SERIAL --execute --json --save-results
```

For T7/T7 Touch, add `--allow-unverified-model` to `status` and the operation commands below. The flag does not relax pending checks. Do not use a guessed partition name or force/lazy unmount to bypass an in-use error.

`status` only queries Discovery. Success, an unlocked state, or `recovery: not_assessed` does **not** resolve pending or verify which password is active.

### 3. Choose the supported path

| Original outcome | Next step |
|---|---|
| Precisely validated wrong-password rejection, with cleanup confirmed and `correct_password_new_run` guidance | A new invocation with the correct password is allowed. Such a rejection normally leaves no pending record. If pending remains, do not assume this case applies. |
| Older `validated_auth_rejection` pending (schema 2) | `unlock` can assess and archive only the supported rejection evidence before a new attempt. It requires matching identity, the same OS boot, valid generation evidence and a fresh locked Discovery. The same connection is allowed only when the record explicitly proves same-connection retry eligibility; otherwise a new connection is required. Any failed check stops the operation. |
| `password_change` pending (schema 3) | The password-change verification path below can check one candidate password against both credential authorities. Commit confirmation is not a prerequisite for this path, but it does not repair inconsistent credentials. |
| Committed `remove-password` pending (`security_setup`, schema 5) | The removal verification path below requires `commit_confirmed=true` and `changes_may_have_occurred=true`; it verifies both default credentials and disabled security mode. |
| `set-password`, unconfirmed removal, uncertain unlock/transport failure, unsupported/legacy records, or any other case | No general automatic recovery is provided. Preserve the record and request review before sending more changes. |

A failed result-file save alone is not a reason to repeat a device operation. See [Errors, JSON and saving](#errors-json-and-saving).

### 4. Reconnect only for an eligible verification path

Both verification-only paths require the same SSD, the **same OS boot**, and a newer disk generation than recorded in pending. After the original process has ended and disk activity has stopped, unmount normally, safely disconnect the SSD, then reconnect it. Do not reboot as a substitute for reconnecting: a changed boot ID is rejected.

Run `list` again and unmount any automatically mounted announcement or data partition. Reconnection alone does not clear pending and does not prove rollback. If the record's operation is unsupported or uncertain, request review instead of treating reconnection as permission to retry.

### 5. Verify the previous operation without repeating its changes

Choose only the command matching the original pending operation. These are alternatives, not a sequence to run together. Review the dry-run first; it does not prove that the pending record will pass all execution checks.

For a password change:

```bash
python3 t7.py change-password --verify-only --serial YOUR_SERIAL --json
sudo python3 t7.py change-password --verify-only --serial YOUR_SERIAL --execute --json --save-results
```

At the hidden prompt, enter the password you expect to be active. If commit was confirmed, this should be the newly selected password. If the outcome is uncertain, do not cycle through guesses. Verification failure leaves pending for review.

For a committed password removal:

```bash
python3 t7.py remove-password --verify-only --serial YOUR_SERIAL --json
sudo python3 t7.py remove-password --verify-only --serial YOUR_SERIAL --execute --json --save-results
```

These paths open authentication/query sessions, but do not resend Set, commit or Relink commands. They archive the original pending record before verification. Only successful verification saves the required evidence and clears pending automatically.

### 6. Check the result before continuing

For password change, look for `complete=true`, `outcome=password_verified` and `both_credentials_verified=true`. For removal, look for `complete=true`, `outcome=password_removal_verified`, `both_credentials_verified=true` and `password_security=disabled`. Preserve the reported `pending_archive` locally.

If verification is refused, interrupted or fails, stop. Errors such as `unsupported_pending_for_verification`, `pending_device_mismatch`, `verification_requires_reconnection_same_boot` or `pending_recovery_blocked:...` are not instructions to delete pending.

Report the model, connection type, original action, error code/stage and sanitized diagnostic fields. Exclude passwords, credentials, authentication packets, actual serials and personal paths. There is no generic force-clear command or guaranteed firmware rollback.

## Errors, JSON and saving

Summary output shows the failure stage, cause, possible settings changes in this run, and next action. JSON retains existing fields and includes `diagnostic`:

| Field | Meaning |
|---|---|
| `failure_stage`, `cause` | Failure location and original error code |
| `changes_this_run` | `none`, `possible` or `unknown` |
| `prior_changes_possible` | Prior-operation changes inherited by verification-only execution |
| `recovery` | `required`, `not_assessed`, `not_required` or `unknown` |
| `next_action`, `next_action_message` | Stable next-action code and translated explanation |

`not_assessed` on status/probe/list or dry-run does not mean there is no prior pending record. A precisely validated authentication rejection allows a new run with the correct password. Uncertain session or mutation results direct the user to review recovery requirements. No automatic retransmission occurs.

`language` identifies the output language. Keys, `error`, `outcome`, `next_action`, command names and other machine codes are not translated. `plan`, `error_stage`, `failure_stage` and `next_action_message` are display text and must not drive automation. Raw device messages, paths and identifiers are preserved. Language selection does not rewrite the safety journal.

`--save-results` is independent of mandatory safety state. Pending records may be written even without optional result saving. Existing `changes_may_have_occurred` and `commit_confirmed` fields on a verification-only result may refer to the earlier operation; distinguish them from `diagnostic.changes_this_run`.

If only result saving fails, the device outcome is preserved, `result_save_error` is reported separately, and the process exits with failure. Preserve console output and resolve the storage issue. The file may be stale; do not repeat SSD mutations solely because report saving failed.

## Verification scope

Offline tests use synthetic responses and mock hosts. They do not establish hardware compatibility or fault recovery. See README.md for the supported scope.

A precisely rejected unlock reports `recovery: not_required` only when pending cleanup, same-connection retry eligibility, and no open session/transaction or settings changes are confirmed. Uncertainty takes precedence; status remains `not_assessed`.

