# CLI usage

From a source checkout, run `python3 t7.py`. A locally installed Arch package provides the equivalent `t7` command. Replace `YOUR_SERIAL` with the serial shown by `list`; omit `--serial` only when exactly one candidate is present.

```bash
python3 t7.py list
python3 t7.py unlock --serial YOUR_SERIAL
sudo python3 t7.py status --serial YOUR_SERIAL --execute
sudo python3 t7.py unlock --serial YOUR_SERIAL --execute
sudo python3 t7.py probe --serial YOUR_SERIAL --execute --json
```

`--execute` sends device commands. Without it, commands other than `list` are host-only dry-runs. `--json` changes stdout format. `--save-results` saves a more detailed result file; every executed operation also writes a separate minimal JSON log. `--lang en|ko` chooses messages and prompts.

With no command, `t7` or `python3 t7.py` shows an unlock dry-run. Use
`t7 unlock --execute` to unlock.

For an installed package, the corresponding examples are `t7 list`, `sudo t7 status --execute`, `sudo t7 unlock --execute`, and `sudo t7 change-password --execute`. The optional GUI starts with `t7-gui` as a normal user; see [GUI usage](GUI-USAGE.md).

Password management requires an unlocked and unmounted device in the appropriate security mode. Check the dry-run and status first, then run only the intended action:

```bash
python3 t7.py change-password --serial YOUR_SERIAL
sudo python3 t7.py change-password --serial YOUR_SERIAL --execute
python3 t7.py set-password --serial YOUR_SERIAL
sudo python3 t7.py set-password --serial YOUR_SERIAL --execute
python3 t7.py remove-password --serial YOUR_SERIAL
sudo python3 t7.py remove-password --serial YOUR_SERIAL --execute
```

For an unverified T7 or T7 Touch model, add `--allow-unverified-model` to the relevant command. The flag does not relax identity, usage or response checks. Fingerprint operations are unsupported.

The CLI stops on the first transport, parsing or validation error; it does not resend a failed configuration command. A last-observed lock state does not prove whether a prior password change committed. After an uncertain failure, inspect the [operation log](OPERATION-LOGS.md), query fresh status when safe, and verify credentials deliberately before any further change. Existing `pending.json` files from older versions are neither consumed nor deleted.

Passwords are entered through hidden prompts. Do not put them in shell arguments or issue reports. After unlocking, inspect partition enumeration and use read-only access to check important files. Unmount normally before disconnecting.
