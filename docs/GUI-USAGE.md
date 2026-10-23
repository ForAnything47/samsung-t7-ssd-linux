# GUI usage

The optional Qt Widgets interface uses the same validation and device operations as the CLI. From a source checkout, install `requirements-gui.txt` in a virtual environment and run `t7_gui.py` as a normal desktop user. A locally installed Arch package provides `t7-gui`. Do not launch the GUI with sudo; a polkit authentication agent authorizes individual device operations.

1. **Refresh devices** lists host-visible candidates without sending SSD commands. Select the intended model and serial. T7 and T7 Touch password operations need explicit unverified-model opt-in in the interface and are not hardware-validated.
2. **Refresh status** sends a Discovery query. The result is a last observation, and `LockingEnabled` alone does not establish password-security mode. Unmount any data partition normally before the query.
3. **Unlock device** requests the current SSD password only if locked. A locked announcement partition may be unmounted by the CLI; an unlocked data partition is never automatically unmounted. The GUI does not mount data after unlock.
4. **Change password** requires password security enabled, an unlocked, unused device, the current password, and the new password twice. **Set password** requires security disabled and asks for the new password twice. **Remove password** requires security enabled, an unlocked, unused device, confirmation, and the current password.
5. Wait for the result. Once a request has reached the SSD, closing a dialog or interrupting the process cannot guarantee cancellation. A failed or missing result is not proof that settings were unchanged.

The administrator password belongs to the system authentication dialog. The SSD password is requested separately in hidden input. The GUI sends it to the authorized worker through a private pipe, not command-line arguments, environment variables, clipboard or saved logs. Python and Qt cannot guarantee erasure of all in-memory copies.

**Operation details** shows a readable Summary or a JSON report. **Open window** opens a resizable, synchronized read-only view; copy and save export the selected text. **Operation logs** opens a separate resizable window for root-owned logs of the selected device, grouped by local date. Reading a log needs authorization but sends no SSD commands. Results and exports can contain serials and local paths; review them before sharing.

**Settings** stores Light/Dark theme and optional administrator session duration in the user's settings. Retention applies only to this app and the same selected SSD, ends on app exit or deadline, and never stores SSD passwords. Every password operation still requests its applicable SSD input.

For a hardware-free interface demonstration, run `.venv-gui/bin/python t7_gui.py --demo` and use only a dummy password. See [operation logs](OPERATION-LOGS.md) and [packaging](PACKAGING.md).
