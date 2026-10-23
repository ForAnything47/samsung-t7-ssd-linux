"""Preference persistence and bounded authorization sessions without privilege/I/O."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import gui_worker as worker


class SessionTests(unittest.TestCase):
    def test_session_binds_serial_and_stops_on_unexpected_fields(self):
        calls = []
        requests = iter([{'start': True}, {'action': 'change-password'}, {'action': 'unlock', 'serial': 'OTHER'}])
        with patch.object(worker.sys, 'argv', ['worker', '--serial=TEST', '--session-seconds=60']), patch.object(worker.resource, 'setrlimit'), patch.object(worker, 'send'), patch.object(worker, 'run_operation', side_effect=lambda *args: calls.append(args) or 0), patch.object(worker, 'session_request', side_effect=lambda deadline: next(requests)):
            worker.main()
        self.assertEqual(calls, [('unlock', 'TEST', False), ('change-password', 'TEST', False)])

    def test_expiry_does_not_start_another_operation(self):
        with patch.object(worker.sys, 'argv', ['worker', '--serial=TEST', '--session-seconds=60']), patch.object(worker.resource, 'setrlimit'), patch.object(worker, 'send'), patch.object(worker.time, 'monotonic', side_effect=[100, 100, 161]), patch.object(worker, 'run_operation', return_value=0) as operation, patch.object(worker, 'session_request', return_value={'start': True}) as request:
            worker.main()
        operation.assert_called_once()
        request.assert_called_once()

    def test_operation_finishes_after_deadline_without_starting_another(self):
        clock = [100]
        calls = []
        events = []
        def delayed_operation(*args):
            calls.append(args)
            clock[0] = 161  # The operation completed after the 60-second lease.
            events.append({'event': 'result', 'report': {'action': args[0], 'complete': True}})
            return 0
        with patch.object(worker.sys, 'argv', ['worker', '--serial=TEST', '--session-seconds=60']), patch.object(worker.resource, 'setrlimit'), patch.object(worker, 'send', events.append), patch.object(worker.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(worker, 'run_operation', side_effect=delayed_operation), patch.object(worker, 'session_request', return_value={'start': True}) as request:
            self.assertEqual(worker.main(), 0)
        self.assertEqual(calls, [('unlock', 'TEST', False)])
        self.assertTrue(any(event.get('event') == 'result' for event in events))
        request.assert_called_once()  # Startup approval only; no next operation.

    def test_expired_partial_request_is_not_accepted(self):
        with patch.object(worker.time, 'monotonic', return_value=61):
            self.assertIsNone(worker.session_request(60))


try:
    from PySide6.QtCore import QSettings
    from gui import preferences
except ModuleNotFoundError:
    QSettings = None


@unittest.skipIf(QSettings is None, 'Optional Qt dependency absent')
class PreferenceTests(unittest.TestCase):
    def test_save_reload_and_invalid_values(self):
        with tempfile.TemporaryDirectory() as folder:
            path = str(Path(folder) / 'settings.ini')
            with patch.object(preferences, 'store', side_effect=lambda: QSettings(path, QSettings.Format.IniFormat)):
                self.assertEqual(preferences.load(), ('light', 0))
                self.assertTrue(preferences.save('dark', 300))
                self.assertEqual(preferences.load(), ('dark', 300))
                settings = preferences.store()
                settings.setValue('authorization_seconds', -1)
                settings.setValue('theme', 'unknown')
                settings.sync()
                self.assertEqual(preferences.load(), ('light', 0))


class WorkerPipeTests(unittest.TestCase):
    def test_reused_worker_requests_password_again_and_exits_on_eof(self):
        import json
        import subprocess
        import sys
        import select
        script = '''
import json, sys
import gui_worker as worker
identity = {'device': '/dev/fake', 'model': 'PSSD T7 Shield', 'serials': ['TEST']}
def operation(action, args, host_adapter):
    if action == 'change-password':
        assert host_adapter(object()).change_password_inputs() == (b'Old1234', b'New1234')
    print(json.dumps({'action': action, 'complete': True, 'identity': identity}))
    return 0
worker.cli.diagnostic_cli = operation
sys.argv = ['worker', '--action=status', '--serial=TEST', '--session-seconds=60']
raise SystemExit(worker.main())
'''
        process = subprocess.Popen([sys.executable, '-u', '-c', script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        def receive():
            data = bytearray()
            while not data.endswith(b'\n'):
                self.assertTrue(select.select([process.stdout], [], [], 5)[0], 'worker response timeout')
                value = process.stdout.read(1)
                self.assertTrue(value, 'unexpected worker EOF')
                data.extend(value)
            return json.loads(data)
        def send(value):
            process.stdin.write((json.dumps(value) + '\n').encode())
        try:
            self.assertEqual(receive()['event'], 'session_ready')
            send({'start': True})
            self.assertEqual(receive()['report']['action'], 'status')
            for _ in range(2):
                send({'action': 'change-password'})
                for prompt, password in (('current', 'Old1234'), ('new', 'New1234'), ('confirm', 'New1234')):
                    event = receive()
                    self.assertEqual(event, {'event': 'password_required', 'prompt': prompt})
                    send({'password': password})
                self.assertTrue(receive()['report']['complete'])
            process.stdin.close()
            self.assertEqual(process.wait(timeout=5), 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()


@unittest.skipIf(QSettings is None, 'Optional Qt dependency absent')
class SettingsDialogTests(unittest.TestCase):
    def test_apply_save_cancel_and_popup_style(self):
        from PySide6.QtWidgets import QApplication, QDialogButtonBox, QDialog, QStyle
        from gui.preferences import SettingsDialog
        app = QApplication.instance() or QApplication([])
        changes = []
        dialog = SettingsDialog(None, 'light', 0, lambda *values: changes.append(values))
        with patch.object(preferences, 'save', return_value=True) as save:
            dialog.show()
            dialog.theme.setCurrentIndex(1)
            dialog.buttons.button(QDialogButtonBox.StandardButton.Apply).click()
            self.assertTrue(dialog.isVisible())
            self.assertEqual(changes, [('dark', 0)])
            for combo in (dialog.theme, dialog.duration):
                self.assertEqual(combo.style().styleHint(QStyle.StyleHint.SH_ComboBox_Popup), 0)
                combo.showPopup()
                app.processEvents()
                popup = combo.view().window()
                popup_layout = popup.layout()
                self.assertIn('#202c3b', popup.styleSheet())
                self.assertEqual(popup_layout.contentsMargins().top(), 0)
                combo.hidePopup()
            dialog.theme.setCurrentIndex(0)
            dialog.reject()
            self.assertEqual(changes, [('dark', 0)])
            self.assertEqual(save.call_count, 1)
            dialog.show()
            dialog.buttons.button(QDialogButtonBox.StandardButton.Save).click()
            self.assertEqual(dialog.result(), QDialog.DialogCode.Accepted)
            self.assertFalse(dialog.isVisible())
        dialog.close()

    def test_failed_save_does_not_apply_or_close(self):
        from PySide6.QtWidgets import QApplication
        from gui.preferences import SettingsDialog
        app = QApplication.instance() or QApplication([])
        changes = []
        dialog = SettingsDialog(None, 'light', 0, lambda *values: changes.append(values))
        dialog.show()
        with patch.object(preferences, 'save', return_value=False):
            dialog.apply_selection(close=True)
        self.assertTrue(dialog.isVisible())
        self.assertFalse(changes)
        self.assertIn('Could not save', dialog.error.text())
        dialog.close()
