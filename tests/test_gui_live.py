"""Read-only integration tests use a fake runner; no device commands or pkexec."""
import os
import unittest
from unittest.mock import patch
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
try:
    from PySide6.QtCore import QObject, Signal
    from PySide6.QtWidgets import QApplication
    from gui.backend import command
    from gui.live import LiveWindow
except ModuleNotFoundError:
    QApplication = None

if QApplication:
    class FakeRunner(QObject):
        completed = Signal(str, dict)
        password_required = Signal()
        def __init__(self):
            super().__init__()
            self.calls = []
        def end_session(self):
            pass
        def start(self, *args):
            self.calls.append(args)


@unittest.skipIf(QApplication is None, 'Optional Qt dependency absent')
class LiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        from unittest.mock import patch
        self.pref_load = patch('gui.preferences.load', return_value=('light', 0))
        self.pref_save = patch('gui.preferences.save', return_value=True)
        self.pref_load.start()
        self.pref_save.start()
        self.addCleanup(self.pref_load.stop)
        self.addCleanup(self.pref_save.stop)
        self.runner = FakeRunner()
        self.window = LiveWindow(self.runner, auto_refresh=False)

    def tearDown(self):
        self.window.live_busy = False
        self.window.close()

    def listed(self, model='PSSD T7 Shield'):
        self.window.refresh_devices()
        self.runner.completed.emit('list', {'complete': True, 'candidates': [
            {'model': model, 'device': '/dev/fake', 'serials': ['TEST-SERIAL']}]})

    def test_no_automatic_status_and_single_selection(self):
        self.listed()
        self.assertEqual(len(self.runner.calls), 1)
        self.assertTrue(self.window.unlock.isEnabled())
        self.window.start()
        self.window.start()
        self.assertEqual(len(self.runner.calls), 2)
        self.assertEqual(self.runner.calls[-1], ('status', 'TEST-SERIAL', False))
        self.assertFalse(self.window.devices.isEnabled())
        self.runner.completed.emit('status', {'complete': True, 'before': {'locked': True}})
        self.assertIn('Locked', self.window.heading.text())

    def test_details_window_does_not_dispatch_or_cancel_active_status(self):
        self.listed()
        self.window.start()
        calls = list(self.runner.calls)
        self.assertTrue(self.window.live_busy)
        self.window.open_details_window()
        self.app.processEvents()
        self.assertEqual(self.runner.calls, calls)
        details = self.window._details_window
        details.close()
        self.assertIsNone(self.window._details_window)
        self.assertTrue(self.window.live_busy)
        self.assertEqual(self.runner.calls, calls)
        self.runner.completed.emit('status', {'complete': True, 'before': {'locked': True}})
        self.assertIn('Locked', self.window.heading.text())

    def test_log_summary_failure_preserves_json_and_next_selection(self):
        from gui.log_viewer import LogViewer
        viewer = LogViewer(lambda day: None)
        self.addCleanup(viewer.close)
        bad = {'action': 'status', 'complete': True, 'before': 'invalid',
               'run_id': 'bad', 'started_at': '2026-10-25T12:00:00+00:00'}
        good = {'action': 'status', 'complete': True, 'before': {'locked': True},
                'run_id': 'good', 'started_at': '2026-10-25T12:01:00+00:00'}
        viewer.entries = [good, bad]
        viewer.show_entry(0)
        self.assertIn('Locked', viewer.human.toPlainText())
        viewer.show_entry(1)
        self.assertIn('Summary unavailable', viewer.human.toPlainText())
        self.assertNotIn('Locked', viewer.human.toPlainText())
        import json
        self.assertEqual(json.loads(viewer.raw.toPlainText()), bad)
        viewer.show_entry(0)
        self.assertIn('Locked', viewer.human.toPlainText())
        self.assertEqual(json.loads(viewer.raw.toPlainText()), good)

    def test_log_viewer_selects_date_and_reads_without_ssd_operation(self):
        self.listed()
        self.window.open_logs()
        self.assertIsNotNone(self.window.log_viewer)
        self.assertGreaterEqual(self.window.log_viewer.minimumWidth(), 640)
        self.assertGreaterEqual(self.window.log_viewer.days.minimumWidth(), 180)
        self.assertEqual(self.window.log_viewer.days.objectName(), 'logDate')
        self.assertIn('QComboBox#logDate::drop-down', self.window.log_viewer.styleSheet())
        self.assertEqual(self.runner.calls[-1], ('logs', 'TEST-SERIAL', False, None))
        self.runner.completed.emit('logs', {'action': 'logs', 'complete': True,
            'dates': ['2026-10-11'], 'day': '2026-10-11', 'device_commands_sent': False,
            'entries': [{'action': 'status', 'complete': True, 'run_id': 'a' * 32,
                         'started_at': '2026-10-11T00:00:00+00:00',
                         'updated_at': '2026-10-11T00:00:01+00:00'}]})
        self.assertEqual(self.window.log_viewer.runs.count(), 1)
        self.assertIn('Log ID:', self.window.log_viewer.human.toPlainText())
        self.assertEqual(self.runner.calls[-1], ('logs', 'TEST-SERIAL', False, None))
        self.window.log_viewer.days.addItem('2026-10-10')
        self.window.log_viewer.days.setCurrentText('2026-10-10')
        self.assertEqual(self.runner.calls[-1], ('logs', 'TEST-SERIAL', False, '2026-10-10'))
        self.window.log_viewer.close()

    def test_unverified_opt_in_and_error(self):
        self.listed('PSSD T7 Touch')
        self.assertFalse(self.window.unlock.isEnabled())
        self.window.unverified.setChecked(True)
        self.assertTrue(self.window.unlock.isEnabled())
        self.window.start()
        self.runner.completed.emit('status', {'complete': False, 'error_stage': 'host checks', 'error': 'device_in_use'})
        self.assertIn('could not be accepted', self.window.message.text())
        self.assertEqual(len(self.runner.calls), 2)

    def test_refresh_clears_stale_selection(self):
        self.listed()
        self.window.refresh_devices()
        self.runner.completed.emit('list', {'complete': True, 'candidates': []})
        self.assertIsNone(self.window.selected)
        self.assertFalse(self.window.unlock.isEnabled())

    def test_command_allowlist_and_no_shell_interpolation(self):
        with self.assertRaises(ValueError):
            command('erase', 'TEST')
        for action in ('pending-verify', 'pending-archive', 'pending-inspect'):
            with self.subTest(action=action), self.assertRaises(ValueError):
                command(action, 'TEST')
        with patch('gui.backend.shutil.which', return_value='/usr/bin/pkexec'):
            program, args = command('status', '--odd;serial', True)
        self.assertEqual(program, '/usr/bin/pkexec')
        self.assertTrue(any(arg.endswith('gui_worker.py') for arg in args))
        self.assertIn('--action=status', args)
        self.assertIn('--serial=--odd;serial', args)
        self.assertIn('--allow-unverified-model', args)
        self.assertNotIn('--save-results', args)
        self.assertNotIn('--execute', command('list')[1])

    def test_password_actions_use_worker_and_busy_controls(self):
        self.listed()
        for action in ('change-password', 'set-password', 'remove-password'):
            with patch('gui.backend.shutil.which', return_value='/usr/bin/pkexec'):
                program, args = command(action, 'TEST')
            self.assertIn('--action=' + action, args)
            self.assertTrue(any(arg.endswith('gui_worker.py') for arg in args))
        self.window.password_operation('change-password')
        self.assertEqual(self.runner.calls[-1], ('change-password', 'TEST-SERIAL', False))
        self.assertTrue(all(not b.isEnabled() for b in self.window.password_buttons.values()))
        self.runner.completed.emit('change-password', {'complete': False, 'error': 'authentication_rejected'})
        self.assertTrue(all(b.isEnabled() for b in self.window.password_buttons.values()))

    def test_remove_confirmation_cancel_sends_no_request(self):
        from PySide6.QtWidgets import QMessageBox
        self.listed()
        before = len(self.runner.calls)
        with patch('gui.live.QMessageBox.question', return_value=QMessageBox.StandardButton.No) as question:
            self.window.password_operation('remove-password')
        question.assert_called_once()
        self.assertEqual(len(self.runner.calls), before)

    def test_pipe_stays_open_between_password_prompts(self):
        from unittest.mock import Mock
        from gui.backend import CliRunner
        runner = CliRunner()
        runner.process = Mock()
        runner.busy = True
        for value in ('Old1234', 'New1234', 'New1234'):
            runner.awaiting_password = True
            runner.provide_password(value)
            runner.process.closeWriteChannel.assert_not_called()
        self.assertEqual(runner.process.write.call_count, 3)
        runner.awaiting_password = True
        runner.provide_password(None)
        runner.process.closeWriteChannel.assert_called_once()

    def test_runner_reuses_worker_then_revokes_without_device_io(self):
        import sys
        import time
        from pathlib import Path
        from gui.backend import CliRunner
        runner = CliRunner()
        runner.authorization_seconds = 60
        results = []
        runner.completed.connect(lambda action, result: results.append((action, result)))
        script = '''
import json, sys
import gui_worker as worker
identity = {'device': '/dev/fake', 'model': 'PSSD T7 Shield', 'serials': ['TEST']}
worker.cli.diagnostic_cli = lambda action, args, host_adapter: (print(json.dumps({'action': action, 'complete': True, 'identity': identity})) or 0)
sys.argv = ['worker', '--action=status', '--serial=TEST', '--session-seconds=60']
raise SystemExit(worker.main())
'''
        def wait_for(count):
            deadline = time.monotonic() + 5
            while len(results) < count and time.monotonic() < deadline:
                self.app.processEvents()
                time.sleep(.01)
            self.assertEqual(len(results), count)
        with patch('gui.backend.command', return_value=(sys.executable, ['-u', '-c', script])) as launch:
            try:
                runner.start('status', 'TEST')
                wait_for(1)
                runner.start('status', 'TEST')
                wait_for(2)
                self.assertEqual(launch.call_count, 1)
                runner.end_session()
                runner.start('status', 'TEST')
                wait_for(3)
                self.assertEqual(launch.call_count, 2)
            finally:
                runner.busy = False
                runner.end_session()
        self.assertTrue(all(result['complete'] for _, result in results))

    def test_authorization_cancel_and_lost_worker_result_are_distinct(self):
        from unittest.mock import Mock
        from PySide6.QtCore import QProcess
        from gui.backend import CliRunner
        for code, started, cancelled in ((126, False, True), (126, True, False), (127, False, True), (1, True, False)):
            runner = CliRunner()
            runner.busy = True
            runner.action = 'unlock'
            runner.session_mode = False
            runner.operation_dispatched = started
            runner.worker_started = started
            runner.output = bytearray()
            runner.overflow = False
            runner.final_report = None
            results = []
            runner.completed.connect(lambda action, result: results.append(result))
            with patch.object(runner, 'read_output'), patch.object(runner, 'read_error'):
                runner.finished(code, QProcess.ExitStatus.NormalExit)
            self.assertEqual(results[0]['launch_diagnostic']['exit_code'], code)
            self.assertEqual(results[0]['launch_diagnostic']['worker_started_observed'], started)
            if code == 127 and not started:
                self.assertEqual(results[0]['error'], 'authorization_or_launch_failed_before_start')
            self.assertEqual(results[0]['recovery_required'], not cancelled)
            self.assertEqual(results[0]['changes_may_have_occurred'], not cancelled)
            if cancelled and code == 126:
                self.assertEqual(results[0]['error'], 'authorization_cancelled')

    def test_active_operation_blocks_controls_and_window_close(self):
        from PySide6.QtGui import QCloseEvent
        self.listed()
        self.window.password_operation('change-password')
        self.assertFalse(self.window.settings_button.isEnabled())
        self.assertFalse(self.window.devices.isEnabled())
        event = QCloseEvent()
        self.window.closeEvent(event)
        self.assertFalse(event.isAccepted())
        self.runner.completed.emit('change-password', {'complete': False, 'error': 'password_input_cancelled_no_auth_sent'})
        self.assertTrue(self.window.settings_button.isEnabled())
        self.assertTrue(self.window.devices.isEnabled())

    def test_success_with_storage_warning_visible_in_main_window(self):
        self.listed()
        self.runner.completed.emit('unlock', {
            'action': 'unlock', 'complete': True, 'outcome': 'unlocked',
            'after': {'locked': False}, 'result_save_error': 'result_checkpoint_failed'})
        self.assertIn('Unlocked', self.window.heading.text())
        self.assertIn('Log/result saving failed', self.window.message.text())

    def test_log_viewer_warns_about_skipped_files_even_without_readable_logs(self):
        self.listed()
        self.window.open_logs()
        self.runner.completed.emit('logs', {
            'action': 'logs', 'complete': True, 'dates': [], 'day': None,
            'entries': [], 'skipped_count': 1,
            'warnings': [{'file': 'a' * 32 + '.json', 'reason': 'unreadable_or_invalid_json'}]})
        viewer = self.window.log_viewer
        self.assertIn('1 unreadable log(s) skipped', viewer.notice.text())
        self.assertIn('a' * 32, viewer.notice.toolTip())
        self.assertEqual(viewer.runs.count(), 0)
