"""Operation logs are durable evidence, not cross-run authorization gates."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from t7manager import errors, paths, records
import gui_worker


class OperationLogTests(unittest.TestCase):
    def test_packaged_records_use_var_opt_without_migrating_source_records(self):
        info = {'device': '/dev/sdz', 'model': 'PSSD T7 Shield', 'serials': ['ONE']}
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source'
            source.mkdir()
            (source / 'state').mkdir()
            legacy = source / 'state' / 'pending.json'
            legacy.write_text('legacy evidence')
            packaged_data = Path(directory) / 'var-opt'
            with patch.object(paths, 'BASE', source):
                self.assertEqual(paths.data_root(), source)
                self.assertEqual(records.state_for_identity(info).parent, source / 'state')
            with patch.object(paths, 'BASE', paths.PACKAGE_ROOT), \
                 patch.object(paths, 'PACKAGE_DATA_ROOT', packaged_data):
                self.assertEqual(paths.data_root(), packaged_data)
                state = records.state_for_identity(info)
                self.assertEqual(state.parent, packaged_data / 'state')
                with records.run_lock(state):
                    report = {'action': 'status', 'complete': True, 'identity': info, 'commands': []}
                    records.operation_checkpoint(state, report)
                self.assertEqual(state.stat().st_mode & 0o777, 0o700)
                self.assertEqual(packaged_data.stat().st_mode & 0o777, 0o700)
                self.assertEqual(state.parent.stat().st_mode & 0o777, 0o700)
                self.assertEqual((state / 'logs').stat().st_mode & 0o777, 0o700)
                self.assertEqual(len(records.read_operation_logs(info)['entries']), 1)
            self.assertEqual(legacy.read_text(), 'legacy evidence')

    def test_packaged_runtime_rejects_public_existing_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            packaged_data = Path(directory) / 'var-opt'
            packaged_data.mkdir(mode=0o755)
            packaged_data.chmod(0o755)
            with patch.object(paths, 'BASE', paths.PACKAGE_ROOT), \
                 patch.object(paths, 'PACKAGE_DATA_ROOT', packaged_data):
                info = {'model': 'PSSD T7 Shield', 'serials': ['ONE']}
                with self.assertRaises(errors.Stop):
                    with records.run_lock(records.state_for_identity(info)):
                        self.fail('public runtime directory accepted')
            self.assertEqual(packaged_data.stat().st_mode & 0o777, 0o755)

    def test_checkpoint_omits_credentials_and_preserves_old_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state'
            state.mkdir(mode=0o700)
            old = state / 'pending.json'
            old.write_bytes(b'legacy evidence; untouched')
            report = {
                'action': 'change-password', 'complete': False,
                'identity': {'device': '/dev/sdz', 'model': 'PSSD T7 Shield', 'serials': ['TEST'], 'secret': 'SECRET'},
                'commands': [{'name': 'auth-current-out', 'phase': 'attempting', 'payload': 'SECRET'}],
                'password': 'SECRET', 'error_stage': 'auth-current-out',
                'session_may_be_open': True,
            }
            records.operation_checkpoint(state, report)
            log_path = Path(report['log_path'])
            saved = json.loads(log_path.read_text())
            self.assertEqual(saved['commands'], [{'name': 'auth-current-out', 'phase': 'attempting'}])
            self.assertEqual(saved['error_stage'], 'auth-current-out')
            self.assertNotIn('SECRET', log_path.read_text())
            self.assertEqual(old.read_bytes(), b'legacy evidence; untouched')
            self.assertEqual(log_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(log_path.parent.stat().st_mode & 0o777, 0o700)
            report.update(complete=True, outcome='password_changed')
            report['commands'][0].update(phase='returned', returncode=0)
            records.operation_checkpoint(state, report)
            self.assertEqual(json.loads(log_path.read_text())['outcome'], 'password_changed')
            self.assertEqual(len(list(log_path.parent.glob('*.json'))), 1)

    def test_lock_only_blocks_concurrent_process(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state'
            with records.run_lock(state):
                self.assertTrue((state / 'lock').exists())
            # The same lock file is reusable after the first process exits.
            with records.run_lock(state):
                self.assertTrue((state / 'lock').exists())

    def test_optional_result_failure_is_recorded_in_mandatory_log(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / 'state'
            out = root / 'run'
            out.mkdir(mode=0o700)
            (out / 'result.json').symlink_to(root / 'other')
            report = {'action': 'status', 'commands': [], 'complete': False}
            with self.assertRaises(Exception):
                records.operation_checkpoint(state, report, out)
            log = json.loads(Path(report['log_path']).read_text())
            self.assertEqual(log['result_save_error'], 'result_checkpoint_failed')

    def test_log_view_is_device_scoped_and_date_filtered(self):
        with tempfile.TemporaryDirectory() as directory:
            info = {'device': '/dev/sdz', 'model': 'PSSD T7 Shield', 'serials': ['ONE']}
            with patch('t7manager.paths.BASE', Path(directory)):
                state = records.state_for_identity(info)
                report = {'action': 'status', 'complete': True, 'identity': info,
                          'commands': [], 'started_at': '2026-10-10T12:00:00+00:00'}
                records.operation_checkpoint(state, report)
                listed = records.read_operation_logs(info)
                self.assertEqual(len(listed['dates']), 1)
                day = listed['dates'][0]
                self.assertEqual(listed['day'], day)
                self.assertEqual(len(listed['entries']), 1)
                selected = records.read_operation_logs(info, day)
                self.assertEqual(len(selected['entries']), 1)
                self.assertFalse(selected['device_commands_sent'])
                other = {'device': '/dev/sdy', 'model': 'PSSD T7 Shield', 'serials': ['TWO']}
                self.assertEqual(records.read_operation_logs(other)['dates'], [])

    def test_gui_log_request_is_host_only(self):
        info = {'device': '/dev/sdz', 'model': 'PSSD T7 Shield', 'serials': ['ONE']}
        with patch('gui_worker.device.list_devices', return_value=[info]), \
             patch('gui_worker.records.read_operation_logs', return_value={
                 'action': 'logs', 'complete': True, 'dates': [], 'entries': [],
                 'device_commands_sent': False}) as read, \
             patch('gui_worker.run_cli') as cli, patch('gui_worker.send'):
            self.assertEqual(gui_worker.run_operation('logs', 'ONE', False), 0)
            read.assert_called_once_with(info, None)
            cli.assert_not_called()

    def test_bad_record_does_not_hide_valid_logs_or_follow_links(self):
        with tempfile.TemporaryDirectory() as directory, patch('t7manager.paths.BASE', Path(directory)):
            info = {'device': '/dev/sdz', 'model': 'PSSD T7 Shield', 'serials': ['ONE']}
            state = records.state_for_identity(info)
            report = {'action': 'status', 'complete': True, 'identity': info, 'commands': []}
            records.operation_checkpoint(state, report)
            logdir = state / 'logs'
            bad = logdir / ('a' * 32 + '.json')
            bad.write_bytes(b'{broken')
            bad.chmod(0o600)
            target = Path(directory) / 'must-not-be-read'
            target.write_text('private target')
            link = logdir / ('b' * 32 + '.json')
            link.symlink_to(target)
            oversized = logdir / ('c' * 32 + '.json')
            oversized.write_bytes(b' ' * 65537)
            oversized.chmod(0o600)
            result = records.read_operation_logs(info)
            self.assertTrue(result['complete'])
            self.assertEqual(len(result['entries']), 1)
            self.assertEqual(result['skipped_count'], 3)
            self.assertEqual({w['file'] for w in result['warnings']}, {bad.name, link.name, oversized.name})
            self.assertEqual(bad.read_bytes(), b'{broken')
            self.assertTrue(link.is_symlink())
            self.assertEqual(target.read_text(), 'private target')
            # An explicitly selected date is equally resilient.
            self.assertEqual(len(records.read_operation_logs(info, result['day'])['entries']), 1)
