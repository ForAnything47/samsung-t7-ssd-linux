"""Explicit model opt-in without relaxing transport or host safety checks."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import t7 as app
from test_single_native import INFO, FakeHost


class Tests(unittest.TestCase):
    def invoke(self, model, args, busy=False):
        info = {**INFO, 'model': model}
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(app, 'BASE', Path(tmp)), \
             patch.object(app, 'list_devices', return_value=[info]), \
             patch.object(app, 'local_output'), \
             patch.object(app, 'usage_snapshot', return_value={
                 'idle': not busy, 'mounts': [], 'holders': [], 'swaps': [], 'inflight': 0}), \
             contextlib.redirect_stdout(output):
            code = app.main([*args, '--json'])
        return code, json.loads(output.getvalue())

    def test_operations_require_opt_in(self):
        for model in ('PSSD T7', 'PSSD T7 Touch'):
            for action in app.ACTION_PLANS:
                if action == 'probe':
                    continue
                code, report = self.invoke(model, [action, '--serial', 'TEST'])
                self.assertEqual(code, 1)
                self.assertEqual(report['commands'], [])
                code, report = self.invoke(model, [action, '--serial', 'TEST', '--allow-unverified-model'])
                self.assertEqual(code, 0, report)
                self.assertTrue(report['unverified_model'])
                self.assertIn('model_warning', report)
                self.assertEqual(report['commands'], [])

    def test_single_candidate_selected_without_serial(self):
        for model in ('PSSD T7', 'PSSD T7 Touch', 'PSSD T7 Shield'):
            for action in app.ACTION_PLANS:
                code, report = self.invoke(model, [action, '--allow-unverified-model'])
                self.assertEqual(code, 0, report)
                self.assertEqual(report['identity']['serials'], ['TEST'])
                self.assertEqual(report['commands'], [])

    def test_serial_mismatch_rejected(self):
        code, report = self.invoke('PSSD T7', ['--allow-unverified-model', '--serial', 'OTHER'])
        self.assertEqual(code, 1)
        self.assertEqual(report['error'], 'matching_T7_not_found')
        self.assertEqual(report['commands'], [])

    def test_missing_multiple_and_serialless_candidates_stop(self):
        other = {**INFO, 'model': 'PSSD T7', 'serials': ['OTHER']}
        for candidates, error in (([], 'matching_T7_not_found'),
                                  ([INFO, other], 'specify_serial_from_list'),
                                  ([{**other, 'serials': []}], 'device_serial_unavailable')):
            with patch.object(app, 'list_devices', return_value=candidates), \
                 patch.object(app, 'local_output'), \
                 patch.object(app, 'execute_unlock') as execute, \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(app.main(['--allow-unverified-model', '--execute', '--json']), 1)
                report = json.loads(output.getvalue())
                self.assertEqual(report['error'], error)
                self.assertEqual(report['commands'], [])
                execute.assert_not_called()

    def test_unknown_model_not_allowed(self):
        code, report = self.invoke('PSSD T9', ['--serial', 'TEST', '--allow-unverified-model'])
        self.assertEqual(code, 1)
        self.assertEqual(report['error'], 'unsupported_security_profile')
        self.assertFalse(app.operation_model_allowed('PSSD T9', app.UnverifiedModelHost()))
        self.assertFalse(app.operation_model_allowed('PSSD T7', app.Host()))

    def test_busy_device_still_blocked(self):
        code, report = self.invoke('PSSD T7', ['status', '--serial', 'TEST', '--allow-unverified-model'], busy=True)
        self.assertEqual(code, 1)
        self.assertEqual(report['error'], 'device_in_use_unmount_or_stop_disk_work_first')

    def test_host_scope_not_global_and_relink_uses_family(self):
        with patch.object(app, 'identity', return_value=INFO) as identity:
            app.UnverifiedModelHost().identify('/dev/sdz')
            identity.assert_called_once_with('/dev/sdz', family=True)
        with patch.object(app, 'wait_reenumeration') as wait, patch.object(app, 'find_device') as find:
            app.UnverifiedModelHost().wait(INFO, '1', 'TEST')
            wait.call_args.kwargs['finder']('TEST')
            find.assert_called_once_with('TEST', family=True)
        self.assertFalse(app.is_supported_model('PSSD T7'))

    def test_unverified_unlock_keeps_response_validation(self):
        info = {**INFO, 'model': 'PSSD T7'}
        for bad in (None, 3):
            host = FakeHost(bad=bad)
            with tempfile.TemporaryDirectory() as tmp, \
                 patch('test_single_native.INFO', info), \
                 patch('test_single_native.NEW', {**info, 'device': '/dev/sdy', 'sysfs': 'new'}):
                state = Path(tmp) / 'state'
                state.mkdir()
                result = app.execute_unlock(info, 'TEST', 'unlock', None, state, host)
                self.assertEqual(result['complete'], bad is None, result)
                if bad is not None:
                    self.assertTrue((state / 'pending.json').exists())
                    self.assertFalse(result['relink_attempted'])

    def test_security_profile_gate_uses_explicit_host(self):
        for model in ('PSSD T7', 'PSSD T7 Touch'):
            self.assertTrue(app.operation_model_allowed(model, app.UnverifiedModelHost()))
            self.assertFalse(app.operation_model_allowed(model, app.Host()))
        self.assertTrue(app.operation_model_allowed('PSSD T7 Shield', app.Host()))

    def test_cli_execute_passes_scoped_host(self):
        info = {**INFO, 'model': 'PSSD T7 Touch'}
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(app, 'BASE', Path(tmp)), \
             patch.object(app, 'list_devices', return_value=[info]), \
             patch.object(app, 'local_output'), \
             patch.object(app, 'usage_snapshot', return_value={'idle': True}), \
             patch.object(app.os, 'geteuid', return_value=0), \
             patch.object(app.shutil, 'which', return_value='/mock/sg_raw'), \
             patch.object(app.resource, 'setrlimit'), \
             patch.object(app, 'run_lock', return_value=contextlib.nullcontext()), \
             patch.object(app, 'execute_unlock', return_value={'complete': True, 'commands': []}) as execute, \
             contextlib.redirect_stdout(io.StringIO()):
            code = app.main(['status', '--allow-unverified-model', '--execute', '--json'])
            self.assertEqual(code, 0)
            self.assertIsInstance(execute.call_args.kwargs['host'], app.UnverifiedModelHost)
            self.assertEqual(execute.call_args.args[1], 'TEST')

    def test_security_setup_keeps_pending_blocker_with_opt_in(self):
        from test_security_setup import SetupHost
        info = {**INFO, 'model': 'PSSD T7 Touch'}
        host = SetupHost('set-password')
        host.allow_unverified_model = True
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            (state / 'pending.json').write_text('{}')
            result = app.execute_security_setup('set-password', info, 'TEST', None, state, host)
            self.assertEqual(result['error'], 'pending_requires_review_use_status_no_changes')
            self.assertEqual(host.calls, [])
