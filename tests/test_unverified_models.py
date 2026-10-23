"""Explicit model opt-in without relaxing transport or host safety checks."""
from t7manager import device as device_api
from t7manager import paths
from t7manager import records
from t7manager import safety
from t7manager import transport
from t7manager.cli import main as cli
from t7manager.operations import security as security_ops
from t7manager.operations import unlock as unlock_ops
import os
import resource
import shutil
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


from test_single_native import INFO, FakeHost


class Tests(unittest.TestCase):
    def invoke(self, model, args, busy=False):
        info = {**INFO, 'model': model}
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(paths, 'BASE', Path(tmp)), \
             patch.object(device_api, 'list_devices', return_value=[info]), \
             patch.object(safety, 'local_output'), \
             patch.object(safety, 'usage_snapshot', return_value={
                 'idle': not busy, 'mounts': [], 'holders': [], 'swaps': [], 'inflight': 0}), \
             contextlib.redirect_stdout(output):
            code = cli.main([*args, '--json'])
        return code, json.loads(output.getvalue())

    def test_operations_require_opt_in(self):
        for model in ('PSSD T7', 'PSSD T7 Touch'):
            for action in cli.ACTION_PLANS:
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
            for action in cli.ACTION_PLANS:
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
            with patch.object(device_api, 'list_devices', return_value=candidates), \
                 patch.object(safety, 'local_output'), \
                 patch.object(unlock_ops, 'execute_unlock') as execute, \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(cli.main(['unlock', '--allow-unverified-model', '--execute', '--json']), 1)
                report = json.loads(output.getvalue())
                self.assertEqual(report['error'], error)
                self.assertEqual(report['commands'], [])
                execute.assert_not_called()

    def test_unknown_model_not_allowed(self):
        code, report = self.invoke('PSSD T9', ['--serial', 'TEST', '--allow-unverified-model'])
        self.assertEqual(code, 1)
        self.assertEqual(report['error'], 'unsupported_security_profile')
        self.assertFalse(transport.operation_model_allowed('PSSD T9', transport.UnverifiedModelHost()))
        self.assertFalse(transport.operation_model_allowed('PSSD T7', transport.Host()))

    def test_busy_device_still_blocked(self):
        code, report = self.invoke('PSSD T7', ['status', '--serial', 'TEST', '--allow-unverified-model'], busy=True)
        self.assertEqual(code, 1)
        self.assertEqual(report['error'], 'device_in_use_unmount_or_stop_disk_work_first')

    def test_host_scope_not_global_and_relink_uses_family(self):
        with patch.object(device_api, 'identity', return_value=INFO) as identity:
            transport.UnverifiedModelHost().identify('/dev/sdz')
            identity.assert_called_once_with('/dev/sdz', family=True)
        with patch.object(device_api, 'wait_reenumeration') as wait, patch.object(device_api, 'find_device') as find:
            transport.UnverifiedModelHost().wait(INFO, '1', 'TEST')
            wait.call_args.kwargs['finder']('TEST')
            find.assert_called_once_with('TEST', family=True)
        self.assertFalse(device_api.is_supported_model('PSSD T7'))

    def test_unverified_unlock_keeps_response_validation(self):
        info = {**INFO, 'model': 'PSSD T7'}
        for bad in (None, 3):
            host = FakeHost(bad=bad)
            with tempfile.TemporaryDirectory() as tmp, \
                 patch('test_single_native.INFO', info), \
                 patch('test_single_native.NEW', {**info, 'device': '/dev/sdy', 'sysfs': 'new'}):
                state = Path(tmp) / 'state'
                state.mkdir()
                result = unlock_ops.execute_unlock(info, 'TEST', 'unlock', None, state, host)
                self.assertEqual(result['complete'], bad is None, result)
                if bad is not None:
                    self.assertFalse((state / 'pending.json').exists())
                    self.assertTrue(list((state / 'logs').glob('*.json')))
                    self.assertFalse(result['relink_attempted'])

    def test_security_profile_gate_uses_explicit_host(self):
        for model in ('PSSD T7', 'PSSD T7 Touch'):
            self.assertTrue(transport.operation_model_allowed(model, transport.UnverifiedModelHost()))
            self.assertFalse(transport.operation_model_allowed(model, transport.Host()))
        self.assertTrue(transport.operation_model_allowed('PSSD T7 Shield', transport.Host()))

    def test_cli_execute_passes_scoped_host(self):
        info = {**INFO, 'model': 'PSSD T7 Touch'}
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(paths, 'BASE', Path(tmp)), \
             patch.object(device_api, 'list_devices', return_value=[info]), \
             patch.object(safety, 'local_output'), \
             patch.object(safety, 'usage_snapshot', return_value={'idle': True}), \
             patch.object(os, 'geteuid', return_value=0), \
             patch.object(shutil, 'which', return_value='/mock/sg_raw'), \
             patch.object(resource, 'setrlimit'), \
             patch.object(records, 'run_lock', return_value=contextlib.nullcontext()), \
             patch.object(unlock_ops, 'execute_unlock', return_value={'complete': True, 'commands': []}) as execute, \
             contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(['status', '--allow-unverified-model', '--execute', '--json'])
            self.assertEqual(code, 0)
            self.assertIsInstance(execute.call_args.kwargs['host'], transport.UnverifiedModelHost)
            self.assertEqual(execute.call_args.args[1], 'TEST')
