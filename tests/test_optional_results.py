from t7manager import device as device_api
from t7manager import paths
from t7manager import records
from t7manager import safety
from t7manager.cli import main as cli
from t7manager.cli import output
from t7manager.operations import probe as probe_ops
from t7manager.operations import unlock as unlock_ops
import os
import shutil
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_single_native import FakeHost, INFO, SECRET
from test_single_compatibility import Host as ProbeHost, INFO as PROBE_INFO

class Tests(unittest.TestCase):
    def test_packaged_cli_places_optional_results_in_var_opt(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_root = Path(tmp) / 'var-opt'
            seen = {}
            def execute(info, serial, action, out, state):
                seen.update(out=out, state=state)
                return {'complete': True, 'action': action, 'commands': [], 'outcome': 'locked'}
            stdout = io.StringIO()
            with patch.object(paths, 'BASE', paths.PACKAGE_ROOT), \
                 patch.object(paths, 'PACKAGE_DATA_ROOT', data_root), \
                 patch.object(device_api, 'list_devices', return_value=[INFO]), \
                 patch.object(safety, 'local_output'), \
                 patch.object(safety, 'usage_snapshot', return_value={'idle': True}), \
                 patch.object(os, 'geteuid', return_value=0), \
                 patch.object(shutil, 'which', return_value='/fake'), \
                 patch.object(unlock_ops, 'execute_unlock', side_effect=execute), \
                 contextlib.redirect_stdout(stdout):
                self.assertEqual(cli.diagnostic_cli('status', ['--execute', '--json', '--save-results']), 0)
            self.assertEqual(seen['out'].parent, data_root / 'runs')
            self.assertEqual(seen['state'].parent, data_root / 'state')
            self.assertEqual((data_root / 'runs').stat().st_mode & 0o777, 0o700)

    def test_no_result_unlock_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp)/'state';state.mkdir()
            result=unlock_ops.execute_unlock(INFO,'TEST','unlock',None,state,FakeHost())
            self.assertTrue(result['complete']);self.assertTrue(list((state/'logs').glob('*.json')))
            self.assertEqual(list(Path(tmp).iterdir()),[state])
    def test_probe_without_output(self):
        result=probe_ops.collect(PROBE_INFO,None,ProbeHost())
        self.assertTrue(result['complete'])
    def test_cli_no_result_directory_and_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);stdout=io.StringIO();stderr=io.StringIO()
            def execute(info,serial,action,out,state):
                self.assertIsNone(out)
                return {'complete':True,'action':action,'commands':[],'after':{'locked':False,'locking_enabled':True},'outcome':'unlocked'}
            with patch.object(paths,'BASE',root),patch.object(device_api,'list_devices',return_value=[INFO]),patch.object(safety,'local_output'),patch.object(safety,'usage_snapshot',return_value={'idle':True}),patch.object(os,'geteuid',return_value=0),patch.object(shutil,'which',return_value='/fake'),patch.object(unlock_ops,'execute_unlock',side_effect=execute),contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
                self.assertEqual(cli.main(['unlock','--execute','--json']),0)
            self.assertIsNone(json.loads(stdout.getvalue())['result_path']);self.assertEqual(stderr.getvalue(),'')
            self.assertFalse((root/'runs').exists());self.assertTrue((root/'state').exists())
    def test_human_unlock_uses_final_state(self):
        stdout=io.StringIO()
        with contextlib.redirect_stdout(stdout):
            output.display_diagnostic({'action':'unlock','complete':True,'before':{'locked':True,'locking_enabled':True},'after':{'locked':False,'locking_enabled':True}},False)
        self.assertIn('잠금 상태: 잠금 해제됨',stdout.getvalue())
        self.assertNotIn('잠금 상태: 잠김',stdout.getvalue())

    def test_unlock_final_checkpoint_failure_preserves_transport_error(self):
        original=records.save
        def save(path,value):
            if path.name=='result.json' and value.get('error'):
                raise OSError('simulated result disk full')
            return original(path,value)
        with tempfile.TemporaryDirectory() as tmp,patch.object(records,'save',side_effect=save):
            root=Path(tmp);result=unlock_ops.execute_unlock(INFO,'TEST','unlock',root/'report',root,FakeHost(fail=10))
            self.assertEqual(result['error'],'transport_failed_no_retry')
            self.assertEqual(result['result_save_error'],'result_checkpoint_failed')
            self.assertFalse((root/'pending.json').exists())
            self.assertTrue(list((root/'logs').glob('*.json')))

    def test_checkpoint_failures_preserve_outcomes_across_operations(self):
        from t7manager import errors
        from t7manager.operations import password, security
        from test_password_change import ChangeHost
        from test_security_setup import SetupHost
        from test_default_credential_probe import ProbeHost as CredentialHost
        cases = {
            'unlock': lambda state, out: unlock_ops.execute_unlock(INFO, 'TEST', 'unlock', out, state, FakeHost()),
            'status': lambda state, out: unlock_ops.execute_unlock(INFO, 'TEST', 'status', out, state, FakeHost()),
            'change-password': lambda state, out: password.execute_password_change(INFO, 'TEST', out, state, ChangeHost()),
            'set-password': lambda state, out: security.execute_security_setup('set-password', INFO, 'TEST', out, state, SetupHost('set-password')),
            'remove-password': lambda state, out: security.execute_security_setup('remove-password', INFO, 'TEST', out, state, SetupHost('remove-password')),
            'probe-default-credential': lambda state, out: probe_ops.probe_default_credential(INFO, 'TEST', out, state, CredentialHost()),
            'probe': lambda state, out: probe_ops.collect(PROBE_INFO, out, ProbeHost(), state),
        }
        original = records.save
        for name, run in cases.items():
            for destination in ('log', 'result'):
                for exception in (OSError, errors.Stop):
                    with self.subTest(action=name, destination=destination, exception=exception), tempfile.TemporaryDirectory() as tmp:
                        def fail_final(path, value):
                            is_target = path.parent.name == 'logs' if destination == 'log' else path.name == 'result.json'
                            if is_target and value.get('complete'):
                                raise exception('unsafe_local_record')
                            return original(path, value)
                        root = Path(tmp)
                        with patch.object(records, 'save', side_effect=fail_final):
                            result = run(root / 'state', root / 'out')
                        self.assertTrue(result['complete'], result)
                        self.assertTrue(result['commands'])
                        self.assertEqual(result['result_save_error'], 'result_checkpoint_failed')
                        if name in ('change-password', 'set-password', 'remove-password'):
                            self.assertTrue(result['commit_confirmed'])

    def test_log_failure_before_first_transfer_stops_device_commands(self):
        from t7manager import errors
        for exception in (OSError, errors.Stop):
            with self.subTest(exception=exception), tempfile.TemporaryDirectory() as tmp:
                host = FakeHost()
                with patch.object(records, 'save', side_effect=exception('unsafe_local_record')):
                    result = unlock_ops.execute_unlock(INFO, 'TEST', 'unlock', None, Path(tmp), host)
                self.assertFalse(result['complete'])
                self.assertEqual(host.calls, [])
                self.assertFalse(result['changes_may_have_occurred'])
                self.assertIn('result_save_error', result)

    def test_probe_mandatory_log_keeps_parsed_diagnostics(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = probe_ops.collect(PROBE_INFO, None, ProbeHost(), Path(tmp))
            saved = json.loads(Path(result['log_path']).read_text())
            self.assertTrue(result['complete'], result)
            for key in ('discovery', 'inquiry', 'features', 'classification', 'unlock_compatibility_proven'):
                self.assertEqual(saved[key], result[key])
            self.assertNotIn('stderr', json.dumps(saved))
            from gui.details import summary
            text = summary('probe', saved)
            self.assertIn('Last observed lock state:', text)
            self.assertIn(saved['classification'], text)

    def test_cli_preserves_completed_change_when_final_save_is_rejected(self):
        from t7manager import errors
        from test_password_change import ChangeHost
        original = records.save
        def fail_final(path, value):
            if path.name == 'result.json' and value.get('complete'):
                raise errors.Stop('unsafe_local_record')
            return original(path, value)
        with tempfile.TemporaryDirectory() as tmp:
            stdout = io.StringIO()
            with patch.object(paths, 'BASE', Path(tmp)), \
                 patch.object(device_api, 'list_devices', return_value=[INFO]), \
                 patch.object(safety, 'local_output'), \
                 patch.object(safety, 'usage_snapshot', return_value={'idle': True}), \
                 patch.object(os, 'geteuid', return_value=0), \
                 patch.object(shutil, 'which', return_value='/fake'), \
                 patch.object(records, 'save', side_effect=fail_final), \
                 contextlib.redirect_stdout(stdout):
                code = cli.diagnostic_cli('change-password', ['--execute', '--json', '--save-results'],
                                          host_adapter=lambda _: ChangeHost())
            result = json.loads(stdout.getvalue())
            self.assertEqual(code, 1)  # Delivery failed; do not hide that in the exit code.
            self.assertTrue(result['complete'])
            self.assertTrue(result['commit_confirmed'])
            self.assertTrue(result['new_password_verified'])
            self.assertEqual(len(result['commands']), 19)
            self.assertIn('result_save_error', result)
