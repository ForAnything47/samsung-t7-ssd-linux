"""Fault tests for journal persistence and result delivery; no device access."""
import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import t7 as app
from test_single_native import FakeHost, INFO
from test_password_change import ChangeHost
from test_security_setup import SetupHost
from test_default_credential_probe import ProbeHost


class Tests(unittest.TestCase):
    def execute(self, action, state, host):
        if action == 'unlock':
            return app.execute_unlock(INFO, 'TEST', action, None, state, host)
        if action == 'change-password':
            return app.execute_password_change(INFO, 'TEST', None, state, host)
        if action == 'probe-default-credential':
            return app.probe_default_credential(INFO, 'TEST', None, state, host)
        return app.execute_security_setup(action, INFO, 'TEST', None, state, host)

    def host(self, action):
        if action == 'unlock': return FakeHost()
        if action == 'change-password': return ChangeHost()
        if action == 'probe-default-credential': return ProbeHost()
        return SetupHost(action)

    def test_journal_failure_before_every_outbound_stops_transmission(self):
        original_save = app.save
        for action in ('unlock', 'change-password', 'set-password', 'remove-password', 'probe-default-credential'):
            with tempfile.TemporaryDirectory() as tmp:
                baseline = self.host(action)
                journal_positions = []
                def record_save(path, value):
                    if path.name == 'pending.json': journal_positions.append(len(baseline.calls))
                    return original_save(path, value)
                with patch.object(app, 'save', side_effect=record_save):
                    result = self.execute(action, Path(tmp), baseline)
                self.assertTrue(result['complete'], result)
            for ordinal, call_index in enumerate(journal_positions):
                for after_write in (False, True):
                    with self.subTest(action=action, ordinal=ordinal, after_write=after_write), tempfile.TemporaryDirectory() as tmp:
                        state = Path(tmp)
                        host = self.host(action)
                        seen = 0
                        def failing_save(path, value):
                            nonlocal seen
                            if path.name == 'pending.json':
                                selected = seen == ordinal
                                seen += 1
                                if selected:
                                    if after_write: original_save(path, value)
                                    raise OSError('synthetic storage failure with secret FakeOnly!9')
                            return original_save(path, value)
                        with patch.object(app, 'save', side_effect=failing_save):
                            result = self.execute(action, state, host)
                        self.assertFalse(result['complete'])
                        self.assertEqual(len(host.calls), call_index)
                        self.assertNotIn('FakeOnly!9', json.dumps(result))
                        if after_write or ordinal > 0:
                            self.assertTrue((state/'pending.json').exists())
                            json.loads((state/'pending.json').read_text())

    def test_unlock_interrupt_at_each_transfer_never_continues(self):
        class InterruptHost(FakeHost):
            def __init__(self, index):
                super().__init__(); self.index=index
            def run(self, cmd, **kwargs):
                reply = super().run(cmd, **kwargs)
                if len(self.calls)-1 == self.index: raise KeyboardInterrupt
                return reply
        for index in range(28):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as tmp:
                state=Path(tmp);host=InterruptHost(index)
                result=self.execute('unlock',state,host)
                self.assertFalse(result['complete'])
                self.assertEqual(len(host.calls),index+1)
                self.assertEqual((state/'pending.json').exists(),index>=2)

    def test_reenumeration_failure_keeps_pending(self):
        for kwargs in ({'waitfail':True},{'changed':27},{'busy':27}):
            with tempfile.TemporaryDirectory() as tmp:
                state=Path(tmp);host=FakeHost(**kwargs)
                result=self.execute('unlock',state,host)
                self.assertFalse(result['complete'])
                self.assertTrue((state/'pending.json').exists())
                self.assertEqual(sum(cmd[-6:]==['e8','00','00','00','00','00'] for cmd,_ in host.calls),1)

    def test_cli_save_failure_preserves_transport_error_and_success(self):
        for success in (False, True):
            for failure in (OSError, KeyboardInterrupt):
                with self.subTest(success=success,failure=failure),tempfile.TemporaryDirectory() as tmp:
                    root=Path(tmp)
                    def execute(info,serial,action,out,state):
                        out.mkdir(parents=True)
                        report={'complete':success,'commands':[{'name':'auth-in','returncode':0}],
                                'changes_may_have_occurred':True,'commit_confirmed':True,
                                'outcome':'unlocked' if success else 'uncertain'}
                        if not success:report.update(error='transport_timeout_no_retry',error_stage='auth-in')
                        return report
                    stream=io.StringIO()
                    with patch.object(app,'BASE',root),patch.object(app,'list_devices',return_value=[INFO]),patch.object(app,'local_output'),patch.object(app,'usage_snapshot',return_value={'idle':True}),patch.object(app.os,'geteuid',return_value=0),patch.object(app.shutil,'which',return_value='/fake'),patch.object(app,'execute_unlock',side_effect=execute),patch.object(app,'save',side_effect=failure('secret must not leak')),contextlib.redirect_stdout(stream):
                        code=app.main(['unlock','--execute','--json','--save-results'])
                    report=json.loads(stream.getvalue())
                    self.assertEqual(code,1)
                    self.assertEqual(report['complete'],success)
                    self.assertEqual(report['result_save_error'],'result_save_failed')
                    if not success:
                        self.assertEqual(report['error'],'transport_timeout_no_retry')
                        self.assertEqual(report['error_stage'],'auth-in')
                    self.assertNotIn('secret must not leak',stream.getvalue())

    def test_collector_checkpoint_failure_keeps_original_error(self):
        class FailedHost(FakeHost):
            def run(self, cmd, **kwargs):
                self.calls.append((cmd,kwargs))
                return subprocess.CompletedProcess(cmd,2,b'',b'')
        original=app.save
        def save(path,value):
            if value.get('error'):raise OSError('disk full')
            return original(path,value)
        with tempfile.TemporaryDirectory() as tmp,patch.object(app,'save',side_effect=save):
            result=app.collect(INFO,Path(tmp)/'out',FailedHost())
            self.assertEqual(result['error'],'transport_failed_no_retry')
            self.assertEqual(result['result_save_error'],'result_checkpoint_failed')
            self.assertEqual(len(result['commands']),1)

    def test_atomic_save_failure_before_replace_keeps_original(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'pending.json';path.write_bytes(b'{"original": true}\n')
            for target in ('fsync','replace'):
                with self.subTest(target=target):
                    manager=patch.object(app.os,'fsync',side_effect=OSError('full')) if target=='fsync' else patch.object(app.os,'replace',side_effect=OSError('full'))
                    with manager,self.assertRaises(OSError):app.save(path,{'new':True})
                    self.assertEqual(path.read_bytes(),b'{"original": true}\n')

    def test_run_lock_excludes_another_operation(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp)
            with app.run_lock(state):
                with self.assertRaises(app.Stop):
                    with app.run_lock(state):self.fail('second lock acquired')
            with app.run_lock(state):pass

    def test_password_change_verification_archives_exact_record(self):
        from test_single_native import UNLOCKED, START
        class VerifyHost(ChangeHost):
            def gen(self, info): return '2'
            def password(self): return b'NewTest9'
            def run(self, cmd, **kwargs):
                index=len(self.calls);self.calls.append((cmd,kwargs))
                if index in (0,9): raw=UNLOCKED
                elif index in (2,6): raw=START.ljust(2048,b'\0')
                elif index in (4,8): raw=app.frame(b'\xfa',4100,291,1).ljust(2048,b'\0')
                else: raw=b''
                return subprocess.CompletedProcess(cmd,0,raw,b'')
        for fail_evidence in (False,True):
            with tempfile.TemporaryDirectory() as tmp:
                state=Path(tmp)
                incident={'schema':3,'kind':'password_change','identity':INFO,'serial':'TEST',
                          'diskseq':'1','boot_id':app.boot_identity(),
                          'commit_confirmed':False,'changes_may_have_occurred':True}
                raw=json.dumps(incident,indent=3).encode()+b'\n\n'
                (state/'pending.json').write_bytes(raw)
                original=app.save
                def save(path,value):
                    if fail_evidence and path.name=='verification.json':raise OSError('full')
                    return original(path,value)
                host=VerifyHost()
                with patch.object(app,'save',side_effect=save):
                    result=app.execute_password_change(INFO,'TEST',None,state,host,verify_only=True)
                self.assertEqual(result['complete'],not fail_evidence)
                history=Path(result['pending_archive'])
                self.assertEqual((history/'pending-original.json').read_bytes(),raw)
                self.assertEqual((state/'pending.json').exists(),fail_evidence)
                self.assertEqual(len(host.calls),10)
                if fail_evidence:
                    current=json.loads((state/'pending.json').read_text())
                    self.assertEqual(current['verification_archive'],str(history))
                for _,kwargs in host.calls:
                    if kwargs['input']:
                        self.assertNotIn(bytes.fromhex('0000000600000017'),kwargs['input'][56:])

    def test_archive_fsync_failure_preserves_original_before_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp)
            incident={'schema':3,'kind':'password_change','identity':INFO,'diskseq':'1',
                      'boot_id':app.boot_identity()}
            raw=json.dumps(incident).encode();(state/'pending.json').write_bytes(raw)
            host=ChangeHost();host.gen=lambda info:'2'
            with patch.object(app.os,'fsync',side_effect=OSError('storage failure')):
                result=app.execute_password_change(INFO,'TEST',None,state,host,verify_only=True)
            self.assertFalse(result['complete'])
            self.assertEqual(host.calls,[])
            self.assertEqual((state/'pending.json').read_bytes(),raw)
