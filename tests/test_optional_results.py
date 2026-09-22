import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import t7 as app
from test_single_native import FakeHost, INFO, SECRET
from test_single_compatibility import Host as ProbeHost, INFO as PROBE_INFO

class Tests(unittest.TestCase):
    def test_no_result_unlock_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp)/'state';state.mkdir()
            result=app.execute_unlock(INFO,'TEST','unlock',None,state,FakeHost())
            self.assertTrue(result['complete']);self.assertEqual(list(state.iterdir()),[])
            self.assertEqual(list(Path(tmp).iterdir()),[state])
    def test_no_result_failure_retains_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp);host=FakeHost(reject=10)
            result=app.execute_unlock(INFO,'TEST','unlock',None,state,host)
            self.assertFalse(result['complete'])
            marker=json.loads((state/'pending.json').read_text())
            self.assertIsNone(marker['run']);self.assertEqual(marker['last_attempt'],'auth-out')
            self.assertNotIn(SECRET,(state/'pending.json').read_bytes())
            next_host=FakeHost();app.execute_unlock(INFO,'TEST','unlock',None,state,next_host)
            self.assertEqual(next_host.calls,[])
    def test_probe_without_output(self):
        result=app.collect(PROBE_INFO,None,ProbeHost())
        self.assertTrue(result['complete'])
    def test_cli_no_result_directory_and_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);stdout=io.StringIO();stderr=io.StringIO()
            def execute(info,serial,action,out,state):
                self.assertIsNone(out)
                return {'complete':True,'action':action,'commands':[],'after':{'locked':False,'locking_enabled':True},'outcome':'unlocked'}
            with patch.object(app,'BASE',root),patch.object(app,'list_devices',return_value=[INFO]),patch.object(app,'local_output'),patch.object(app,'usage_snapshot',return_value={'idle':True}),patch.object(app.os,'geteuid',return_value=0),patch.object(app.shutil,'which',return_value='/fake'),patch.object(app,'execute_unlock',side_effect=execute),contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
                self.assertEqual(app.main(['--execute','--json']),0)
            self.assertIsNone(json.loads(stdout.getvalue())['result_path']);self.assertEqual(stderr.getvalue(),'')
            self.assertFalse((root/'runs').exists());self.assertTrue((root/'state').exists())
    def test_human_unlock_uses_final_state(self):
        stdout=io.StringIO()
        with contextlib.redirect_stdout(stdout):
            app.display_diagnostic({'action':'unlock','complete':True,'before':{'locked':True,'locking_enabled':True},'after':{'locked':False,'locking_enabled':True}},False)
        self.assertIn('잠금 상태: 잠금 해제됨',stdout.getvalue())
        self.assertNotIn('잠금 상태: 잠김',stdout.getvalue())

    def test_unlock_final_checkpoint_failure_preserves_transport_error(self):
        original=app.save
        def save(path,value):
            if path.name=='result.json' and value.get('error'):
                raise OSError('simulated result disk full')
            return original(path,value)
        with tempfile.TemporaryDirectory() as tmp,patch.object(app,'save',side_effect=save):
            root=Path(tmp);result=app.execute_unlock(INFO,'TEST','unlock',root/'report',root,FakeHost(fail=10))
            self.assertEqual(result['error'],'transport_failed_no_retry')
            self.assertEqual(result['result_save_error'],'result_checkpoint_failed')
            self.assertTrue((root/'pending.json').exists())
