import contextlib
import io
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import t7 as app
from test_single_native import INFO

class Tests(unittest.TestCase):
    def invoke(self,args,usage=None,**kwargs):
        out=io.StringIO();err=io.StringIO()
        with patch.object(app,'list_devices',return_value=[INFO]),patch.object(app,'local_output'),patch.object(app,'usage_snapshot',return_value=usage or {'idle':True}),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            code=app.main([*args, "--lang", "ko"])
        return code,out.getvalue(),err.getvalue()
    def test_dry_json_single_object_no_device_io(self):
        with patch.object(app,'collect') as collect,patch.object(app,'execute_unlock') as unlock:
            for action in ('status','probe'):
                code,out,err=self.invoke([action,'--json'])
                self.assertEqual(code,0);self.assertFalse(err)
                self.assertTrue(json.loads(out)['dry_run'])
            collect.assert_not_called();unlock.assert_not_called()
    def test_busy_human_and_json(self):
        usage={'idle':False,'mounts':[{'device':'/dev/sdz1','mountpoint':'/media/data'}]}
        code,out,_=self.invoke(['status'],usage)
        self.assertEqual(code,1);self.assertIn('/media/data',out);self.assertIn('장치 사용 여부 검사',out)
        code,out,err=self.invoke(['probe','--execute','--json'],usage)
        self.assertEqual(code,1);self.assertFalse(err)
        self.assertEqual(json.loads(out)['commands'],[])
    def test_invalid_arguments_json(self):
        code,out,err=self.invoke(['status','--json','--bad'])
        self.assertEqual(code,1);self.assertEqual(json.loads(out)['error'],'invalid_arguments');self.assertFalse(err)
    def test_real_result_file_matches_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            def fake(info,serial,action,out,state):
                out.mkdir(parents=True)
                return {'complete':True,'commands':[{'name':'discovery-before','returncode':0}],
                        'before':{'locked':True,'locking_enabled':True,'comid':4100}}
            with patch.object(app,'BASE',Path(tmp)),patch.object(app.os,'geteuid',return_value=0),patch.object(app.shutil,'which',return_value='/fake'),patch.object(app,'execute_unlock',side_effect=fake):
                code,out,err=self.invoke(['status','--execute','--json','--save-results'])
                data=json.loads(out);self.assertEqual(code,0);self.assertFalse(err)
                self.assertEqual(json.loads(Path(data['result_path']).read_text()),data)
    def test_failure_stage_from_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            def fake(info,out):
                out.mkdir(parents=True)
                return {'complete':False,'error':'transport_failed_no_retry','commands':[{'name':'discovery','returncode':2}]}
            with patch.object(app,'BASE',Path(tmp)),patch.object(app.os,'geteuid',return_value=0),patch.object(app.shutil,'which',return_value='/fake'),patch.object(app,'collect',side_effect=fake):
                code,out,_=self.invoke(['probe','--execute','--save-results'])
                self.assertEqual(code,1);self.assertIn('discovery',out);self.assertIn('반환 코드: 2',out)
