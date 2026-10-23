from t7manager import protocol
from t7manager.operations import probe as probe_ops
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_single_native import FakeHost,INFO,START,LOCKED

SECRET=b'SyntheticDefaultOnly9'
class ProbeHost(FakeHost):
    def __init__(self,stop=None):super().__init__();self.stop=stop
    def run(self,cmd,**kwargs):
        index=len(self.calls);self.calls.append((cmd,kwargs))
        if index==self.stop:raise subprocess.TimeoutExpired(cmd,45,output=SECRET,stderr=SECRET)
        raw=b''
        if index in (0,7):raw=LOCKED
        elif index==2:raw=START.ljust(2048,b'\0')
        elif index==4:raw=protocol.frame(b'\xf0\xf0\xf2\x03'+protocol.byte_atom(SECRET)+b'\xf3\xf1\xf1\xf9'+protocol.TAIL,4100,291,1).ljust(2048,b'\0')
        elif index==6:raw=protocol.frame(b'\xfa',4100,291,1).ljust(2048,b'\0')
        return subprocess.CompletedProcess(cmd,0,raw,b'')

class Tests(unittest.TestCase):
    def test_success_no_credential_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp);host=ProbeHost()
            result=probe_ops.probe_default_credential(INFO,'TEST',state/'report',state,host)
            self.assertTrue(result['complete'],result)
            self.assertFalse((state/'pending.json').exists())
            self.assertNotIn(SECRET.decode(),json.dumps(result))
            self.assertNotIn(SECRET,(state/'report/result.json').read_bytes())
            self.assertEqual([p.name for p in (state/'report').iterdir()],['result.json'])
    def test_timeout_each_transfer(self):
        for index in range(8):
            with self.subTest(index=index),tempfile.TemporaryDirectory() as tmp:
                state=Path(tmp);host=ProbeHost(index)
                result=probe_ops.probe_default_credential(INFO,'TEST',None,state,host)
                self.assertFalse(result['complete'])
                self.assertEqual(len(host.calls),index+1)
                self.assertNotIn(SECRET.decode(),json.dumps(result))
                self.assertFalse((state/'pending.json').exists())
                self.assertTrue(list((state/'logs').glob('*.json')))
    def test_wrong_column_not_accepted(self):
        response=protocol.Response(4100,291,1,'method',0,(('control',240),('control',240),('control',242),4,SECRET,('control',243),('control',241),('control',241),('control',249)))
        result=protocol.default_credential_structure(response)
        self.assertFalse(result['expected_column_structure'])
        self.assertNotIn(SECRET.decode(),json.dumps(result))
