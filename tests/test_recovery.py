import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess
import t7 as app
from test_single_native import FakeHost, INFO, NEW, LOCKED, SECRET

class RejectedHost(FakeHost):
    def __init__(self):super().__init__(reject=10)
    def run(self,cmd,**kwargs):
        result=super().run(cmd,**kwargs)
        if '--request=2048' in cmd and result.returncode==0:result.stdout=result.stdout.ljust(2048,b'\0')
        return result

class ReconnectedHost(FakeHost):
    def __init__(self,bad=False):super().__init__();self.recovery_calls=0;self.bad_recovery=bad
    def gen(self,info):return '3' if self.reenumerated else '2'
    def run(self,cmd,**kwargs):
        if not self.recovery_calls:
            self.recovery_calls+=1
            return subprocess.CompletedProcess(cmd,0,b'bad' if self.bad_recovery else LOCKED,b'')
        return super().run(cmd,**kwargs)
    def wait(self,*args):self.reenumerated=True;return NEW,'3'

class Tests(unittest.TestCase):
    def create(self,state):
        result=app.execute_unlock(INFO,'TEST','unlock',None,state,RejectedHost())
        self.assertEqual(result['error'],'authentication_rejected_no_retry')
        proof=json.loads((state/'pending.json').read_text())
        self.assertEqual(proof['kind'],'validated_auth_rejection')
        self.assertNotIn(SECRET,(state/'pending.json').read_bytes())
        return proof
    def test_reconnected_unlock_archives_then_succeeds(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp);proof=self.create(state);original=(state/'pending.json').read_bytes()
            host=ReconnectedHost();r=app.execute_unlock(INFO,'TEST','unlock',None,state,host)
            self.assertTrue(r['complete']);self.assertTrue(r['recovery']['applied'])
            self.assertEqual(Path(r['recovery']['archived_pending']).read_bytes(),original)
            self.assertFalse((state/'pending.json').exists());self.assertEqual(host.password_calls,1)
            self.assertEqual(host.recovery_calls,1);self.assertEqual(len(host.calls),28)
    def test_incomplete_changed_or_legacy_evidence_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp);proof=self.create(state)
            bads=[{}, {**proof,'kind':'uncertain'}, {**proof,'boot_id':'other'},
                  {**proof,'diskseq':'2'}, {**proof,'auth_status':2},
                  {**proof,'changes_started':True},{**proof,'anonymous_session_closed':False},
                  {**proof,'identity':{**INFO,'serials':['other']}},
                  {**proof,'commands':proof['commands'][:-1]}]
            for bad in bads:
                (state/'pending.json').write_text(json.dumps(bad));original=(state/'pending.json').read_bytes()
                host=ReconnectedHost();r=app.execute_unlock(INFO,'TEST','unlock',None,state,host)
                self.assertFalse(r['complete']);self.assertEqual(host.recovery_calls,0)
                self.assertEqual(host.password_calls,0);self.assertEqual((state/'pending.json').read_bytes(),original)
    def test_failed_fresh_discovery_keeps_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp);self.create(state);original=(state/'pending.json').read_bytes()
            host=ReconnectedHost(bad=True);r=app.execute_unlock(INFO,'TEST','unlock',None,state,host)
            self.assertFalse(r['complete']);self.assertEqual((state/'pending.json').read_bytes(),original)
            self.assertEqual(host.password_calls,0);self.assertEqual(host.calls,[])
    def test_normalized_shape_and_lengths_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp);proof=self.create(state)
            for name in ('auth-in','anonymous-end-in','discovery-before-auth'):
                bad=copy.deepcopy(proof)
                next(c for c in bad['commands'] if c['name']==name)['received']=1
                self.assertEqual(app.assess_pending(bad,INFO,'2',app.boot_identity()),'incomplete_auth_rejection_evidence')
    def test_same_generation_cannot_recover(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp);self.create(state);host=FakeHost()
            r=app.execute_unlock(INFO,'TEST','unlock',None,state,host)
            self.assertFalse(r['complete']);self.assertEqual(host.calls,[])
    def test_timeout_proof_is_never_eligible(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp);app.execute_unlock(INFO,'TEST','unlock',None,state,FakeHost(timeout=10))
            proof=json.loads((state/'pending.json').read_text())
            self.assertEqual(proof['kind'],'uncertain')
            self.assertEqual(app.assess_pending(proof,INFO,'2',app.boot_identity()),'legacy_or_uncertain_evidence')

    def test_dry_run_preserves_evidence_and_never_queries(self):
        import contextlib, io, hashlib
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);key=INFO['model']+'\0'+'\0'.join(sorted(set(INFO['serials'])))
            state=root/'state'/hashlib.sha256(key.encode()).hexdigest()[:24];state.mkdir(parents=True)
            self.create(state);original=(state/'pending.json').read_bytes();out=io.StringIO()
            with patch.object(app,'BASE',root),patch.object(app,'list_devices',return_value=[INFO]),patch.object(app,'generation',return_value='2'),patch.object(app,'local_output'),patch.object(app,'usage_snapshot',return_value={'idle':True}),patch.object(app,'execute_unlock') as run,contextlib.redirect_stdout(out):
                self.assertEqual(app.main(['--json']),0)
                run.assert_not_called()
            result=json.loads(out.getvalue())
            self.assertFalse(result['pending_recovery']['applied'])
            self.assertEqual(result['pending_recovery']['reason'],'fresh_locked_discovery_required')
            self.assertEqual((state/'pending.json').read_bytes(),original)
            self.assertFalse((state/'history').exists())
