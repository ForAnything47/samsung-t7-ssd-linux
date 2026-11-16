"""Offline regression contracts for shared presentation and transfer helpers."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
from t7manager import records, transport, errors
from t7manager.results import new_operation_result


class Contracts(unittest.TestCase):
    def test_transfer_records_before_error_and_never_retries(self):
        for failure, code in [(subprocess.TimeoutExpired('sg_raw',45), 'transport_timeout_no_retry'),
                              (subprocess.CompletedProcess([],1,b''), 'transport_failed_no_retry'),
                              (subprocess.CompletedProcess([],0,b'x'), 'unexpected_receive_length')]:
            with self.subTest(code=code):
                host=Mock(); host.run.side_effect = failure if isinstance(failure, Exception) else None
                host.run.return_value=failure
                entry={'phase':'attempting'}; snapshots=[]
                with self.assertRaisesRegex(errors.Stop,code):
                    transport.transfer_command(host,'/dev/fake',b'\xa2',entry,
                                               lambda: snapshots.append(copy.deepcopy(entry)), request=2)
                host.run.assert_called_once()
                self.assertEqual(snapshots[-1]['phase'],'timeout' if isinstance(failure,Exception) else 'returned')

    def test_unlock_short_response_policy_and_command_arguments(self):
        host=Mock();host.run.return_value=subprocess.CompletedProcess([],0,b'x')
        self.assertEqual(transport.transfer_command(host,'/dev/fake',b'\xa2',{},lambda:None,
                                                   request=2,exact_length=False),b'x')
        host.run.assert_called_once_with(['sg_raw','--readonly','--cmdset=1','--timeout=30',
                                         '--request=2','--outfile=-','/dev/fake','a2'],
                                        input=b'',capture_output=True,timeout=45,check=False)

    def test_initial_results_are_independent(self):
        a=new_operation_result('unlock',{});b=new_operation_result('unlock',{})
        a['commands'].append({})
        self.assertEqual(b['commands'],[])
        self.assertFalse(b['changes_may_have_occurred'])

    @unittest.skipUnless(hasattr(time,'tzset'),'requires POSIX timezone support')
    def test_overflow_timestamp_preserves_good_log_and_original(self):
        with tempfile.TemporaryDirectory() as tmp:
            info={'model':'PSSD T7 Shield','serials':['TEST']};state=Path(tmp)
            with patch.dict(os.environ,{'TZ':'Asia/Seoul'}):
                time.tzset()
                try:
                    with patch.object(records,'state_for_identity',return_value=state):
                        good={'action':'status','identity':info,'complete':True,'commands':[]}
                        records.operation_checkpoint(state,good)
                        bad=dict(json.loads(Path(good['log_path']).read_text()),run_id='a'*32,
                                 started_at='9999-12-31T23:59:59+00:00')
                        p=state/'logs'/('a'*32+'.json');p.write_text(json.dumps(bad));p.chmod(0o600)
                        original=p.read_bytes();result=records.read_operation_logs(info)
                        self.assertEqual(len(result['entries']),1)
                        self.assertEqual(result['warnings'][0]['reason'],'invalid_log_timestamp')
                        self.assertEqual(p.read_bytes(),original)
                finally:
                    pass
            time.tzset()
