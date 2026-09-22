import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import dataclasses
import t7 as app
from test_recovery import RejectedHost
from test_single_native import INFO

class Tests(unittest.TestCase):
    def test_values_are_not_disclosed(self):
        secret=b'private-password'
        response=app.Response(4100,0,0,'method',1,(secret,987654321,('control',240)))
        result=app.auth_failure_diagnostic(response,2048)
        encoded=json.dumps(result)
        self.assertNotIn(secret.decode(),encoded)
        self.assertNotIn('987654321',encoded)
        self.assertNotIn('240',encoded)
        self.assertEqual(result['token_shapes'],[{'kind':'bytes','length':16},{'kind':'integer'},{'kind':'control'}])
        self.assertEqual(result['recovery_exclusion_reasons'],['unsupported_return_tokens'])

    def test_nonempty_rejection_keeps_pending_uncertain_and_stops(self):
        original=app.parse_response
        def parse(*args,**kwargs):
            response=original(*args,**kwargs)
            if response.kind=='method' and response.status==1:
                return dataclasses.replace(response,values=(('control',240),('control',241),('control',249)))
            return response
        with tempfile.TemporaryDirectory() as tmp, patch.object(app,'parse_response',side_effect=parse):
            state=Path(tmp)
            result=app.execute_unlock(INFO,'TEST','unlock',None,state,RejectedHost())
            self.assertFalse(result['complete'])
            self.assertFalse(result['recovery_eligible_after_reconnection'])
            self.assertEqual(result['commands'][-1]['name'],'auth-in')
            self.assertFalse(result['changes_may_have_occurred'])
            self.assertEqual(json.loads((state/'pending.json').read_text())['kind'],'uncertain')
            self.assertEqual(result['auth_response_diagnostic']['recovery_exclusion_reasons'],['unsupported_return_tokens'])

    def test_supported_shape_has_no_exclusions(self):
        result=app.auth_failure_diagnostic(app.Response(4100,0,0,'method',1,()),2048)
        self.assertEqual(result['recovery_exclusion_reasons'],[])

    def test_sync_session_comparisons_do_not_accept_rejection(self):
        values=(('control',248),bytes.fromhex('00000000000000ff'),bytes.fromhex('000000000000ff03'),('control',240),1,0,('control',241),('control',249))
        response=app.Response(4100,0,0,'method',1,values)
        result=app.auth_failure_diagnostic(response,2048)
        self.assertEqual(result['recovery_exclusion_reasons'],[])
        self.assertTrue(app.supported_auth_rejection(response,2048))
        checks=result['sync_session_checks']
        self.assertTrue(checks['control_tokens_match'])
        self.assertTrue(checks['sync_session_uid_match'])
        self.assertTrue(checks['host_session_matches_request'])
        self.assertTrue(checks['device_session_zero'])
        self.assertFalse(checks['device_session_positive_uint32'])
        for index,bad,key in [(0,('control',241),'control_tokens_match'),(1,b'PASSWORD','invoking_uid_match'),(2,b'PASSWORD','sync_session_uid_match'),(4,True,'session_values_uint32'),(5,2**32,'session_values_uint32')]:
            altered=list(values);altered[index]=bad
            r=dataclasses.replace(response,values=tuple(altered))
            self.assertFalse(app.sync_session_checks(r)[key])
            self.assertFalse(app.supported_auth_rejection(r,2048))
        for count in range(8):
            self.assertFalse(app.sync_session_checks(dataclasses.replace(response,values=values[:count]))['eight_tokens'])

    def test_same_connection_retry_only_for_exact_sync_rejection(self):
        from test_recovery import ReconnectedHost
        original=app.parse_response
        values=(('control',248),bytes.fromhex('00000000000000ff'),bytes.fromhex('000000000000ff03'),('control',240),1,0,('control',241),('control',249))
        def parse(*args,**kwargs):
            r=original(*args,**kwargs)
            return dataclasses.replace(r,values=values) if r.kind=='method' and r.status==1 else r
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp)
            with patch.object(app,'parse_response',side_effect=parse):
                failed=app.execute_unlock(INFO,'TEST','unlock',None,state,RejectedHost())
            self.assertTrue(failed['retry_without_reconnection'])
            self.assertEqual(failed['error'],'authentication_rejected')
            self.assertTrue(failed['pending_cleared'])
            self.assertFalse(failed['session_may_be_open'])
            self.assertEqual(app.diagnostic_summary(failed)['recovery'], 'not_required')
            self.assertFalse((state/'pending.json').exists())
            self.assertFalse((state/'history').exists())
            from test_single_native import FakeHost
            result=app.execute_unlock(INFO,'TEST','unlock',None,state,FakeHost())
            self.assertTrue(result['complete'])
            self.assertNotIn('recovery',result)
            self.assertFalse((state/'pending.json').exists())

    def test_recovery_label_needs_complete_cleanup_evidence(self):
        report = {'action': 'unlock', 'error': 'authentication_rejected',
                  'pending_cleared': True, 'retry_without_reconnection': True,
                  'session_may_be_open': False, 'transaction_may_be_open': False,
                  'changes_may_have_occurred': False}
        for language in ('ko', 'en'):
            with patch.object(app, 'LANGUAGE', language):
                result = app.diagnostic_summary(report)
                self.assertEqual(result['recovery'], 'not_required')
                self.assertEqual(result['next_action'], 'correct_password_new_run')
        for key in ('pending_cleared', 'retry_without_reconnection',
                    'session_may_be_open', 'transaction_may_be_open',
                    'changes_may_have_occurred'):
            altered = dict(report)
            altered.pop(key)
            with self.subTest(missing=key):
                self.assertEqual(app.diagnostic_summary(altered)['recovery'], 'unknown')

    def test_uncertainty_overrides_rejection_cleanup_flags(self):
        report = {'action': 'unlock', 'error': 'authentication_rejected',
                  'pending_cleared': True, 'retry_without_reconnection': True,
                  'session_may_be_open': False, 'transaction_may_be_open': False,
                  'changes_may_have_occurred': False}
        for key in ('session_may_be_open', 'transaction_may_be_open', 'recovery_required'):
            with self.subTest(flag=key):
                result = app.diagnostic_summary({**report, key: True})
                self.assertEqual(result['recovery'], 'required')
                self.assertEqual(result['next_action'], 'review_required')
        self.assertEqual(app.diagnostic_summary({**report, 'action': 'status'})['recovery'], 'not_assessed')
