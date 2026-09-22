"""Presentation contracts, with all device operations mocked out."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import t7 as app
from test_single_native import INFO

class Tests(unittest.TestCase):
    def invoke(self,args):
        stream=io.StringIO()
        with patch.object(app,'list_devices',return_value=[INFO]),patch.object(app,'local_output'),patch.object(app,'usage_snapshot',return_value={'idle':True}),contextlib.redirect_stdout(stream):
            code=app.main([*args, "--lang", "ko"])
        return code,stream.getvalue()

    def test_every_action_dry_run_common_json_no_writes(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(app,'BASE',Path(tmp)),patch.object(app,'execute_unlock') as unlock,patch.object(app,'collect') as collect,patch.object(app,'execute_password_change') as change,patch.object(app,'execute_security_setup') as setup,patch.object(app,'probe_default_credential') as default:
            for action in app.ACTION_PLANS:
                code,text=self.invoke([action,'--json'])
                report=json.loads(text)
                self.assertEqual(code,0)
                self.assertTrue(report['dry_run'])
                self.assertEqual(report['commands'],[])
                self.assertIsNone(report['result_path'])
                self.assertFalse(report['save_results'])
                self.assertIn('plan',report)
                self.assertEqual(report['diagnostic']['changes_this_run'],'none')
                self.assertEqual(report['diagnostic']['recovery'],'not_assessed')
            for call in (unlock,collect,change,setup,default):call.assert_not_called()
            self.assertEqual(list(Path(tmp).iterdir()),[])

    def test_verify_only_plan_has_no_mutation_or_new_password_request(self):
        for action in ('change-password','remove-password'):
            code,text=self.invoke([action,'--verify-only','--json'])
            report=json.loads(text)
            self.assertTrue(report['verify_only'])
            self.assertIn('Set 없음',report['plan'])
            self.assertNotIn('새 암호 2회',report['plan'])

    def test_list_aliases_summary_json_and_invalid_options(self):
        for command in ('list','--list'):
            code,text=self.invoke([command])
            self.assertEqual(code,0)
            self.assertIn('PSSD T7 Shield',text)
            self.assertNotIn('"candidates"',text)
            code,text=self.invoke([command,'--json'])
            result=json.loads(text)
            self.assertTrue(result['complete'])
            self.assertFalse(result['device_commands_sent'])
            self.assertEqual(result['candidates'],[INFO])
            code,text=self.invoke([command,'--serial','missing','--json'])
            self.assertEqual(json.loads(text)['candidates'],[])
            for flag in ('--bad','--execute','--save-results'):
                code,text=self.invoke([command,flag,'--json'])
                self.assertEqual(code,1)
                self.assertEqual(json.loads(text)['error'],'invalid_arguments')

    def test_status_does_not_claim_password_security_or_global_recovery(self):
        report={'action':'status','complete':True,'before':{'locked':False,'locking_enabled':True},'outcome':'already_unlocked'}
        stream=io.StringIO()
        with contextlib.redirect_stdout(stream):app.display_diagnostic(report,False)
        self.assertIn('이 조회만으로 확정하지 않음',stream.getvalue())
        self.assertNotIn('비밀번호 보안: 활성',stream.getvalue())
        self.assertEqual(app.diagnostic_summary(report)['recovery'],'not_assessed')

    def test_uncertain_and_exact_rejection_have_different_next_actions(self):
        rejected={'action':'unlock','error':'authentication_rejected','error_stage':'auth-in','changes_may_have_occurred':False,'session_may_be_open':False}
        uncertain={**rejected,'error':'transport_timeout_no_retry','session_may_be_open':True}
        self.assertEqual(app.diagnostic_summary(rejected)['next_action'],'correct_password_new_run')
        self.assertEqual(app.diagnostic_summary(uncertain)['next_action'],'review_required')
        self.assertEqual(app.diagnostic_summary(uncertain)['changes_this_run'],'none')

    def test_verification_separates_prior_changes(self):
        report={'action':'remove-password','verify_only':True,'changes_may_have_occurred':True,'error':'unsupported_protocol_response','recovery_required':True}
        summary=app.diagnostic_summary(report)
        self.assertEqual(summary['changes_this_run'],'none')
        self.assertTrue(summary['prior_changes_possible'])
        self.assertEqual(summary['next_action'],'review_required')

    def test_unknown_engine_failure_is_not_reported_as_no_change(self):
        result={'action':'unlock','error':'local_error','error_stage':'장치 조회','commands':[]}
        self.assertEqual(app.diagnostic_summary(result)['changes_this_run'],'unknown')
        self.assertEqual(app.diagnostic_summary(result)['next_action'],'review_required')

    def test_successful_device_with_failed_save_says_not_to_repeat(self):
        result={'action':'set-password','complete':True,'changes_may_have_occurred':True,'result_save_error':'result_save_failed'}
        self.assertEqual(app.diagnostic_summary(result)['next_action'],'preserve_console_result')

    def test_human_error_has_stage_cause_changes_and_next_step(self):
        report={'action':'change-password','error':'authentication_rejected','error_stage':'auth-current-in','changes_may_have_occurred':False}
        stream=io.StringIO()
        with contextlib.redirect_stdout(stream):app.display_diagnostic(report,False)
        text=stream.getvalue()
        for expected in ('auth-current-in','authentication_rejected','이번 실행의 설정 변경: 없음','다음 조치:'):
            self.assertIn(expected,text)
