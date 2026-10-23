"""Evidence-sensitive summaries; no Qt or device access required."""
import unittest
from gui.details import summary
from gui.explanations import failure_explanation


class ExplanationTests(unittest.TestCase):
    def test_set_existing_password_and_code_preserved(self):
        report = {'error': 'security_mode_precondition_failed', 'before': {'mbr_enabled': True}}
        text = summary('set-password', report)
        self.assertIn('already configured', text)
        self.assertIn('Change password', text)
        self.assertIn('Technical code: security_mode_precondition_failed', text)
        self.assertEqual(report['error'], 'security_mode_precondition_failed')

    def test_locking_enabled_alone_does_not_claim_password_exists(self):
        report = {'error': 'security_mode_precondition_failed', 'before': {'locking_enabled': True}}
        self.assertNotIn('already configured', summary('set-password', report))

    def test_locked_removal_and_disabled_removal_differ(self):
        for state, expected in (({'locked': True}, 'still locked'), ({'mbr_enabled': False}, 'may already be disabled')):
            self.assertIn(expected, summary('remove-password', {'error': 'security_mode_precondition_failed', 'before': state}))

    def test_recovery_overrides_input_retry_guidance(self):
        cause, step, _ = failure_explanation('change-password', {'error': 'password_entries_differ_no_auth_sent', 'changes_may_have_occurred': True})
        self.assertIn('do not automatically retry', step)
        self.assertIn('do not match', cause)

    def test_common_and_unknown_errors(self):
        for code, expected in (('authentication_rejected', 'rejected the current password'), ('password_input_cancelled_no_auth_sent', 'cancelled'), ('device_in_use_unmount_or_stop_disk_work_first', 'mounted'), ('future_error', 'could not be accepted')):
            self.assertIn(expected, summary('unlock', {'error': code}))

    def test_launch_diagnostics_are_visible_without_claiming_pending_exists(self):
        text = summary('unlock', {'error': 'authorization_or_launch_failed',
            'recovery_required': True, 'changes_may_have_occurred': True,
            'launch_diagnostic': {'exit_code': 127, 'exit_status': 'normal',
                'worker_started_observed': False, 'stdout_bytes': 0,
                'output_overflow': False, 'authorization_session_requested': False}})
        self.assertIn('exit code 127', text)
        self.assertIn('worker start observed False', text)
        self.assertIn('Review the operation log', text)

    def test_storage_warning_does_not_hide_success_or_original_failure(self):
        for complete in (True, False):
            report = {'complete': complete, 'result_save_error': 'result_checkpoint_failed'}
            if not complete:
                report.update(error='authentication_rejected', error_stage='auth-in')
            text = summary('unlock', report)
            self.assertIn('Result: Completed' if complete else 'Result: Not completed', text)
            self.assertIn('could not be saved', text)
            self.assertIn('Do not repeat a device change solely', text)
            if not complete:
                self.assertIn('authentication_rejected', text)
