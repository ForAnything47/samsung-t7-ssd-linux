"""Presentation-only failure explanations. Never authorize retries or change state."""

# Each entry describes the cause and a practical next step. Raw codes stay in
# JSON and in the summary's technical detail for reporting/debugging.
MESSAGES = {
    'authorization_or_launch_failed_before_start': ('Administrator authorization was cancelled or denied, or the worker could not start. No device operation was dispatched.', 'You can start a new operation and authorize it. If authorization was accepted but this recurs, check the desktop authentication service.'),
    'authorization_or_launch_failed': ('Administrator authorization or worker startup failed. The available result does not distinguish cancellation, denial and a launch error.', 'Review the launch diagnostics below. This result does not confirm a device change.'),
    'authorization_cancelled': ('Administrator authorization was cancelled before the device worker started.', 'No device operation was started. You can authorize a new operation when ready.'),
    'authentication_rejected': ('The SSD rejected the current password.', 'Check the current SSD password, not your administrator password.'),
    'password_entries_differ_no_auth_sent': ('The two new passwords do not match.', 'Enter the same new password in both prompts. Authentication was not sent.'),
    'new_password_same_no_changes': ('The new password is the same as the current password you entered.', 'Choose a different new password.'),
    'unsupported_password_format_no_auth_sent': ('The password does not meet this tool’s supported format.', 'Use 4–16 ASCII characters without spaces. Authentication was not sent.'),
    'password_input_cancelled_no_auth_sent': ('Password entry was cancelled.', 'No authentication was sent. Start a new operation when ready.'),
    'device_in_use_unmount_or_stop_disk_work_first': ('The SSD is mounted or another operation is using it.', 'Finish file operations and safely unmount its partitions. Stop any other disk users.'),
    'matching_T7_not_found': ('The selected SSD could not be found.', 'Refresh the device list and check its connection and serial number.'),
    'specify_serial_from_list': ('More than one matching device is connected.', 'Select the intended SSD by its serial number.'),
    'sg_raw_required': ('The required sg_raw program is missing.', 'Install the sg3_utils package.'),
    'execute_requires_sudo': ('Administrator authorization is required.', 'Authorize the operation through the system dialog.'),
    'Authorization cancelled or failed': ('Administrator authorization was cancelled or denied.', 'Check the system authorization dialog and desktop authentication agent.'),
    'transport_timeout_no_retry': ('The SSD did not respond before the timeout.', 'Preserve the result and review the device connection. Do not repeat a change while its outcome is uncertain.'),
    'transport_failed_no_retry': ('Communication with the SSD failed.', 'Review the command result and connection before another operation.'),
    'device_identity_or_generation_changed': ('The device connection or identity changed during the operation.', 'Refresh the device list and review the previous result before proceeding.'),
    'unsafe_local_record': ('A safety record has unexpected ownership, permissions or a link.', 'Check the record location and permissions without deleting the evidence.'),
    'unsafe_local_directory': ('The record directory does not meet the required ownership or permission checks.', 'Review the storage location and its permissions.'),
    'local_error': ('A local file or host check failed.', 'Check paths, permissions and the technical details; the exact cause is not established.'),
    'interrupted': ('The operation was interrupted.', 'Check whether changes or an open session were recorded before starting again.'),
    'unsupported_security_profile': ('The SSD response does not match a supported security profile.', 'Preserve the result for compatibility review. Do not bypass the checks.'),
    'unexpected_lock_state': ('The SSD is not in the lock state required for this operation.', 'For a password change, unlock the SSD first and unmount its data partitions.'),
    'unexpected_datastore_security_mode': ('The SSD reported a different password-security mode than this operation requires.', 'Review its current mode before attempting another change.'),
}


def failure_explanation(action, report):
    diagnostic = report.get('diagnostic') or {}
    code = report.get('error') or diagnostic.get('cause') or 'unknown'
    cause, step = MESSAGES.get(code, (
        'The operation stopped because a check or device response could not be accepted.',
        'Review the failed stage and technical code below. Preserve the result for diagnosis.',
    ))
    if code == 'security_mode_precondition_failed':
        # Discovery flags are not proof of Samsung password mode. Say exactly
        # what the observed precondition means, without equating LockingEnabled
        # with a configured user password (it remains true after removal).
        state = report.get('before') or {}
        if action == 'set-password' and state.get('mbr_enabled') is True:
            cause = 'Password protection appears to be already configured on this SSD; Set password requires protection to be disabled.'
            step = 'To replace an existing password, unlock the SSD and choose Change password.'
        elif state.get('locked') is True:
            cause = 'The SSD is still locked; this operation requires it to be unlocked.'
            step = 'Unlock it with the current password, then unmount its data partitions.'
        elif action == 'remove-password' and state.get('mbr_enabled') is False:
            cause = 'The SSD is not reporting the protected mode required for removal; password protection may already be disabled.'
            step = 'Review the previous removal result. Discovery alone does not confirm password removal.'
        else:
            cause = 'The SSD security flags do not meet the conditions for this operation.'
            step = 'Set password requires disabled protection. Remove password requires enabled protection and an unlocked SSD.'
    if (report.get('recovery_required') is True
            or report.get('session_may_be_open') is True
            or report.get('transaction_may_be_open') is True
            or report.get('changes_may_have_occurred') is True
            or diagnostic.get('next_action') == 'review_required'
):
        step = 'The previous or current operation may be unresolved. Review the operation log and fresh status before another change; do not automatically retry.'
    return cause, step, code
