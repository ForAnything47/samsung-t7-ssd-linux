"""Human-readable rendering of CLI results; never infer missing state."""

from .explanations import failure_explanation


def summary(action, report):
    def certainty(value):
        return 'Yes' if value is True else 'No' if value is False else 'Unknown'

    success = report.get('complete') is True
    lines = ['Result: ' + ('Completed' if success else 'Not completed')]
    if action == 'list':
        devices = report.get('candidates', [])
        lines.append(f'Devices found: {len(devices)}')
        for device in devices:
            lines.append(f"• {device.get('model', 'Unknown')} · {device.get('device', 'Unknown')}")
            lines.append('  Serial: ' + ', '.join(device.get('serials', [])))
        lines.append('Host-only listing; no SSD commands sent.')
    else:
        identity = report.get('identity_after', report.get('identity', {}))
        if identity:
            lines.append(f"Device: {identity.get('model', 'Unknown')} · {identity.get('device', 'Unknown')}")
        state = report.get('after') or report.get('discovery') or report.get('before', {})
        if state:
            locked = state.get('locked')
            lines.append('Last observed lock state: ' + ('Locked' if locked is True else 'Unlocked' if locked is False else 'Unknown'))
            if 'after' not in report and not success:
                lines.append('This observation predates the failure; current state is not confirmed.')
        if action == 'probe':
            if report.get('inquiry'):
                lines.append('Device revision: ' + str(report['inquiry'].get('revision', 'Unknown')))
            if report.get('classification'):
                lines.append('Profile comparison: ' + report['classification'])
                lines.append('Profile similarity does not prove unlock compatibility.')
        if report.get('outcome'):
            lines.append('Outcome: ' + report['outcome'].replace('_', ' '))
        if report.get('reenumeration_verified') is True:
            lines.append('Device reconnection verified.')
        for part in report.get('partitions', []):
            lines.append(f"Partition: {part.get('device', 'Unknown')} · {part.get('size_bytes', 'Unknown')} bytes")
    if not success:
        diagnostic = report.get('diagnostic', {})
        lines.append('Failed stage: ' + str(report.get('error_stage') or diagnostic.get('failure_stage') or 'Unknown'))
        cause, guidance, code = failure_explanation(action, report)
        lines.append('Cause: ' + cause)
        lines.append('Next step: ' + guidance)
        lines.append('Technical code: ' + str(code))
        launch = report.get('launch_diagnostic')
        if isinstance(launch, dict):
            lines.append('Launch diagnostics: exit code ' + str(launch.get('exit_code'))
                         + '; status ' + str(launch.get('exit_status'))
                         + '; worker start observed ' + str(launch.get('worker_started_observed'))
                         + '; operation dispatched ' + str(launch.get('operation_dispatched'))
                         + '; stdout bytes ' + str(launch.get('stdout_bytes'))
                         + '; output overflow ' + str(launch.get('output_overflow'))
                         + '; retained session requested ' + str(launch.get('authorization_session_requested')))
        if report.get('recovery_required') is True or report.get('session_may_be_open') is True or report.get('transaction_may_be_open') is True:
            lines.append('Review the operation log and fresh device status before repeating a change.')
    if report.get('result_save_error'):
        lines.append('Warning: Operation log or result file could not be saved; stored records may be incomplete.')
        lines.append('Preserve these displayed results and check the log directory. Do not repeat a device change solely because saving failed.')
        lines.append('Storage error: ' + str(report['result_save_error']))
    return '\n'.join(lines)
