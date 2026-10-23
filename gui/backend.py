"""Asynchronous CLI adapter with optional bounded, same-device worker reuse.

No shell or automatic retries. Unlock credentials use a private stdin pipe. pkexec
owns the administrator prompt; the GUI remains an ordinary-user process.
"""
import json
import shutil
import sys
import time
from pathlib import Path
from PySide6.QtCore import QObject, QProcess, Signal

CLI = Path(__file__).resolve().parents[1] / 't7.py'
LIMIT = 1024 * 1024
PASSWORD_ACTIONS = ('unlock', 'change-password', 'set-password', 'remove-password')
WORKER_ACTIONS = ('status', 'logs') + PASSWORD_ACTIONS


def command(action, serial=None, allow_unverified=False, session_seconds=0, log_day=None):
    if action == 'list':
        return sys.executable, ['-I', str(CLI), 'list', '--json', '--lang', 'en']
    if action not in WORKER_ACTIONS or not isinstance(serial, str) or not serial or '\0' in serial:
        raise ValueError('Unsupported action or missing serial')
    pkexec = shutil.which('pkexec')
    if not pkexec:
        raise ValueError('pkexec is unavailable. Install polkit and run a desktop authentication agent.')
    args = ['/usr/bin/python3', '-I', str(CLI.with_name('gui_worker.py')),
            '--action=' + action, '--serial=' + serial]
    if session_seconds:
        if session_seconds not in (60, 300, 900):
            raise ValueError('Invalid authorization duration')
        args.append('--session-seconds=' + str(session_seconds))
    if allow_unverified:
        args.append('--allow-unverified-model')
    if action == 'logs' and log_day is not None:
        args.append('--log-day=' + log_day)
    return pkexec, args


class CliRunner(QObject):
    completed = Signal(str, dict)
    password_required = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.process = QProcess(self)
        self.process.readyReadStandardOutput.connect(self.read_output)
        self.process.readyReadStandardError.connect(self.read_error)
        self.process.finished.connect(self.finished)
        self.process.errorOccurred.connect(self.process_error)
        self.busy = False
        self.authorization_seconds = 0
        self.session_deadline = 0
        self.session_key = None
        self.session_mode = False

    def end_session(self):
        """Only idle workers may be stopped; never interrupt device transactions."""
        if self.busy:
            return
        self.session_deadline = 0
        self.session_key = None
        if self.process.state() != QProcess.ProcessState.NotRunning:
            self.process.closeWriteChannel()
            if not self.process.waitForFinished(1000):
                self.process.terminate()
                self.process.waitForFinished(1000)

    def start(self, action, serial=None, allow_unverified=False, log_day=None):
        if self.busy:
            return
        key = (serial, allow_unverified)
        reuse = (action != 'list' and self.session_key == key
                 and time.monotonic() < self.session_deadline
                 and self.process.state() == QProcess.ProcessState.Running)
        if not reuse:
            self.end_session()
        self.session_mode = reuse or (action != 'list' and self.authorization_seconds > 0)
        self.operation_dispatched = reuse
        self.worker_started = reuse
        self.action = action
        self.log_day = log_day
        self.output = bytearray()
        self.event_buffer = bytearray()
        self.final_report = None
        self.awaiting_password = False
        self.overflow = False
        self.busy = True
        if reuse:
            request = {'action': action}
            if action == 'logs' and log_day is not None:
                request['day'] = log_day
            self.process.write((json.dumps(request) + '\n').encode())
            return
        self.session_key = key if self.session_mode else None
        try:
            program, args = command(action, serial, allow_unverified,
                                    self.authorization_seconds if self.session_mode else 0, log_day)
        except ValueError as exc:
            self.deliver({'complete': False, 'error': str(exc), 'error_stage': 'launch'})
            return
        self.process.setWorkingDirectory(str(CLI.parent))
        self.process.start(program, args)

    def read_output(self):
        data = bytes(self.process.readAllStandardOutput())
        room = max(0, LIMIT - len(self.output))
        self.output.extend(data[:room])
        if (self.action in WORKER_ACTIONS or self.session_mode) and not self.overflow:
            self.event_buffer.extend(data[:room])
            while b'\n' in self.event_buffer:
                line, _, rest = self.event_buffer.partition(b'\n')
                self.event_buffer = bytearray(rest)
                try:
                    event = json.loads(line)
                    if event.get('event') == 'worker_started':
                        self.worker_started = True
                        self.dispatch_initial()
                    elif event.get('event') == 'session_ready' and self.session_mode:
                        self.worker_started = True
                        self.session_deadline = time.monotonic() + min(int(event['seconds']), self.authorization_seconds) - 1
                        self.dispatch_initial()
                    elif event.get('event') == 'password_required' and not self.awaiting_password:
                        self.prompt = event.get('prompt', 'current')
                        if self.prompt not in ('current', 'new', 'confirm'):
                            raise ValueError()
                        self.awaiting_password = True
                        self.password_required.emit()
                    elif event.get('event') == 'result' and isinstance(event.get('report'), dict):
                        self.final_report = event['report']
                        if self.final_report.get('action') != self.action:
                            raise ValueError()
                        if self.session_mode:
                            self.deliver(self.final_report)
                except (ValueError, AttributeError, KeyError, TypeError):
                    self.overflow = True
        self.overflow |= len(data) > room

    def dispatch_initial(self):
        if not self.operation_dispatched:
            # Mark before writing: a lost result after this point is uncertain.
            self.operation_dispatched = True
            self.process.write(b'{"start": true}\n')

    def provide_password(self, password=None):
        if not self.busy or not self.awaiting_password:
            return
        self.awaiting_password = False
        message = {'cancel': True} if password is None else {'password': password}
        self.process.write((json.dumps(message) + '\n').encode('utf-8'))
        if password is None and not self.session_mode:
            self.process.closeWriteChannel()

    def read_error(self):
        # Drain stderr; do not expose raw child output as actionable guidance.
        self.process.readAllStandardError()

    def process_error(self, error):
        if error == QProcess.ProcessError.FailedToStart:
            self.deliver({'complete': False, 'error': 'Could not start CLI or authorization service', 'error_stage': 'launch'})

    def finished(self, code, status):
        self.session_deadline = 0
        self.session_key = None
        if not self.busy:
            return
        self.read_output()
        self.read_error()
        if not self.busy:
            return
        try:
            if self.overflow or status != QProcess.ExitStatus.NormalExit:
                raise ValueError()
            report = self.final_report if self.action in WORKER_ACTIONS or self.session_mode else json.loads(self.output)
            if not isinstance(report, dict) or report.get('action') != self.action:
                raise ValueError()
            if code != 0 and report.get('complete') is True:
                raise ValueError()
        except (ValueError, UnicodeError):
            launch_diagnostic = {
                'exit_code': code,
                'operation_dispatched': self.operation_dispatched,
                'exit_status': 'normal' if status == QProcess.ExitStatus.NormalExit else 'crashed',
                'worker_started_observed': self.worker_started,
                'stdout_bytes': len(self.output),
                'output_overflow': self.overflow,
                'authorization_session_requested': self.session_mode,
            }
            if (code in (126, 127) and status == QProcess.ExitStatus.NormalExit
                    and not self.operation_dispatched and not self.worker_started
                    and not self.output and not self.overflow):
                self.deliver({'complete': False, 'action': self.action,
                              'error': 'authorization_cancelled' if code == 126 else 'authorization_or_launch_failed_before_start',
                              'error_stage': 'authorization / worker startup',
                              'launch_diagnostic': launch_diagnostic, 'commands': [],
                              'device_commands_sent': False, 'recovery_required': False,
                              'changes_may_have_occurred': False})
                return
            report = {'complete': False, 'action': self.action,
                      'error': 'authorization_or_launch_failed' if code in (126, 127) and not self.worker_started else 'CLI returned no valid result',
                      'error_stage': 'authorization / CLI response',
                      'launch_diagnostic': launch_diagnostic}
        if self.action in PASSWORD_ACTIONS and self.final_report is None:
            report.update(recovery_required=True, changes_may_have_occurred=True,
                          next_action='Completion unknown. Review the operation log and fresh status; do not automatically repeat the operation.')
        self.deliver(report)

    def deliver(self, report):
        if self.busy:
            self.busy = False
            self.output.clear()
            self.completed.emit(self.action, report)
