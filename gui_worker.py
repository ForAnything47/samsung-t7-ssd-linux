#!/usr/bin/env python3
"""Privileged GUI operation bridge with optional bounded session reuse. Only JSON events cross stdout.

The existing CLI owns device selection, journals, locks and protocol execution.
Passwords travel over stdin for each operation, never through argv, environment or files.
"""
import argparse
import contextlib
import io
import json
import resource
import sys
import os
import select
import time
from pathlib import Path

# -I deliberately excludes user site packages and PYTHONPATH. Load only the
# colocated core package; installing a root-owned copy is required for system packaging.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from t7manager import device, errors, records
from t7manager.cli import i18n, main as cli


def send(event):
    try:
        sys.__stdout__.write(json.dumps(event) + '\n')
        sys.__stdout__.flush()
    except BrokenPipeError:
        # Losing the display must not interrupt an in-flight transaction.
        pass


def request_password(prompt="current"):
    """Read one bounded response; prompt names never contain credentials."""
    send({'event': 'password_required', 'prompt': prompt})
    line = sys.stdin.buffer.readline(1025)
    try:
        if not line.endswith(b'\n') or len(line) > 1024:
            raise ValueError()
        request = json.loads(line)
        if request == {'cancel': True}:
            raise errors.Stop('password_input_cancelled_no_auth_sent')
        if not isinstance(request, dict) or set(request) != {'password'} or not isinstance(request['password'], str):
            raise ValueError()
        credential = request['password'].encode('ascii')
        if not 4 <= len(credential) <= 16 or any(not 33 <= b <= 126 for b in credential):
            raise ValueError()
        return credential
    except (ValueError, UnicodeError):
        raise errors.Stop('unsupported_password_format_no_auth_sent') from None
    finally:
        line = None


class GuiHost:
    def __init__(self, host):
        self.host = host

    def __getattr__(self, name):
        return getattr(self.host, name)

    def password(self):
        return request_password()

    def new_security_password(self):
        first = request_password('new')
        second = request_password('confirm')
        if first != second:
            raise errors.Stop('password_entries_differ_no_auth_sent')
        return first

    def change_password_inputs(self):
        current = request_password('current')
        new = self.new_security_password()
        if current == new:
            raise errors.Stop('new_password_same_no_changes')
        return current, new


ACTIONS = ('status', 'unlock', 'change-password', 'set-password', 'remove-password', 'logs')
def run_operation(action, serial, allow, day=None):
    if action == 'logs':
        try:
            matches = [info for info in device.list_devices(family=True) if serial in info['serials']]
            if len(matches) != 1:
                raise errors.Stop('matching_T7_not_found')
            report = records.read_operation_logs(matches[0], day)
        except (errors.Stop, OSError, ValueError):
            report = {'action': 'logs', 'complete': False, 'error': 'operation_logs_unavailable',
                      'device_commands_sent': False}
    else:
        report = run_cli(action, serial, allow)
    send({'event': 'result', 'report': report})
    return 0 if report.get('complete') is True else 1


def run_cli(action, serial, allow):
    argv = ['--serial=' + serial, '--execute', '--json']
    if allow:
        argv.append('--allow-unverified-model')
    previous_language = i18n.LANGUAGE
    i18n.LANGUAGE = 'en'
    output = io.StringIO()
    try:
        with contextlib.redirect_stdout(output):
            code = cli.diagnostic_cli(action, argv, host_adapter=GuiHost)
    finally:
        i18n.LANGUAGE = previous_language
    report = json.loads(output.getvalue())
    if code != 0 and report.get('complete') is True:
        report = {'action': action, 'complete': False, 'error': 'cli_exit_mismatch'}
    return report


def session_request(deadline):
    """Bounded, deadline-aware reads: a partial line cannot extend authorization."""
    data = bytearray()
    while len(data) < 4096:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([sys.stdin.fileno()], [], [], remaining)[0]:
            return None
        value = os.read(sys.stdin.fileno(), 1)
        if not value:
            return None
        data.extend(value)
        if value == b'\n':
            try:
                return json.loads(data)
            except ValueError:
                return None
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--action', choices=ACTIONS, default='unlock')
    parser.add_argument('--serial', required=True)
    parser.add_argument('--allow-unverified-model', action='store_true')
    parser.add_argument('--session-seconds', type=int, choices=(0, 60, 300, 900), default=0)
    parser.add_argument('--log-day')
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    deadline = time.monotonic() + args.session_seconds
    if args.session_seconds:
        send({'event': 'session_ready', 'seconds': args.session_seconds})
    else:
        send({'event': 'worker_started'})
    # No CLI/device operation is allowed until this GUI explicitly dispatches
    # it. A missing startup event/ack can then be distinguished from lost results.
    if session_request(min(deadline, time.monotonic() + 30) if args.session_seconds else time.monotonic() + 30) != {'start': True}:
        return 1
    code = (run_operation(args.action, args.serial, args.allow_unverified_model, args.log_day)
            if args.action == 'logs' else run_operation(args.action, args.serial, args.allow_unverified_model))
    while args.session_seconds and time.monotonic() < deadline:
        request = session_request(deadline)
        # No device/path/privilege policy supplied by a subsequent request.
        if not isinstance(request, dict) or request.get('action') not in ACTIONS or set(request) not in ({'action'}, {'action', 'day'}):
            break
        if time.monotonic() >= deadline:
            break
        code = (run_operation(request['action'], args.serial, args.allow_unverified_model, request.get('day'))
                if request['action'] == 'logs' else run_operation(request['action'], args.serial, args.allow_unverified_model))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
