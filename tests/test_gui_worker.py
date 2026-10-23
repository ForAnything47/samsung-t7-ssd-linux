"""Credential bridge tests: synthetic data only; never execute device I/O."""
import io
import unittest
from unittest.mock import patch
import gui_worker as worker
from t7manager import errors, transport


class Input:
    def __init__(self, data):
        self.buffer = io.BytesIO(data)


class WorkerTests(unittest.TestCase):
    def test_password_not_in_events(self):
        events = []
        with patch.object(worker.sys, 'stdin', Input(b'{"password":"Test1234"}\n')), patch.object(worker, 'send', events.append):
            self.assertEqual(worker.request_password(), b'Test1234')
        self.assertEqual(events, [{'event': 'password_required', 'prompt': 'current'}])

    def test_cancel_eof_invalid_and_oversized_fail_before_auth(self):
        for raw in (b'{"cancel":true}\n', b'', b'{}\n', b'{"password":"a"}\n', b'x'*1025, b'{"password":42}\n'):
            with self.subTest(raw=raw[:30]), patch.object(worker.sys, 'stdin', Input(raw)), patch.object(worker, 'send'):
                with self.assertRaises(errors.Stop):
                    worker.request_password()

    def test_adapter_preserves_original_host(self):
        host = transport.UnverifiedModelHost()
        adapter = worker.GuiHost(host)
        self.assertTrue(adapter.allow_unverified_model)
        self.assertIs(adapter.identify, host.identify)

    def test_cli_entry_uses_existing_unlock_and_no_password_arguments(self):
        def cli(action, args, *, host_adapter):
            self.assertEqual(action, 'unlock')
            self.assertIn('--serial=TEST', args)
            self.assertIs(host_adapter, worker.GuiHost)
            print('{"action":"unlock","complete":true}')
            return 0
        events=[]
        with patch.object(worker.sys, 'argv', ['gui_worker.py', '--serial=TEST']), patch.object(worker.cli, 'diagnostic_cli', cli), patch.object(worker, 'send', events.append), patch.object(worker.resource, 'setrlimit'), patch.object(worker, 'session_request', return_value={'start': True}):
            self.assertEqual(worker.main(), 0)
        self.assertEqual(events[0]['event'], 'worker_started')
        self.assertEqual(events[-1]['event'], 'result')

    def test_multi_prompt_change_and_setup(self):
        import json
        for operation, values, expected in (
            ('change_password_inputs', ['Old1234', 'New1234', 'New1234'], (b'Old1234', b'New1234')),
            ('new_security_password', ['New1234', 'New1234'], b'New1234'),
        ):
            events = []
            raw = ''.join(json.dumps({'password': value}) + '\n' for value in values).encode()
            with patch.object(worker.sys, 'stdin', Input(raw)), patch.object(worker, 'send', events.append):
                self.assertEqual(getattr(worker.GuiHost(object()), operation)(), expected)
            self.assertEqual([event['prompt'] for event in events],
                             ['current', 'new', 'confirm'] if len(values) == 3 else ['new', 'confirm'])
            self.assertNotIn('1234', repr(events))

    def test_cancel_at_each_change_prompt_and_mismatch(self):
        import json
        for index in range(3):
            values = [{'password': 'Old1234'}, {'password': 'New1234'}][:index]
            values.append({'cancel': True})
            raw = ''.join(json.dumps(value) + '\n' for value in values).encode()
            with patch.object(worker.sys, 'stdin', Input(raw)), patch.object(worker, 'send'):
                with self.assertRaisesRegex(errors.Stop, 'password_input_cancelled_no_auth_sent'):
                    worker.GuiHost(object()).change_password_inputs()
        with patch.object(worker, 'request_password', side_effect=[b'Old1234', b'New1234', b'Other123']):
            with self.assertRaisesRegex(errors.Stop, 'password_entries_differ_no_auth_sent'):
                worker.GuiHost(object()).change_password_inputs()

    def test_dispatch_all_password_actions(self):
        for action in ('change-password', 'set-password', 'remove-password'):
            def cli(selected, args, *, host_adapter):
                self.assertEqual(selected, action)
                self.assertNotIn('--save-results', args)
                print('{"action":"' + action + '","complete":true}')
                return 0
            with patch.object(worker.sys, 'argv', ['worker', '--serial=TEST', '--action=' + action]), patch.object(worker.cli, 'diagnostic_cli', cli), patch.object(worker, 'send'), patch.object(worker.resource, 'setrlimit'), patch.object(worker, 'session_request', return_value={'start': True}):
                self.assertEqual(worker.main(), 0)

    def test_no_device_operation_without_explicit_start_ack(self):
        for request in (None, {}, {'start': False}, {'action': 'unlock'}):
            with patch.object(worker.sys, 'argv', ['worker', '--serial=TEST']), patch.object(worker.resource, 'setrlimit'), patch.object(worker, 'send'), patch.object(worker, 'session_request', return_value=request), patch.object(worker, 'run_operation') as operation:
                self.assertEqual(worker.main(), 1)
                operation.assert_not_called()
