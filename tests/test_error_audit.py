"""Fault injection for durable operation logs; no physical device access."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from t7manager import errors, records
from t7manager.operations import unlock as unlock_ops
from test_single_native import FakeHost, INFO, SECRET


class Tests(unittest.TestCase):
    def test_log_failure_before_transfer_stops_device_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / 'state'
            host = FakeHost()
            with patch.object(records, 'save', side_effect=OSError('secret disk failure')):
                result = unlock_ops.execute_unlock(INFO, 'TEST', 'unlock', None, state, host)
            self.assertFalse(result['complete'])
            self.assertEqual(host.calls, [])
            self.assertNotIn('secret disk failure', json.dumps(result))

    def test_interrupted_transfer_does_not_retry(self):
        class InterruptHost(FakeHost):
            def run(self, command, **kwargs):
                result = super().run(command, **kwargs)
                raise KeyboardInterrupt
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / 'state'
            host = InterruptHost()
            result = unlock_ops.execute_unlock(INFO, 'TEST', 'unlock', None, state, host)
            self.assertFalse(result['complete'])
            self.assertEqual(len(host.calls), 1)
            log = json.loads(Path(result['log_path']).read_text())
            self.assertEqual(log['commands'][0]['name'], 'discovery-before')
            self.assertNotIn(SECRET.decode(), json.dumps(log))

    def test_atomic_save_preserves_previous_file_on_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'log.json'
            path.write_bytes(b'{"original": true}\n')
            path.chmod(0o600)
            for syscall in ('fsync', 'replace'):
                with self.subTest(syscall=syscall):
                    manager = (patch.object(os, 'fsync', side_effect=OSError('full'))
                               if syscall == 'fsync' else
                               patch.object(os, 'replace', side_effect=OSError('full')))
                    with manager, self.assertRaises(OSError):
                        records.save(path, {'new': True})
                    self.assertEqual(path.read_bytes(), b'{"original": true}\n')

    def test_file_lock_excludes_concurrent_run_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            with records.run_lock(state):
                with self.assertRaises(errors.Stop):
                    with records.run_lock(state):
                        self.fail('second lock acquired')
            with records.run_lock(state):
                pass
