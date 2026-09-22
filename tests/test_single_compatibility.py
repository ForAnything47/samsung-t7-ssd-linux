from contextlib import nullcontext
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import t7 as probe
from t7 import Stop, is_t7_family
INFO = {'device': '/dev/sdz', 'model': 'PSSD T7 Touch', 'serials': ['TEST'], 'sysfs': 'fake'}
RAW = (Path(__file__).parent / 'fixtures/discovery-locked.bin').read_bytes()

class Host:

    def __init__(self, fail=None, timeout=None, short=None, changed=False, busy=False, raw=RAW):
        self.calls = []
        self.fail = fail
        self.timeout = timeout
        self.short = short
        self.changed = changed
        self.busy = busy
        self.raw = raw

    def identify(self, device):
        return INFO

    def gen(self, info):
        return '2' if self.changed and self.calls else '1'

    def idle(self, device):
        if self.busy:
            raise Stop('busy')

    def claim(self, device):
        return nullcontext()

    def run(self, cmd, **kwargs):
        i = len(self.calls)
        self.calls.append(cmd)
        if i == self.timeout:
            raise subprocess.TimeoutExpired(cmd, 45)
        raw = bytes(36) if i == 0 else self.raw
        if i == self.short:
            raw = raw[:-1]
        return subprocess.CompletedProcess(cmd, 1 if i == self.fail else 0, raw, b'SCSI Status: Good')

class Tests(unittest.TestCase):

    def run_case(self, **kwargs):
        host = Host(**kwargs)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'out'
            result = probe.collect(INFO, out, host)
            self.assertEqual(result, json.loads((out / 'result.json').read_text()))
            return (result, host, {p.name: p.read_bytes() for p in out.iterdir()})

    def test_only_two_queries_and_no_unlock_claim(self):
        r, h, files = self.run_case()
        self.assertTrue(r['complete'])
        self.assertFalse(r['unlock_compatibility_proven'])
        self.assertFalse(r['model_has_prior_validation'])
        self.assertEqual(len(h.calls), 2)
        self.assertEqual(files['discovery.bin'], RAW)
        for cmd, (_, cdb, _) in zip(h.calls, probe.QUERIES):
            self.assertEqual(cmd[-len(cdb):], [f'{b:02x}' for b in cdb])
            self.assertIn('--readonly', cmd)
            self.assertFalse(any((x.startswith('--send') for x in cmd)))

    def test_first_error_stops_no_retry(self):
        for field in ('fail', 'timeout', 'short'):
            for i in (0, 1):
                r, h, _ = self.run_case(**{field: i})
                self.assertFalse(r['complete'])
                self.assertEqual(len(h.calls), i + 1)

    def test_busy_and_generation_change_stop(self):
        for args, count in [({'busy': True}, 0), ({'changed': True}, 1)]:
            r, h, _ = self.run_case(**args)
            self.assertFalse(r['complete'])
            self.assertEqual(len(h.calls), count)

    def test_unsupported_response_preserved(self):
        raw = bytes(4096)
        r, h, files = self.run_case(raw=raw)
        self.assertFalse(r['complete'])
        self.assertEqual(files['discovery.bin'], raw)
        self.assertEqual(r['classification'], 'unsupported_or_incomplete')

    def test_changed_comid_is_not_unlock_approval(self):
        raw = bytearray(RAW)
        raw[132:134] = b'\x10\x05'
        r = probe.analyze(bytes(raw), 'PSSD T7 Shield')
        self.assertEqual(r['classification'], 'parsed_profile_differs')
        self.assertFalse(r['unlock_compatibility_proven'])

    def test_family_exact_match(self):
        for model in ('PSSD T7', 'PSSD T7 Touch', 'PSSD T7 Shield'):
            self.assertTrue(is_t7_family(model))
        for model in ('PSSD T9', 'PSSD T7 fake', 'T7', 'PSSD T5'):
            self.assertFalse(is_t7_family(model))

    def test_dry_run_and_list_do_not_collect(self):
        for args in ([], ['--list']):
            with patch('t7.list_devices', return_value=[INFO]), patch('t7.local_output'), patch('t7.usage_snapshot', return_value={'idle': True}), patch('t7.collect') as collect, patch('builtins.print'):
                self.assertEqual(probe.main(['list'] if '--list' in args else ['probe', *args]), 0)
                collect.assert_not_called()

    def test_ambiguous_candidates_and_busy_never_collect(self):
        for devices, usage in [([INFO, INFO], {'idle': True}), ([INFO], {'idle': False})]:
            with patch('t7.list_devices', return_value=devices), patch('t7.local_output'), patch('t7.usage_snapshot', return_value=usage), patch('t7.collect') as collect, patch('builtins.print'):
                self.assertEqual(probe.main(['probe', '--execute']), 1)
                collect.assert_not_called()
if __name__ == '__main__':
    unittest.main()
