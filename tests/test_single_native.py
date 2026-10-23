from t7manager import device as device_api
from t7manager import records
from t7manager import safety
from t7manager.cli import main as cli
from t7manager.operations import unlock as unlock_ops
from contextlib import nullcontext
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from t7manager.errors import Stop
from t7manager.device import device_serials
from t7manager.protocol import frame
from t7manager.protocol import byte_atom
from t7manager.protocol import uint
SECRET = b'FakeOnly!9'
INFO = {'device': '/dev/sdz', 'serials': ['TEST'], 'sysfs': 'old', 'model': 'PSSD T7 Shield'}
NEW = {**INFO, 'device': '/dev/sdy', 'sysfs': 'new'}
LOCKED = (Path(__file__).parent / 'fixtures/discovery-locked.bin').read_bytes()
UNLOCKED = bytearray(LOCKED)
UNLOCKED[68] = (UNLOCKED[68] | 32) & ~4
UNLOCKED = bytes(UNLOCKED)
START = frame(b'\xf8' + byte_atom(bytes.fromhex('00000000000000ff')) + byte_atom(bytes.fromhex('000000000000ff03')) + b'\xf0' + uint(1) + uint(291) + b'\xf1\xf9\xf0\x00\x00\x00\xf1', 4100)

class FakeHost:

    def __init__(self, fail=None, bad=None, timeout=None, reject=None, unlocked=False, changed=None, waitfail=False, busy=None):
        self.calls = []
        self.password_calls = 0
        self.reenumerated = False
        self.fail = fail
        self.bad = bad
        self.timeout = timeout
        self.reject = reject
        self.unlocked = unlocked
        self.changed = changed
        self.waitfail = waitfail
        self.busy = busy

    def usage(self, device):
        return {'idle': True, 'mounts': [], 'holders': [], 'swaps': [], 'inflight': 0}

    def identify(self, device):
        return NEW if self.reenumerated else INFO

    def gen(self, info):
        return '999' if len(self.calls) == self.changed else '2' if self.reenumerated else '1'

    def idle(self, device):
        if len(self.calls) == self.busy:
            raise Stop('device_in_use')

    def claim(self, device):
        return nullcontext()

    def password(self):
        self.password_calls += 1
        return SECRET

    def partitions(self, info):
        return [{'device': info['device'] + '1', 'size_bytes': 2000000000000}]

    def wait(self, *args):
        if self.waitfail:
            raise Stop('no_new_generation')
        self.reenumerated = True
        return (NEW, '2')

    def run(self, cmd, **kwargs):
        i = len(self.calls)
        self.calls.append((cmd, kwargs))
        if i == self.timeout:
            raise subprocess.TimeoutExpired(cmd, 45, output=SECRET, stderr=SECRET)
        if i == self.fail:
            return subprocess.CompletedProcess(cmd, 2, SECRET, SECRET)
        raw = b''
        if i in (0, 1, 8):
            raw = UNLOCKED if self.unlocked else LOCKED
        if i in (25, 27):
            raw = UNLOCKED
        if i in (3, 10):
            raw = START
        if i == 5:
            raw = frame(b'\xf0' + byte_atom(bytes(144)) + b'\xf1\xf9\xf0\x00\x00\x00\xf1', 4100, 291, 1)
        if i in (7, 24):
            raw = frame(b'\xfa', 4100, 291, 1)
        if i in (12, 22):
            raw = frame(bytes([251 if i == 12 else 252, 1 if i == self.reject else 0]), 4100, 291, 1)
        if i in (14, 16, 18, 20):
            raw = frame(b'\xf0\xf1\xf9\xf0' + bytes([1 if i == self.reject else 0]) + b'\x00\x00\xf1', 4100, 291, 1)
        if i == 10 and i == self.reject:
            raw = frame(b'\xf0\x01\x00\x00\xf1', 4100)
        if i == self.bad:
            raw = SECRET
        return subprocess.CompletedProcess(cmd, 0, raw, SECRET)

class Tests(unittest.TestCase):

    def case(self, action='unlock', pending=False, **kwargs):
        h = FakeHost(**kwargs)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / 'state'
            state.mkdir()
            if pending:
                (state / 'pending.json').write_text('{}')
            out = root / 'out'
            r = unlock_ops.execute_unlock(INFO, 'TEST', action, out, state, h)
            for p in root.rglob('*.json'):
                text = p.read_bytes()
                self.assertNotIn(SECRET, text)
                self.assertNotIn(SECRET.hex().encode(), text)
            self.assertEqual(json.loads((out / 'result.json').read_text()), r)
            marker = (state / 'pending.json').exists()
        return (r, h, marker)

    def test_password_cancel_reports_input_stage(self):
        with patch.object(FakeHost, 'password', side_effect=Stop('password_input_cancelled_no_auth_sent')):
            report, host, pending = self.case()
        self.assertEqual(report['error_stage'], 'password input')
        self.assertEqual([command['name'] for command in report['commands']], ['discovery-before'])
        self.assertFalse(report['changes_may_have_occurred'])
        self.assertFalse(pending)

    def test_full_success(self):
        r, h, m = self.case()
        self.assertTrue(r['complete'])
        self.assertEqual(r['outcome'], 'unlocked')
        self.assertEqual(len(h.calls), 28)
        self.assertFalse(m)
        self.assertEqual(h.password_calls, 1)
        self.assertEqual(r['partitions'][0]['device'], '/dev/sdy1')
        self.assertEqual(sum((SECRET in kwargs['input'] for _, kwargs in h.calls)), 1)
        self.assertEqual(h.calls[26][0][-6:], ['e8', '00', '00', '00', '00', '00'])
        for cmd, kwargs in h.calls:
            self.assertIn('--readonly', cmd)
            self.assertNotIn(SECRET.decode(), ' '.join(cmd))
            self.assertFalse(any((x.startswith('--infile') for x in cmd)))

    def test_all_transport_failures_stop(self):
        for i in range(28):
            with self.subTest(i=i):
                r, h, m = self.case(fail=i)
                self.assertFalse(r['complete'])
                self.assertEqual(len(h.calls), i + 1)
                self.assertFalse(m)

    def test_all_timeouts_stop(self):
        for i in range(28):
            r, h, m = self.case(timeout=i)
            self.assertFalse(r['complete'])
            self.assertEqual(len(h.calls), i + 1)

    def test_malformed_each_response_stops(self):
        for i in (0, 1, 3, 5, 7, 8, 10, 12, 14, 16, 18, 20, 22, 24, 25, 27):
            r, h, m = self.case(bad=i)
            self.assertFalse(r['complete'])
            self.assertEqual(len(h.calls), i + 1)

    def test_status_failure_stops(self):
        for i in (10, 12, 14, 16, 18, 20, 22):
            r, h, m = self.case(reject=i)
            self.assertFalse(r['complete'])
            self.assertEqual(len(h.calls), i + 1)

    def test_changed_generation_before_each_transfer(self):
        for i in range(1, 28):
            r, h, m = self.case(changed=i)
            self.assertFalse(r['complete'])
            self.assertEqual(len(h.calls), i)

    def test_busy_before_each_transfer(self):
        for i in range(28):
            r, h, m = self.case(busy=i)
            self.assertFalse(r['complete'])
            self.assertEqual(len(h.calls), i)

    def test_wait_failure_does_not_retry_e8(self):
        r, h, m = self.case(waitfail=True)
        self.assertFalse(r['complete'])
        self.assertFalse(m)
        self.assertEqual(len(h.calls), 27)

    def test_status_readonly_without_password(self):
        r, h, m = self.case(action='status')
        self.assertTrue(r['complete'])
        self.assertEqual(len(h.calls), 1)
        self.assertEqual(h.password_calls, 0)

    def test_already_unlocked_no_password_or_mutation(self):
        r, h, m = self.case(unlocked=True)
        self.assertTrue(r['complete'])
        self.assertEqual(len(h.calls), 1)
        self.assertEqual(h.password_calls, 0)
        self.assertFalse(m)

    def test_pending_blocks_unlock_but_allows_status(self):
        r, h, m = self.case(pending=True)
        self.assertTrue(r['complete'])
        self.assertEqual(len(h.calls), 28)
        self.assertTrue(m)  # Legacy record is preserved, but does not block.
        r, h, m = self.case(action='status', pending=True)
        self.assertTrue(r['complete'])
        self.assertTrue(m)

    def test_success_allows_next_run_without_old_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / 'state'
            state.mkdir()
            for i in range(2):
                r = unlock_ops.execute_unlock(INFO, 'TEST', 'unlock', root / str(i), state, FakeHost())
                self.assertTrue(r['complete'])
                self.assertFalse((state / 'pending.json').exists())

    def test_concurrent_runs_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            with records.run_lock(Path(tmp)):
                with self.assertRaises(Stop):
                    with records.run_lock(Path(tmp)):
                        pass

    def test_selector_no_fallback(self):
        self.assertEqual(device_api.select('TEST', lambda _: INFO), INFO)
        with self.assertRaises(Stop):
            device_api.select('OTHER', lambda _: INFO)
        with self.assertRaises(Stop):
            device_api.select('TEST', lambda _: None)

    def test_nearest_usb_serial_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            hub = Path(tmp) / 'hub'
            usb = hub / 'usb'
            node = usb / 'interface/block/sdz'
            node.mkdir(parents=True)
            for p in (hub, usb):
                (p / 'idVendor').write_text('04e8')
                (p / 'idProduct').write_text('x')
            (hub / 'serial').write_text('HUB')
            (usb / 'serial').write_text('TEST')
            self.assertEqual(device_serials(node), ['TEST'])
            (usb / 'serial').unlink()
            self.assertEqual(device_serials(node), [])

    def test_default_dry_run(self):
        with patch('t7manager.device.list_devices', return_value=[INFO]), patch('t7manager.device.select', return_value=INFO), patch('t7manager.safety.usage_snapshot', return_value={'idle': True}), patch('t7manager.safety.local_output', return_value='/dev/nvme0n1p9'), patch('t7manager.operations.unlock.execute_unlock') as run, patch('builtins.print'):
            self.assertEqual(cli.main(['--json']), 0)
            run.assert_not_called()

class ScannerTests(unittest.TestCase):

    def test_duplicate_matching_devices_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('sdz', 'sdy'):
                p = root / name / 'device'
                p.mkdir(parents=True)
                (p / 'model').write_text('PSSD T7 Shield')
            with patch('t7manager.device.Path', side_effect=lambda x: root if x == '/sys/class/block' else Path(x)), patch('t7manager.device.identity', return_value=INFO):
                with self.assertRaises(Stop):
                    device_api.find_device('TEST')

    def test_unique_matching_device_and_missing_serial(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            p = root / 'sdz/device'
            p.mkdir(parents=True)
            (p / 'model').write_text('PSSD T7 Shield')
            with patch('t7manager.device.Path', side_effect=lambda x: root if x == '/sys/class/block' else Path(x)), patch('t7manager.device.identity', return_value=INFO):
                self.assertEqual(device_api.find_device('TEST'), INFO)
                self.assertIsNone(device_api.find_device('missing'))

MOUNT = {'device': '/dev/sdz1', 'device_number': '8:1', 'mountpoint': '/media/T7', 'root': '/', 'fstype': 'vfat', 'partition': True, 'size_bytes': 34537472}

class MountedHost(FakeHost):
    def __init__(self, mode='ok'):
        super().__init__()
        self.mode = mode
        self.mounted = True
        self.events = []

    def usage(self, device):
        mount = dict(MOUNT)
        if self.mode == 'data':
            mount.update(fstype='exfat', size_bytes=2000000000000)
        if self.mode == 'changed' and self.events:
            mount['device'] = '/dev/sdz2'
        return {'idle': not self.mounted, 'mounts': [mount] if self.mounted else [], 'holders': [], 'swaps': ['/dev/sdz1'] if self.mode == 'swap' else [], 'inflight': 0}

    def idle(self, device):
        if self.mounted:
            raise Stop('still_mounted')
        return super().idle(device)

    def claim(self, device):
        if self.mounted:
            raise Stop('exclusive_busy')
        return nullcontext()

    def run(self, cmd, **kwargs):
        if cmd[0] == 'udisksctl':
            self.events.append('unmount')
            assert '--force' not in cmd and '--block-device' in cmd and ('/dev/sdz1' in cmd)
            if self.mode == 'timeout':
                raise subprocess.TimeoutExpired(cmd, 30)
            if self.mode == 'busy':
                return subprocess.CompletedProcess(cmd, 1, b'', b'busy')
            if self.mode != 'remount':
                self.mounted = False
            return subprocess.CompletedProcess(cmd, 0, b'', b'')
        if self.mounted:
            self.events.append('discovery')
            return subprocess.CompletedProcess(cmd, 0, UNLOCKED if self.mode == 'unlocked' else b'bad' if self.mode == 'malformed' else LOCKED, b'')
        return super().run(cmd, **kwargs)

class AutoUnmountTests(unittest.TestCase):

    def case(self, mode='ok', action='unlock'):
        host = MountedHost(mode)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / 'state'
            state.mkdir()
            result = unlock_ops.execute_unlock(INFO, 'TEST', action, root / 'out', state, host)
        return (result, host)

    def test_locked_mount_unmount_then_full_unlock(self):
        r, h = self.case()
        self.assertTrue(r['complete'])
        self.assertEqual(h.events, ['discovery', 'unmount'])
        self.assertEqual(len(h.calls), 28)
        self.assertEqual(r['unmount']['returncode'], 0)

    def test_failed_or_timed_out_unmount_never_authenticates(self):
        for mode in ('busy', 'timeout', 'remount'):
            r, h = self.case(mode)
            self.assertFalse(r['complete'])
            self.assertEqual(h.calls, [])
            self.assertEqual(h.password_calls, 0)
            self.assertEqual(h.events, ['discovery', 'unmount'])

    def test_unlocked_or_invalid_response_never_unmounts(self):
        for mode in ('unlocked', 'malformed'):
            r, h = self.case(mode)
            self.assertFalse(r['complete'])
            self.assertEqual(h.events, ['discovery'])
            self.assertEqual(h.password_calls, 0)

    def test_data_partition_and_swap_never_touched(self):
        for mode in ('data', 'swap'):
            r, h = self.case(mode)
            self.assertFalse(r['complete'])
            self.assertEqual(h.events, [])

    def test_mount_change_stops_before_unmount(self):
        r, h = self.case('changed')
        self.assertFalse(r['complete'])
        self.assertEqual(h.events, ['discovery'])

    def test_status_never_unmounts(self):
        r, h = self.case(action='status')
        self.assertFalse(r['complete'])
        self.assertEqual(h.events, [])

    def test_dry_run_plans_without_io(self):
        usage = MountedHost().usage('/dev/sdz')
        with patch('t7manager.device.list_devices', return_value=[INFO]), patch('t7manager.device.select', return_value=INFO), patch('t7manager.safety.usage_snapshot', return_value=usage), patch('t7manager.safety.local_output', return_value='/dev/nvme0n1p9'), patch('t7manager.operations.unlock.execute_unlock') as run, patch('builtins.print') as output:
            self.assertEqual(cli.main(['--json']), 0)
            run.assert_not_called()
            data = json.loads(output.call_args[0][0])
            self.assertEqual(data['planned_unmount'], '/dev/sdz1')
            self.assertTrue(data['automatic_unmount'])
            self.assertEqual(data['commands'], [])

    def test_bind_and_multiple_mounts_rejected(self):
        usage = MountedHost().usage('/dev/sdz')
        usage['mounts'] = [{**MOUNT, 'root': '/folder'}]
        self.assertIsNone(safety.auto_unmount_candidate(usage))
        usage['mounts'] = [MOUNT, MOUNT]
        self.assertIsNone(safety.auto_unmount_candidate(usage))

class GeneralHostTests(unittest.TestCase):

    def test_automatic_selection_requires_unique_serial(self):
        with patch('t7manager.device.list_devices', return_value=[INFO]):
            self.assertEqual(device_api.select(None, lambda serial: INFO if serial == 'TEST' else None), INFO)
        for candidates in ([], [INFO, NEW], [{**INFO, 'serials': []}]):
            with patch('t7manager.device.list_devices', return_value=candidates):
                with self.assertRaises(Stop):
                    device_api.select(None, lambda _: INFO)

    def test_list_and_ambiguous_selection_never_execute(self):
        for args, candidates, expected in [(['--list'], [INFO], 0), ([], [INFO, NEW], 1), (['--execute'], [INFO, NEW], 1)]:
            with patch('t7manager.device.list_devices', return_value=candidates), patch('t7manager.operations.unlock.execute_unlock') as execute, patch('t7manager.safety.local_output') as output, patch('builtins.print'):
                self.assertEqual(cli.main(args), expected)
                execute.assert_not_called()
                output.assert_not_called()

    def test_explicit_serial_preserved(self):
        with patch('t7manager.device.list_devices', return_value=[INFO, {**NEW, 'serials': ['OTHER']}]), patch('t7manager.safety.usage_snapshot', return_value={'idle': True}), patch('t7manager.safety.local_output', return_value='/dev/other'), patch('t7manager.operations.unlock.execute_unlock') as execute, patch('builtins.print') as output:
            self.assertEqual(cli.main(['--serial', 'TEST', '--json']), 0)
            self.assertEqual(json.loads(output.call_args[0][0])['identity'], INFO)
            execute.assert_not_called()

    def test_block_ancestry_partition_stack_and_unknown(self):
        from t7manager.safety import backing_disks
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            links = root / 'links'
            links.mkdir()
            disk = root / 'disk'
            disk.mkdir()
            (disk / 'device').mkdir()
            (disk / 'slaves').mkdir()
            (disk / 'dev').write_text('8:0')
            part = disk / 'part'
            part.mkdir()
            (part / 'partition').write_text('1')
            (part / 'dev').write_text('8:1')
            dm = root / 'dm'
            dm.mkdir()
            (dm / 'slaves').mkdir()
            (dm / 'dev').write_text('253:0')
            (dm / 'slaves/part').symlink_to(part)
            for number, node in [('8:0', disk), ('8:1', part), ('253:0', dm)]:
                (links / number).symlink_to(node)
            self.assertEqual(backing_disks('253:0', links), {str(disk)})
            (disk / 'device').rmdir()
            with self.assertRaises(Stop):
                backing_disks('8:0', links)
            (dm / 'slaves/self').symlink_to(dm)
            with self.assertRaises(Stop):
                backing_disks('253:0', links)

    def test_output_target_network_unknown_and_separate_disk(self):
        from t7manager.safety import local_output
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / 'target'
            target.mkdir()
            other = root / 'other'
            other.mkdir()
            info = {**INFO, 'sysfs': str(target)}
            for fstype, disks, allowed in [('ext4', {str(other)}, True), ('ext4', {str(target)}, False), ('xfs', {str(other), str(target)}, False), ('nfs', {str(other)}, False), ('overlay', {str(other)}, False)]:
                result = subprocess.CompletedProcess([], 0, json.dumps({'filesystems': [{'source': '/dev/mapper/data', 'fstype': fstype, 'maj:min': '253:0'}]}), '')
                with patch('subprocess.run', return_value=result), patch('t7manager.safety.backing_disks', return_value=disks):
                    if allowed:
                        self.assertEqual(local_output(root / 'new/log', info), '/dev/mapper/data')
                    else:
                        with self.assertRaises(Stop):
                            local_output(root / 'new/log', info)

    def test_btrfs_checks_every_device_and_symlink_destination(self):
        from t7manager.safety import local_output
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / 'target'
            target.mkdir()
            other = root / 'other'
            other.mkdir()
            devices = root / 'btrfs/abc-123/devices'
            devices.mkdir(parents=True)
            for name, number in [('one', '8:1'), ('two', '8:17')]:
                (devices / name).mkdir()
                (devices / name / 'dev').write_text(number)
            link = root / 'log'
            link.symlink_to(other, target_is_directory=True)
            result = subprocess.CompletedProcess([], 0, json.dumps({'filesystems': [{'source': '/dev/sdb1[/home]', 'fstype': 'btrfs', 'uuid': 'abc-123'}]}), '')
            with patch('t7manager.safety.Path', side_effect=lambda path: root / 'btrfs' if path == '/sys/fs/btrfs' else Path(path)), patch('subprocess.run', return_value=result) as run, patch('t7manager.safety.backing_disks', side_effect=[{str(other)}, {str(target)}]) as backing:
                with self.assertRaises(Stop):
                    local_output(link / 'new', {**INFO, 'sysfs': str(target)})
                self.assertEqual(backing.call_count, 2)
                self.assertIn(str(other), run.call_args[0][0])
if __name__ == '__main__':
    unittest.main()
