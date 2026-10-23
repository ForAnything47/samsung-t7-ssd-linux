"""Host-only tests: never access a real SSD."""
from t7manager import device as device_api
from t7manager import errors
from t7manager import records
import json
import os
import pathlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch



class Tests(unittest.TestCase):
    def test_public_existing_record_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'log.json'
            path.write_text('{}')
            path.chmod(0o644)
            with self.assertRaises(errors.Stop):
                records.save(path, {'changed': True})
            self.assertEqual(path.read_text(), '{}')

    def test_exact_model_scope_and_family_feedback(self):
        for name in ('PSSD T7', 'PSSD T7 Touch', 'PSSD T7 Shield'):
            self.assertTrue(device_api.is_t7_family(name))
            self.assertEqual(device_api.is_supported_model(name), name == 'PSSD T7 Shield')
        self.assertTrue(device_api.is_supported_model(' pssd t7 shield\n'))
        for name in ('PSSD T7 Shield FAKE', 'fake t7 shield', 'PSSD T7 Shield2'):
            self.assertFalse(device_api.is_supported_model(name))
            with patch.object(pathlib.Path, 'resolve', lambda self, **kwargs: self), patch.object(pathlib.Path, 'exists', return_value=False), patch.object(pathlib.Path, 'read_text', return_value=name), patch.object(device_api, 'device_serials', return_value=['TEST']):
                with self.assertRaises(ValueError):device_api.identity('/dev/sdz')

    def test_old_temporary_link_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            victim = root / 'unrelated'
            victim.write_text('unchanged')
            (root / 'pending.tmp').symlink_to(victim)
            records.save(root / 'pending.json', {'test': True})
            self.assertEqual(victim.read_text(), 'unchanged')
            self.assertFalse((root / 'pending.json').is_symlink())
            self.assertEqual(stat.S_IMODE((root / 'pending.json').stat().st_mode), 0o600)
            self.assertFalse(list(root.glob('.pending.json.*.tmp')))

    def test_final_symlink_and_hardlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            victim = root / 'unrelated'
            victim.write_text('unchanged')
            path = root / 'pending.json'
            for hard in (False, True):
                if hard:os.link(victim, path)
                else:path.symlink_to(victim)
                with self.assertRaises(errors.Stop):records.save(path, {'changed': True})
                self.assertEqual(victim.read_text(), 'unchanged')
                path.unlink()

    def test_directory_links_owner_and_writable_modes_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / 'real'
            real.mkdir(mode=0o700)
            link = root / 'link'
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(OSError):records.save(link / 'result.json', {})
            real.chmod(0o777)
            with self.assertRaises(errors.Stop):records.save(real / 'result.json', {})
            self.assertEqual(stat.S_IMODE(real.stat().st_mode), 0o777)
            real.chmod(0o700)
            with patch.object(os, 'getuid', return_value=os.getuid()+1):
                with self.assertRaises(errors.Stop):records.save(real / 'result.json', {})

    def test_interrupted_save_preserves_previous_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'pending.json'
            records.save(path, {'original': True})
            with patch.object(json, 'dump', side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):records.save(path, {'new': True})
            self.assertEqual(json.loads(path.read_text()), {'original': True})
            self.assertFalse(list(root.glob('.pending.json.*.tmp')))
