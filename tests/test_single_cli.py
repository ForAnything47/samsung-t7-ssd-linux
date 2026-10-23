"""CLI entry point and relocatable source distribution contract."""
import ast
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from t7manager.cli import main as cli

ROOT = Path(__file__).resolve().parents[1]


class Tests(unittest.TestCase):
    def test_distribution_runs_from_unrelated_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            installed = Path(tmp) / 'application'
            installed.mkdir()
            shutil.copyfile(ROOT / 't7.py', installed / 't7.py')
            shutil.copytree(ROOT / 't7manager', installed / 't7manager',
                            ignore=shutil.ignore_patterns('__pycache__'))
            result = subprocess.run(
                [sys.executable, '-B', '-I', str(installed / 't7.py'), '--help'],
                cwd=tmp, capture_output=True, text=True, check=True,
            )
            self.assertIn('one hidden SSD password entry', result.stdout)
            self.assertIn('an explicit COMMAND and --execute', result.stdout)
            self.assertEqual(sorted(p.name for p in installed.iterdir()), ['t7.py', 't7manager'])
            # Module relocation must not relocate or create safety records.
            check = 'from t7manager.paths import BASE; print(BASE)'
            result = subprocess.run([sys.executable, '-B', '-c', check], cwd=installed,
                                    capture_output=True, text=True, check=True)
            self.assertEqual(result.stdout.strip(), str(installed))
            self.assertFalse((installed / 'state').exists())

    def test_core_imports_have_no_runtime_side_effects(self):
        # A fresh interpreter catches import-time work hidden by cached modules.
        script = """
import importlib
import pkgutil
import sys
from unittest.mock import patch
import t7manager
with patch('subprocess.run', side_effect=AssertionError('unexpected command')), \
     patch('subprocess.Popen', side_effect=AssertionError('unexpected process')), \
     patch('getpass.getpass', side_effect=AssertionError('unexpected prompt')), \
     patch('pathlib.Path.mkdir', side_effect=AssertionError('unexpected directory')), \
     patch('pathlib.Path.write_text', side_effect=AssertionError('unexpected write')):
    for module in pkgutil.walk_packages(t7manager.__path__, 't7manager.'):
        importlib.import_module(module.name)
assert not any(name.startswith('PySide6') for name in sys.modules)
"""
        subprocess.run([sys.executable, '-B', '-c', script], cwd=ROOT,
                       capture_output=True, text=True, check=True)

    def test_worker_isolated_help_from_unrelated_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            installed = Path(tmp) / 'application'
            installed.mkdir()
            shutil.copyfile(ROOT / 'gui_worker.py', installed / 'gui_worker.py')
            shutil.copytree(ROOT / 't7manager', installed / 't7manager',
                            ignore=shutil.ignore_patterns('__pycache__'))
            result = subprocess.run(
                [sys.executable, '-B', '-I', str(installed / 'gui_worker.py'), '--help'],
                cwd=tmp, capture_output=True, text=True, check=True,
            )
            self.assertIn('--serial', result.stdout)
            self.assertFalse((installed / 'state').exists())

    def test_relock_is_unavailable(self):
        with patch.object(cli, 'diagnostic_cli') as diagnostic, patch('builtins.print'):
            for action in ('lock', 'relock'):
                self.assertEqual(cli.main([action, '--execute']), 1)
            diagnostic.assert_not_called()
        names = set()
        for path in (ROOT / 't7manager').rglob('*.py'):
            names.update(n.name for n in ast.walk(ast.parse(path.read_text()))
                         if isinstance(n, (ast.FunctionDef, ast.ClassDef)))
        self.assertTrue({'execute_relock', 'relock_payloads', 'OfflineRelock'}.isdisjoint(names))

    def test_dispatch(self):
        with patch.object(cli, 'diagnostic_cli', return_value=0) as diagnostic, patch.object(cli, 'list_cli', return_value=0) as listing:
            cli.main([])
            diagnostic.assert_called_with('unlock', [])
            cli.main(['status', '--execute'])
            diagnostic.assert_called_with('status', ['--execute'])
            cli.main(['probe', '--serial', 'TEST'])
            diagnostic.assert_called_with('probe', ['--serial', 'TEST'])
            cli.main(['list'])
            listing.assert_called_with([])
