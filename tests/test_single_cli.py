import ast
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import t7 as app

class Tests(unittest.TestCase):
    def test_file_runs_in_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'t7.py';shutil.copyfile(app.__file__,path)
            result=subprocess.run([sys.executable,'-I',str(path),'--help'],capture_output=True,text=True,check=True)
            self.assertIn('one hidden password prompt',result.stdout)
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()),['t7.py'])
    def test_relock_is_unavailable(self):
        with patch.object(app,'diagnostic_cli') as diagnostic,patch('builtins.print'):
            for action in ('lock','relock'):self.assertEqual(app.main([action,'--execute']),1)
            diagnostic.assert_not_called()
        source=Path(app.__file__).read_text()
        names={node.name for node in ast.walk(ast.parse(source)) if isinstance(node,(ast.FunctionDef,ast.ClassDef))}
        self.assertTrue({'execute_relock','relock_payloads','OfflineRelock'}.isdisjoint(names))
    def test_dispatch(self):
        with patch.object(app,'diagnostic_cli',return_value=0) as diagnostic,patch.object(app,'list_cli',return_value=0) as listing:
            app.main([]);diagnostic.assert_called_with('unlock',[])
            app.main(['status','--execute']);diagnostic.assert_called_with('status',['--execute'])
            app.main(['probe','--serial','TEST']);diagnostic.assert_called_with('probe',['--serial','TEST'])
            app.main(['list']);listing.assert_called_with([])
