"""Language selection must change presentation, never protocol decisions."""
from t7manager import credentials as password_input
from t7manager import device as device_api
from t7manager import paths
from t7manager import safety
from t7manager.cli import i18n
from t7manager.cli import main as cli
from t7manager.operations import unlock as unlock_ops
import getpass
import os
import shutil
import sys
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_single_native import INFO


class Tests(unittest.TestCase):
    def invoke(self, args, env=None, usage=None):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, patch.object(paths, 'BASE', Path(tmp)), patch.dict(os.environ, env or {}, clear=True), patch.object(device_api, 'list_devices', return_value=[INFO]), patch.object(safety, 'local_output'), patch.object(safety, 'usage_snapshot', return_value=usage or {'idle': True}), contextlib.redirect_stdout(output):
            code = cli.main(args)
        return code, output.getvalue()

    def test_locale_precedence_and_override(self):
        for env, expected in [({}, 'en'), ({'LANG': 'ko_KR.UTF-8'}, 'ko'), ({'LC_MESSAGES': 'en_US', 'LANG': 'ko_KR'}, 'en'), ({'LC_ALL': 'C', 'LC_MESSAGES': 'ko_KR'}, 'en'), ({'LC_ALL': '', 'LANG': 'ko_KR'}, 'ko')]:
            _, text = self.invoke(['list', '--json'], env)
            self.assertEqual(json.loads(text)['language'], expected)
            _, text = self.invoke(['--lang=ko', 'list', '--json'], env)
            self.assertEqual(json.loads(text)['language'], 'ko')
        self.assertEqual(i18n.LANGUAGE, 'ko')

    def test_invalid_language_has_no_device_calls(self):
        with patch.object(device_api, 'list_devices') as devices:
            for args in (['--lang'], ['--lang=fr', '--json']):
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(cli.main(args), 1)
                self.assertIn('invalid_language', output.getvalue())
            devices.assert_not_called()

    def test_english_all_dry_plans_and_errors(self):
        for action in cli.ACTION_PLANS:
            for extra in ([], ['--bad']):
                code, text = self.invoke([action, '--lang', 'en', '--json', *extra])
                result = json.loads(text)
                self.assertEqual(result['commands'], [])
                self.assertNotRegex(text, '[가-힣]')
    def test_machine_fields_unchanged_between_languages(self):
        reports = []
        for language in ('en', 'ko'):
            code, text = self.invoke(['status', '--lang', language, '--json'], usage={'idle': False})
            self.assertEqual(code, 1)
            reports.append(json.loads(text))
        for key in ('error', 'commands', 'complete', 'identity', 'host_checks_passed'):
            self.assertEqual(reports[0][key], reports[1][key])
        for key in ('cause', 'changes_this_run', 'recovery', 'next_action'):
            self.assertEqual(reports[0]['diagnostic'][key], reports[1]['diagnostic'][key])
        self.assertNotEqual(reports[0]['error_stage'], reports[1]['error_stage'])

    def test_stage_suffix_and_user_data_not_translated(self):
        with patch.object(i18n, 'LANGUAGE', 'en'):
            report = {'error_stage': 'auth-in (전송 또는 응답 검증)', 'identity': {'serials': ['잠김'], 'device': '/dev/잠김'}, 'error': 'authentication_rejected'}
            localized = i18n.localized_report(report)
            self.assertNotRegex(localized['error_stage'], '[가-힣]')
            self.assertEqual(localized['identity'], report['identity'])
            self.assertIn('전송', report['error_stage'])

    def test_password_prompts_both_languages(self):
        for language in ('en', 'ko'):
            with patch.object(i18n, 'LANGUAGE', language), patch.object(sys.stdin, 'isatty', return_value=True), patch.object(getpass, 'getpass', return_value='FakeOnly9') as prompt:
                self.assertEqual(password_input.read_password(), b'FakeOnly9')
                text = prompt.call_args.args[0]
                self.assertEqual(bool(__import__('re').search('[가-힣]', text)), language == 'ko')
            with patch.object(i18n, 'LANGUAGE', language), patch.object(sys.stdin, 'isatty', return_value=True), patch.object(getpass, 'getpass', side_effect=['OldFake9', 'NewFake9', 'NewFake9']) as prompt:
                password_input.change_password_inputs()
                self.assertEqual(len(prompt.call_args_list), 3)
                for call in prompt.call_args_list:
                    self.assertEqual(bool(__import__('re').search('[가-힣]', call.args[0])), language == 'ko')

    def test_help_language_and_restore(self):
        for language in ('en', 'ko'):
            _, text = self.invoke(['--help', '--lang', language])
            for item in ('list', 'status', 'probe', 'unlock', 'change-password',
                         'set-password', 'remove-password', 'probe-default-credential',
                         '--execute', '--json', '--save-results', '--lang'):
                self.assertIn(item, text)
            if language == 'en':
                self.assertNotRegex(text, '[가-힣]')
                self.assertIn('Actual operations require both', text)
            else:
                self.assertIn('사용법', text)
                self.assertIn('실제 장치 작업에는 명령과', text)
            with self.assertRaises(SystemExit):
                self.invoke(['status', '--help', '--lang', language])
            self.assertEqual(i18n.LANGUAGE, 'ko')

    def test_report_saving_matches_localized_stdout(self):
        for language in ('en', 'ko'):
            with tempfile.TemporaryDirectory() as tmp:
                def fake(info, serial, action, out, state):
                    out.mkdir(parents=True)
                    return {'complete': False, 'commands': [], 'error': 'authentication_rejected', 'changes_may_have_occurred': False, 'error_stage': 'password input'}
                output = io.StringIO()
                with patch.object(paths, 'BASE', Path(tmp)), patch.object(device_api, 'list_devices', return_value=[INFO]), patch.object(safety, 'local_output'), patch.object(safety, 'usage_snapshot', return_value={'idle': True}), patch.object(os, 'geteuid', return_value=0), patch.object(shutil, 'which', return_value='/fake'), patch.object(unlock_ops, 'execute_unlock', side_effect=fake), contextlib.redirect_stdout(output):
                    self.assertEqual(cli.main(['unlock', '--execute', '--json', '--save-results', '--lang', language]), 1)
                result = json.loads(output.getvalue())
                self.assertEqual(json.loads(Path(result['result_path']).read_text()), result)
