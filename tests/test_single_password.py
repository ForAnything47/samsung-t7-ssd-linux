from t7manager import credentials as password_input
from t7manager import errors
from t7manager.cli import i18n
import getpass
import sys
import unittest
from unittest.mock import patch


class Tests(unittest.TestCase):
    def test_one_hidden_prompt(self):
        with patch.object(sys.stdin,'isatty',return_value=True),patch.object(getpass,'getpass',return_value='FakeOnly!9') as prompt:
            self.assertEqual(password_input.read_password(),b'FakeOnly!9');self.assertEqual(prompt.call_count,1)
    def test_invalid_input_and_nonterminal_rejected(self):
        for value in ('abc','a bcd','비밀번호','x'*17):
            with patch.object(sys.stdin,'isatty',return_value=True),patch.object(getpass,'getpass',return_value=value):
                with self.assertRaises(errors.Stop):password_input.read_password()
        with patch.object(sys.stdin,'isatty',return_value=False),patch.object(getpass,'getpass') as prompt:
            with self.assertRaises(errors.Stop):password_input.read_password()
            prompt.assert_not_called()

    def test_interrupt_at_every_prompt_keeps_stdout_clean(self):
        import contextlib
        import io
        cases = [(password_input.read_password, 1), (password_input.change_password_inputs, 3),
                 (password_input.new_security_password, 2)]
        for language in ('en', 'ko'):
            for function, count in cases:
                for position in range(count):
                    with self.subTest(language=language, function=function.__name__, position=position):
                        out, err = io.StringIO(), io.StringIO()
                        values = ['FakeOnly9'] * position + [KeyboardInterrupt()]
                        with patch.object(i18n, 'LANGUAGE', language), patch.object(sys.stdin, 'isatty', return_value=True), patch.object(getpass, 'getpass', side_effect=values) as prompt, contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                            with self.assertRaises(KeyboardInterrupt):
                                function()
                        self.assertEqual(prompt.call_count, position + 1)
                        self.assertIs(prompt.call_args.kwargs['stream'], err)
                        self.assertEqual(out.getvalue(), '')
                        self.assertEqual(err.getvalue(), '\n')

    def test_prompt_success_and_newline_failure_preserve_result(self):
        import contextlib
        import io
        with contextlib.redirect_stderr(io.StringIO()) as err, patch.object(getpass, 'getpass', return_value='FakeOnly9'):
            self.assertEqual(password_input.hidden_password_prompt('Prompt: '), 'FakeOnly9')
            self.assertEqual(err.getvalue(), '')
        with patch.object(getpass, 'getpass', side_effect=KeyboardInterrupt), patch('builtins.print', side_effect=OSError('write failed')):
            with self.assertRaises(KeyboardInterrupt):
                password_input.hidden_password_prompt('Prompt: ')
