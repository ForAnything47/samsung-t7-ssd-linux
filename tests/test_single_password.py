import unittest
from unittest.mock import patch
import t7 as app

class Tests(unittest.TestCase):
    def test_one_hidden_prompt(self):
        with patch.object(app.sys.stdin,'isatty',return_value=True),patch.object(app.getpass,'getpass',return_value='FakeOnly!9') as prompt:
            self.assertEqual(app.read_password(),b'FakeOnly!9');self.assertEqual(prompt.call_count,1)
    def test_invalid_input_and_nonterminal_rejected(self):
        for value in ('abc','a bcd','비밀번호','x'*17):
            with patch.object(app.sys.stdin,'isatty',return_value=True),patch.object(app.getpass,'getpass',return_value=value):
                with self.assertRaises(app.Stop):app.read_password()
        with patch.object(app.sys.stdin,'isatty',return_value=False),patch.object(app.getpass,'getpass') as prompt:
            with self.assertRaises(app.Stop):app.read_password()
            prompt.assert_not_called()

    def test_interrupt_at_every_prompt_keeps_stdout_clean(self):
        import contextlib
        import io
        cases = [(app.read_password, 1), (app.change_password_inputs, 3),
                 (app.new_security_password, 2)]
        for language in ('en', 'ko'):
            for function, count in cases:
                for position in range(count):
                    with self.subTest(language=language, function=function.__name__, position=position):
                        out, err = io.StringIO(), io.StringIO()
                        values = ['FakeOnly9'] * position + [KeyboardInterrupt()]
                        with patch.object(app, 'LANGUAGE', language), patch.object(app.sys.stdin, 'isatty', return_value=True), patch.object(app.getpass, 'getpass', side_effect=values) as prompt, contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                            with self.assertRaises(KeyboardInterrupt):
                                function()
                        self.assertEqual(prompt.call_count, position + 1)
                        self.assertIs(prompt.call_args.kwargs['stream'], err)
                        self.assertEqual(out.getvalue(), '')
                        self.assertEqual(err.getvalue(), '\n')

    def test_prompt_success_and_newline_failure_preserve_result(self):
        import contextlib
        import io
        with contextlib.redirect_stderr(io.StringIO()) as err, patch.object(app.getpass, 'getpass', return_value='FakeOnly9'):
            self.assertEqual(app.hidden_password_prompt('Prompt: '), 'FakeOnly9')
            self.assertEqual(err.getvalue(), '')
        with patch.object(app.getpass, 'getpass', side_effect=KeyboardInterrupt), patch('builtins.print', side_effect=OSError('write failed')):
            with self.assertRaises(KeyboardInterrupt):
                app.hidden_password_prompt('Prompt: ')
