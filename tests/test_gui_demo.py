"""Mock GUI checks. Qt-specific checks skip when the optional extra is absent."""
import os
import unittest
from gui.model import DEVICES, SCENARIOS, DemoModel


class ModelTests(unittest.TestCase):
    def test_success_and_duplicate_start(self):
        model = DemoModel()
        model.start()
        with self.assertRaises(ValueError):
            model.start()
        with self.assertRaises(ValueError):
            model.reset(DEVICES[1], SCENARIOS[0])
        for _ in range(4):
            model.advance()
        self.assertEqual(model.state, "Unlocked")
        self.assertFalse(model.can_start)

    def test_rejection_allows_new_user_attempt(self):
        model = DemoModel()
        model.reset(DEVICES[0], "Password rejected")
        model.start()
        model.advance()
        model.advance()
        self.assertFalse(model.busy)
        self.assertTrue(model.can_start)
        self.assertIn("rejected", model.message)

    def test_opt_in_resets_with_selection_and_cancel(self):
        model = DemoModel()
        model.reset(DEVICES[1], SCENARIOS[0])
        self.assertFalse(model.can_start)
        model.allow_unverified = True
        model.start()
        model.cancel()
        self.assertTrue(model.can_start)
        model.reset(DEVICES[2], SCENARIOS[0])
        self.assertFalse(model.can_start)


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
try:
    from PySide6.QtWidgets import QApplication
    from gui.window import Window
except ModuleNotFoundError:
    QApplication = None


@unittest.skipIf(QApplication is None, "Optional PySide6 dependency not installed")
class WidgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        from unittest.mock import patch
        self.pref_load = patch('gui.preferences.load', return_value=('light', 0))
        self.pref_save = patch('gui.preferences.save', return_value=True)
        self.pref_load.start()
        self.pref_save.start()
        self.addCleanup(self.pref_load.stop)
        self.addCleanup(self.pref_save.stop)
        self.window = Window()

    def tearDown(self):
        self.window.close()

    def test_password_cleared_and_busy_controls_blocked(self):
        window = self.window
        window.password.setText("synthetic-only")
        window.start()
        self.assertEqual(window.password.text(), "")
        self.assertFalse(window.devices.isEnabled())
        self.assertFalse(window.unlock.isEnabled())
        window.cancel_demo()
        self.assertFalse(window.model.busy)
        self.assertTrue(window.devices.isEnabled())

    def test_details_progress_copy_and_export_without_password(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        window = self.window
        window.password.setText("private-input-canary")
        window.start()
        for _ in range(4):
            window.tick()
        text = window.operation_text.toPlainText()
        self.assertIn("Simulating authentication", text)
        self.assertIn("Simulation complete", text)
        self.assertNotIn("private-input-canary", text)
        window.copy_detail_text()
        self.assertEqual(self.app.clipboard().text(), text)
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "details.txt"
            with patch("gui.window.QFileDialog.getSaveFileName", return_value=(str(target), "")):
                window.save_detail_text()
            self.assertEqual(target.read_text(), text)
            pending = Path(folder) / "pending.json"
            pending.write_text("original")
            with patch("gui.window.QFileDialog.getSaveFileName", return_value=(str(pending), "")):
                window.save_detail_text()
            self.assertEqual(pending.read_text(), "original")

    def test_theme_switch_preserves_details_and_updates_popup(self):
        window = self.window
        text = window.operation_text.toPlainText()
        for dark in (True, False):
            window.apply_theme(dark)
            self.assertEqual(window.scenario.property("darkMode"), dark)
            self.assertEqual(window.operation_text.toPlainText(), text)
            self.assertFalse(window.copy_details.icon().isNull())
            window.scenario.showPopup()
            self.app.processEvents()
            self.assertIn("#202c3b" if dark else "#ffffff", window.scenario.view().window().styleSheet())
            window.scenario.hidePopup()

    def test_summary_json_switch_and_copy(self):
        window = self.window
        window.append_report('status', {'action': 'status', 'complete': True, 'before': {'locked': True}})
        self.assertIn('Last observed lock state: Locked', window.operation_text.toPlainText())
        window.detail_mode.setCurrentText('JSON')
        self.assertIn('"locked": true', window.operation_text.toPlainText())
        self.assertIn('STATUS', window.operation_text.toPlainText())
        window.copy_detail_text()
        self.assertEqual(self.app.clipboard().text(), window.operation_text.toPlainText())
        window.detail_mode.setCurrentText('Summary')
        self.assertNotIn('"locked": true', window.operation_text.toPlainText())

    def test_details_window_stays_in_sync_and_close_independently(self):
        window = self.window
        window.show()
        for index in range(80):
            window.append_detail(f"Entry {index}")
        self.app.processEvents()
        source_scroll = window.operation_text.verticalScrollBar()
        self.assertGreater(source_scroll.maximum(), 0)
        source_scroll.setValue(source_scroll.maximum() // 2)
        window.open_details_window()
        self.app.processEvents()
        details = window._details_window
        self.assertIsNotNone(details)
        self.assertFalse(details.isFullScreen())
        self.assertGreaterEqual(details.minimumWidth(), 560)
        self.assertEqual(details.editor.toPlainText(), window.operation_text.toPlainText())
        self.assertFalse(details.follow.isChecked())
        self.assertGreater(details.editor.verticalScrollBar().value(), 0)
        window.open_details_window()
        self.assertIs(window._details_window, details)

        details.mode.setCurrentText("JSON")
        self.assertEqual(window.detail_mode.currentText(), "JSON")
        window.append_report("status", {"action": "status", "complete": True})
        self.assertEqual(details.editor.toPlainText(), window.operation_text.toPlainText())
        self.assertLess(details.editor.verticalScrollBar().value(),
                        details.editor.verticalScrollBar().maximum())
        details.follow.setChecked(True)
        window.append_detail("Latest event")
        self.assertEqual(details.editor.verticalScrollBar().value(),
                         details.editor.verticalScrollBar().maximum())
        window.apply_theme(True)
        self.assertEqual(details.mode.property("darkMode"), True)
        details.close()
        self.assertIsNone(window._details_window)
        self.assertTrue(window.isVisible())

    def test_details_window_copy_and_save_displayed_mode(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        window = self.window
        window.append_report("status", {"action": "status", "complete": True})
        window.open_details_window()
        self.app.processEvents()
        details = window._details_window
        details.mode.setCurrentText("JSON")
        details.copy_text()
        self.assertEqual(self.app.clipboard().text(), details.editor.toPlainText())
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "details.txt"
            with patch("gui.window.QFileDialog.getSaveFileName", return_value=(str(target), "")):
                details.save_text()
            self.assertEqual(target.read_text(), details.editor.toPlainText())
        details.close()
