"""Per-user GUI preferences; never store passwords or authorization tokens."""
from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QDialog, QDialogButtonBox, QFormLayout, QListView, QStyleFactory, QLabel, QVBoxLayout

from PySide6.QtGui import QIcon
from . import theme as appearance

DURATIONS = (0, 60, 300, 900)


def store():
    return QSettings('ForAnything47', 'T7PasswordManager')


def load():
    settings = store()
    theme = settings.value('theme', 'light')
    try:
        seconds = int(settings.value('authorization_seconds', 0))
    except (ValueError, TypeError):
        seconds = 0
    return theme if theme in ('light', 'dark') else 'light', seconds if seconds in DURATIONS else 0


def save(theme, seconds):
    settings = store()
    settings.setValue('theme', theme)
    settings.setValue('authorization_seconds', seconds)
    settings.sync()
    return settings.status() == QSettings.Status.NoError


class SettingsDialog(QDialog):
    def __init__(self, parent, theme, seconds, apply_callback=None):
        super().__init__(parent)
        self.setWindowTitle('Settings')
        self.apply_callback = apply_callback
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.theme = self.make_combo()
        self.theme.addItems(['Light', 'Dark'])
        self.theme.setCurrentIndex(theme == 'dark')
        self.duration = self.make_combo()
        for label, value in zip(('Do not retain', '1 minute', '5 minutes', '15 minutes'), DURATIONS):
            self.duration.addItem(label, value)
        self.duration.setCurrentIndex(DURATIONS.index(seconds))
        form.addRow('Theme', self.theme)
        form.addRow('Administrator authorization', self.duration)
        layout.addLayout(form)
        note = QLabel('Applies to this app and the same selected SSD only. The timer starts after authorization, not after each operation. Closing the app ends the session. SSD passwords are still requested and are not saved. A running operation is allowed to finish after expiry.')
        note.setWordWrap(True)
        layout.addWidget(note)
        self.error = QLabel()
        self.error.setWordWrap(True)
        layout.addWidget(self.error)
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Apply | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.accepted.connect(lambda: self.apply_selection(close=True))
        self.buttons.button(QDialogButtonBox.StandardButton.Apply).clicked.connect(self.apply_selection)
        self.buttons.rejected.connect(self.reject)
        # Native theme icons may be white on our explicitly light palette.
        for button in self.buttons.buttons():
            button.setIcon(QIcon())
        layout.addWidget(self.buttons)
        self.update_palette(theme == 'dark')
        self.resize(480, 260)

    def make_combo(self):
        combo = appearance.ScenarioCombo()
        style = appearance.ComboListStyle(QStyleFactory.create('Fusion'))
        style.setParent(combo)
        combo.setStyle(style)
        combo.setView(QListView())
        return combo

    def update_palette(self, dark):
        self.setStyleSheet(appearance.stylesheet(dark))
        for combo in (self.theme, self.duration):
            combo.setProperty('darkMode', dark)

    def apply_selection(self, checked=False, *, close=False):
        selected = 'dark' if self.theme.currentIndex() == 1 else 'light'
        seconds = self.duration.currentData()
        if not save(selected, seconds):
            self.error.setText('Could not save settings. Check your configuration directory.')
            return
        if self.apply_callback:
            self.apply_callback(selected, seconds)
        self.update_palette(selected == 'dark')
        self.error.setText('Settings applied and saved.')
        if close:
            self.accept()
