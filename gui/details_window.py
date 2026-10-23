"""Resizable, read-only view of the main window's operation details."""

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QCheckBox, QHBoxLayout, QLabel, QListView, QMainWindow, QPlainTextEdit,
    QPushButton, QStyleFactory, QToolButton, QVBoxLayout, QWidget,
)

from . import theme


class DetailsWindow(QMainWindow):
    def __init__(self, source):
        super().__init__(source, Qt.WindowType.Window)
        self.source = source
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle("T7 · Operation details")
        self.resize(900, 600)
        self.setMinimumSize(560, 360)

        central = QWidget(self)
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        toolbar = QHBoxLayout()
        toolbar.addWidget(QLabel("Operation details"))
        toolbar.addStretch()
        self.mode = theme.ScenarioCombo()
        self.mode.setObjectName("detailMode")
        self.mode.setAccessibleName("Operation details window display mode")
        self.popup_style = theme.ComboListStyle(QStyleFactory.create("Fusion"))
        self.mode.setStyle(self.popup_style)
        self.mode.setView(QListView())
        self.popup_style.setParent(self.mode)
        self.mode.addItems(("Summary", "JSON"))
        self.mode.setCurrentIndex(source.detail_mode.currentIndex())
        toolbar.addWidget(self.mode)
        self.follow = QCheckBox("Follow new results")
        self.follow.setAccessibleName("Follow new operation details")
        toolbar.addWidget(self.follow)
        self.copy_button = QToolButton()
        self.copy_button.setToolTip("Copy displayed details")
        self.copy_button.setAccessibleName("Copy operation details window")
        self.copy_button.clicked.connect(self.copy_text)
        toolbar.addWidget(self.copy_button)
        self.save_button = QToolButton()
        self.save_button.setToolTip("Save displayed details as text")
        self.save_button.setAccessibleName("Save operation details window")
        self.save_button.clicked.connect(self.save_text)
        toolbar.addWidget(self.save_button)
        self.exit_button = QPushButton("Close window")
        self.exit_button.clicked.connect(self.close)
        toolbar.addWidget(self.exit_button)
        layout.addLayout(toolbar)

        self.editor = QPlainTextEdit()
        self.editor.setReadOnly(True)
        self.editor.setAccessibleName("Operation details window")
        layout.addWidget(self.editor, 1)

        QShortcut(QKeySequence("Escape"), self, activated=self.close)
        self.mode.currentIndexChanged.connect(source.detail_mode.setCurrentIndex)
        source.detail_mode.currentIndexChanged.connect(self.mode.setCurrentIndex)
        source.details_updated.connect(self.refresh)

        original = source.operation_text.verticalScrollBar()
        original_max = original.maximum()
        self.initial_ratio = original.value() / max(1, original_max)
        self.follow.setChecked(original.value() >= original_max)
        self.refresh()
        QTimer.singleShot(0, self.restore_initial_scroll)
        self.apply_theme(source.is_dark)

    def restore_initial_scroll(self):
        if not self.follow.isChecked():
            target = self.editor.verticalScrollBar()
            target.setValue(round(self.initial_ratio * target.maximum()))

    def apply_theme(self, dark):
        self.setStyleSheet(theme.stylesheet(dark))
        self.mode.setProperty("darkMode", dark)
        color = "#e3eaf3" if dark else "#243e58"
        self.copy_button.setIcon(theme.detail_icon("copy", color))
        self.save_button.setIcon(theme.detail_icon("save", color))

    def refresh(self):
        scroll = self.editor.verticalScrollBar()
        position = scroll.value()
        self.editor.setPlainText(self.source.operation_text.toPlainText())
        scroll.setValue(scroll.maximum() if self.follow.isChecked() else position)

    def copy_text(self):
        self.source.copy_text(self.editor.toPlainText(), self)

    def save_text(self):
        self.source.export_detail_text(self.editor.toPlainText(), self)

    def closeEvent(self, event):
        source_scroll = self.source.operation_text.verticalScrollBar()
        own_scroll = self.editor.verticalScrollBar()
        source_scroll.setValue(round(own_scroll.value() / max(1, own_scroll.maximum())
                                     * source_scroll.maximum()))
        self.source._details_window = None
        event.accept()
