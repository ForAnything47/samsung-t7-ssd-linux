"""Light/dark palette, toolbar icons and theme-independent popup rendering."""
from PySide6.QtCore import Qt, QRectF, QPointF
from PySide6.QtGui import QIcon, QPixmap, QPainter, QPen, QColor, QPolygonF
from PySide6.QtWidgets import QComboBox, QProxyStyle, QStyle, QFrame


def detail_icon(kind, color="#243e58"):
    """Theme-independent dark strokes for the explicitly light detail toolbar."""
    pixmap = QPixmap(48, 48)
    pixmap.setDevicePixelRatio(2)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(QPen(QColor(color), 1.7))
    if kind == "copy":
        painter.drawRoundedRect(QRectF(8, 8, 12, 13), 1.5, 1.5)
        painter.drawLine(5, 16, 4, 16)
        painter.drawLine(4, 16, 4, 3)
        painter.drawLine(4, 3, 16, 3)
        painter.drawLine(16, 3, 16, 5)
    else:
        painter.drawRoundedRect(QRectF(3, 3, 18, 18), 1.5, 1.5)
        painter.drawRect(QRectF(7, 3, 10, 6))
        painter.drawRect(QRectF(7, 14, 10, 7))
    painter.end()
    return QIcon(pixmap)


class ComboListStyle(QProxyStyle):
    """Use a list popup, not a platform menu with top/bottom scrollers."""
    def styleHint(self, hint, option=None, widget=None, returnData=None):
        if hint == QStyle.StyleHint.SH_ComboBox_Popup:
            return 0
        return super().styleHint(hint, option, widget, returnData)


class ScenarioCombo(QComboBox):
    def paintEvent(self, event):
        super().paintEvent(event)
        if self.objectName() in ("detailMode", "logDate"):
            # Draw the arrow inside the single rounded border. Native styles
            # otherwise paint a separate rectangular button over its edge.
            painter = QPainter(self)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#b8c9dc" if self.property("darkMode") is True else "#60758b"))
            x, y = self.width() - 16, self.height() / 2
            painter.drawPolygon(QPolygonF((QPointF(x - 4, y - 2),
                                           QPointF(x + 4, y - 2),
                                           QPointF(x, y + 2))))

    def showPopup(self):
        # The popup is a separate window: styling the item view alone leaves
        # the native container/scroller background visible on KDE dark themes.
        popup = self.view().window()
        popup.setObjectName("scenarioPopup")
        popup.setAutoFillBackground(True)
        dark = self.property("darkMode") is True
        background, foreground, border = ("#202c3b", "#e3eaf3", "#46566b") if dark else ("#ffffff", "#182b40", "#ccd5df")
        popup.setStyleSheet(f"QWidget {{ background-color: {background}; color: {foreground}; }} "
                            f"QFrame#scenarioPopup {{ border: 1px solid {border}; padding: 0px; margin: 0px; }}")
        if isinstance(popup, QFrame):
            popup.setFrameShape(QFrame.Shape.NoFrame)
        if popup.layout() is not None:
            popup.layout().setContentsMargins(0, 0, 0, 0)
            popup.layout().setSpacing(0)
        super().showPopup()


LIGHT_STYLESHEET = """
            QWidget { background: #f4f6f9; color: #182b40; font-size: 14px; }
            QLabel#title { font-size: 30px; font-weight: 700; }
            QLabel#heading { font-size: 23px; font-weight: 600; }
            QLabel#banner { background: #e2edf9; color: #23507c; padding: 14px; border-radius: 8px; }
            QListWidget, QLineEdit, QComboBox { background: white; border: 1px solid #ccd5df; border-radius: 6px; padding: 10px; }
            QComboBox#detailMode, QComboBox#logDate { padding: 8px 32px 8px 10px; }
            QComboBox#detailMode { min-width: 100px; }
            QComboBox#detailMode::drop-down, QComboBox#logDate::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 24px;
                margin: 2px 2px 2px 0px;
                border: none;
                background: transparent;
            }
            QComboBox QAbstractItemView { background: #ffffff; color: #182b40; selection-background-color: #dceafa; selection-color: #182b40; border: 1px solid #ccd5df; padding: 0px; outline: 0; }
            QComboBox QAbstractItemView::item { padding: 8px; }
            QToolButton { background: #e4e9ef; border: 1px solid #bdc9d6; border-radius: 5px; padding: 6px; }
            QToolButton:hover { background: #d4e3f3; }
            QToolButton:pressed { background: #bed4ec; }
            QPlainTextEdit { background: white; border: 1px solid #ccd5df; padding: 10px; }
            QListWidget::item { padding: 12px 4px; }
            QListWidget::item:selected { background: #dceafa; color: #182b40; }
            QPushButton { background: #e4e9ef; border: none; padding: 12px; border-radius: 6px; }
            QPushButton#primary { background: #245f9e; color: white; }
            QPushButton:disabled, QPushButton#primary:disabled { background: #e0e4e9; color: #7b8795; }
            QProgressBar { border: none; background: #e0e7ef; max-height: 6px; }
            QProgressBar::chunk { background: #245f9e; }
        """


def stylesheet(dark):
    """Return the selected palette without changing widget or operation state."""
    stylesheet = LIGHT_STYLESHEET
    if dark:
        colors = {
            "#f4f6f9": "#151e2a", "#182b40": "#e3eaf3",
            "#e2edf9": "#243c56", "#23507c": "#c2dfff",
            "#ffffff": "#202c3b", "#ccd5df": "#46566b",
            "#dceafa": "#334f70", "#e4e9ef": "#2b3a4d",
            "#bdc9d6": "#52647b", "#d4e3f3": "#3b526e",
            "#bed4ec": "#496584", "#245f9e": "#286bb0",
            "#e0e4e9": "#283344", "#7b8795": "#a3adba",
            "#e0e7ef": "#334155",
        }
        for light, replacement in colors.items():
            stylesheet = stylesheet.replace(light, replacement)
        stylesheet = stylesheet.replace("background: white", "background: #202c3b")
    return stylesheet
