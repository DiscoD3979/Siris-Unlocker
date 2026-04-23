import sys
import ctypes
import os
import time
from PySide6.QtWidgets import QApplication, QSplashScreen
from PySide6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QPixmap, QPainter, QColor, QFont, QLinearGradient, QBrush

# ------------------------------------------------------------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    executable = sys.executable
    params = f'"{sys.argv[0]}" ' + ' '.join(sys.argv[1:])
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, params, None, 1)
    except Exception as e:
        ctypes.windll.user32.MessageBoxW(None, f"Не удалось запросить права администратора: {e}", "Ошибка", 0)
        sys.exit(1)

# ------------------------------------------------------------
class SplashScreen(QSplashScreen):
    def __init__(self):
        pixmap = QPixmap(500, 300)
        pixmap.fill(Qt.transparent)
        super().__init__(pixmap)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.progress = 0
        self.message = "Старт..."
        self.animation = QPropertyAnimation(self, b"windowOpacity")
        self.animation.setDuration(300)
        self.animation.setStartValue(0.0)
        self.animation.setEndValue(1.0)
        self.animation.setEasingCurve(QEasingCurve.OutCubic)

    def showEvent(self, event):
        super().showEvent(event)
        self.animation.start()

    def set_progress(self, value, message=""):
        self.progress = value
        self.message = message
        self.repaint()
        # Небольшая задержка, чтобы пользователь успел увидеть этап
        QApplication.processEvents()
        time.sleep(0.15)

    def drawContents(self, painter):
        painter.setRenderHint(QPainter.Antialiasing)

        # Полупрозрачный фон с градиентом (как в старом дизайне)
        gradient = QLinearGradient(0, 0, 0, self.height())
        gradient.setColorAt(0, QColor(30, 30, 30, 200))
        gradient.setColorAt(1, QColor(20, 20, 20, 200))
        painter.fillRect(self.rect(), QBrush(gradient))

        # Заголовок с символами
        painter.setPen(QColor(255, 255, 255))
        title_font = QFont("Segoe UI", 22, QFont.Bold)
        painter.setFont(title_font)
        painter.drawText(self.rect().adjusted(0, 50, 0, -100), Qt.AlignCenter, "⋆༺ Siris & Unlocker ༻⋆")

        # Сообщение
        painter.setPen(QColor(200, 200, 200))
        msg_font = QFont("Segoe UI", 10)
        painter.setFont(msg_font)
        painter.drawText(self.rect().adjusted(0, 130, 0, -70), Qt.AlignCenter, self.message)

        # Прогресс-бар
        bar_width, bar_height = 300, 6
        bar_x = (self.width() - bar_width) // 2
        bar_y = self.height() - 50

        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(60, 60, 60))
        painter.drawRoundedRect(bar_x, bar_y, bar_width, bar_height, 3, 3)

        fill_width = int(bar_width * self.progress / 100)
        if fill_width > 0:
            painter.setBrush(QColor("#430261"))
            painter.drawRoundedRect(bar_x, bar_y, fill_width, bar_height, 3, 3)

        # Процент выполнения
        painter.setPen(QColor(180, 180, 180))
        percent_font = QFont("Segoe UI", 8)
        painter.setFont(percent_font)
        painter.drawText(bar_x + bar_width + 10, bar_y + bar_height, f"{self.progress}%")

        # Версия
        painter.setPen(QColor(150, 150, 150))
        ver_font = QFont("Segoe UI", 8)
        painter.setFont(ver_font)
        painter.drawText(self.rect().adjusted(0, -20, 0, -5), Qt.AlignHCenter | Qt.AlignBottom, "версия 3.0.7")

# ------------------------------------------------------------
def main():
    if not is_admin():
        run_as_admin()
        sys.exit(0)

    app = QApplication(sys.argv)
    splash = SplashScreen()
    splash.show()
    app.processEvents()

    steps = [
        ("Загрузка стилей...", lambda: load_styles(app)),
        ("Импорт главного окна...", lambda: import_main_window()),
        ("Инициализация ресурсов...", lambda: init_resources()),
        ("Запуск...", lambda: create_main_window())
    ]

    total_steps = len(steps)
    for i, (msg, func) in enumerate(steps):
        func()
        splash.set_progress(int((i + 1) / total_steps * 100), msg)
        app.processEvents()

    from ui.main_window import MainWindow
    window = MainWindow()

    splash.finish(window)
    window.show()
    sys.exit(app.exec())

# ------------------------------------------------------------
def load_styles(app):
    style_path = os.path.join(os.path.dirname(__file__), "ui", "styles.qss")
    if os.path.exists(style_path):
        with open(style_path, "r", encoding="utf-8") as f:
            app.setStyleSheet(f.read())

def import_main_window():
    import ui.main_window

def init_resources():
    pass

def create_main_window():
    pass

# ------------------------------------------------------------
if __name__ == "__main__":
    main()