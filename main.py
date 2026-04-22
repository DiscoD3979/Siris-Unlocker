import sys
import ctypes
import os
from PySide6.QtWidgets import QApplication, QSplashScreen
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QPixmap, QPainter, QColor, QFont

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

    def set_progress(self, value, message=""):
        self.progress = value
        self.message = message
        self.repaint()

    def drawContents(self, painter):
        painter.setRenderHint(QPainter.Antialiasing)

        # Фон (чуть более прозрачный)
        painter.fillRect(self.rect(), QColor(30, 30, 30, 200))

        painter.setPen(QColor(255, 255, 255))
        painter.setFont(QFont("Segoe UI", 20, QFont.Bold))

        # Заголовок
        painter.drawText(self.rect().adjusted(0, 50, 0, -100), Qt.AlignCenter, "⋆༺ Siris & Unlocker ༻⋆")

        # Сообщение
        painter.setFont(QFont("Segoe UI", 10))
        painter.drawText(self.rect().adjusted(0, 120, 0, -80), Qt.AlignCenter, self.message)

        # Прогресс-бар
        bar_width, bar_height = 300, 25
        bar_x = (self.width() - bar_width) // 2
        bar_y = self.height() - 80

        painter.setPen(QColor(80, 80, 80))
        painter.drawRect(bar_x, bar_y, bar_width, bar_height)

        fill_width = int(bar_width * self.progress / 100)
        if fill_width > 0:
            painter.fillRect(bar_x + 1, bar_y + 1, fill_width - 2, bar_height - 2, QColor(90, 150, 90))

        # Версия (поднята выше)
        painter.setPen(QColor(150, 150, 150))
        painter.setFont(QFont("Segoe UI", 9))
        painter.drawText(self.rect().adjusted(0, -30, 0, -5), Qt.AlignHCenter | Qt.AlignBottom, "версия 2.5.3")

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