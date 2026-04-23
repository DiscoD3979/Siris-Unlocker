import random
import string
import os
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QStackedWidget, QSystemTrayIcon, QMenu, QApplication
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon, QAction

from ui.pages.menu_page import MenuPage
from ui.pages.task_manager_page import TaskManagerPage
from ui.pages.startup_page import StartupPage
from ui.pages.unlock_page import UnlockPage
from ui.pages.extra_page import ExtraPage
from ui.pages.quarantine_page import QuarantinePage

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        # ... (ваш код генерации заголовка, иконки, минимального размера) ...
        title_characters = string.ascii_letters + string.digits + "!@#$%^&*()_-+=[]{};:,.<>?/`~"
        random_title = ''.join(random.choices(title_characters, k=12))
        self.setWindowTitle(random_title)

        icon_path = os.path.join(os.path.dirname(__file__), '..', 'icon.ico')
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self.setMinimumSize(900, 600)

        # ---------- Остальная инициализация интерфейса (без изменений) ----------
        central_widget = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(10, 10, 10, 10)

        top_layout = QHBoxLayout()
        self.back_button = QPushButton("← Назад")
        self.back_button.setObjectName("backButton")
        self.back_button.setVisible(False)
        self.back_button.clicked.connect(self.go_to_menu)
        top_layout.addWidget(self.back_button, alignment=Qt.AlignLeft)
        top_layout.addStretch()
        main_layout.addLayout(top_layout)

        self.stacked_widget = QStackedWidget()

        self.menu_page = MenuPage(self)
        self.task_manager_page = TaskManagerPage()
        self.startup_page = StartupPage()
        self.unlock_page = UnlockPage()
        self.extra_page = ExtraPage()
        self.quarantine_page = QuarantinePage()
        self.extra_page.set_parent_window(self)

        self.stacked_widget.addWidget(self.menu_page)           # 0
        self.stacked_widget.addWidget(self.task_manager_page)   # 1
        self.stacked_widget.addWidget(self.startup_page)        # 2
        self.stacked_widget.addWidget(self.unlock_page)         # 3
        self.stacked_widget.addWidget(self.extra_page)          # 4
        self.stacked_widget.addWidget(self.quarantine_page)     # 5

        main_layout.addWidget(self.stacked_widget)
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        self.setWindowFlag(Qt.WindowStaysOnTopHint, True)

        # ---------- ДОБАВЛЯЕМ СИСТЕМНЫЙ ТРЕЙ ----------
        self.tray_icon = None
        self.setup_tray()

    def setup_tray(self):
        """Создаёт иконку в трее с контекстным меню."""
        icon_path = os.path.join(os.path.dirname(__file__), '..', 'icon.ico')
        if not os.path.exists(icon_path):
            # Если иконки нет – создаём пустую (но лучше добавить)
            icon = QIcon()
        else:
            icon = QIcon(icon_path)

        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(icon)
        self.tray_icon.setToolTip("SirisUnlocker")

        # Меню трея
        tray_menu = QMenu()

        show_action = QAction("Показать окно", self)
        show_action.triggered.connect(self.show_window_from_tray)

        exit_action = QAction("Выход", self)
        exit_action.triggered.connect(self.exit_application)

        tray_menu.addAction(show_action)
        tray_menu.addSeparator()
        tray_menu.addAction(exit_action)

        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()

        # По двойному клику по иконке показываем окно
        self.tray_icon.activated.connect(self.on_tray_activated)

    def on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self.show_window_from_tray()

    def show_window_from_tray(self):
        """Показывает и активирует главное окно."""
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def exit_application(self):
        """Полное завершение приложения."""
        self.tray_icon.hide()
        QApplication.quit()

    def closeEvent(self, event):
        """При нажатии на крестик – скрываем окно в трей, а не закрываем."""
        event.ignore()
        self.hide()
        self.tray_icon.showMessage(
            "SirisUnlocker",
            "Приложение свернуто в трей. Нажмите Alt+` для быстрого показа.",
            QSystemTrayIcon.Information,
            2000
        )

    # ---------- Остальные методы (go_to_menu, open_xxx) без изменений ----------
    def go_to_menu(self):
        self.stacked_widget.setCurrentIndex(0)
        self.back_button.setVisible(False)

    def open_task_manager(self):
        self.stacked_widget.setCurrentIndex(1)
        self.back_button.setVisible(True)

    def open_startup(self):
        self.stacked_widget.setCurrentIndex(2)
        self.back_button.setVisible(True)

    def open_unlock(self):
        self.stacked_widget.setCurrentIndex(3)
        self.back_button.setVisible(True)

    def open_extra(self):
        self.stacked_widget.setCurrentIndex(4)
        self.back_button.setVisible(True)

    def open_quarantine(self):
        self.quarantine_page.refresh()
        self.stacked_widget.setCurrentIndex(5)
        self.back_button.setVisible(True)