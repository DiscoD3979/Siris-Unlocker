import random
import string
import os
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QStackedWidget
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon

from ui.pages.menu_page import MenuPage
from ui.pages.task_manager_page import TaskManagerPage
from ui.pages.startup_page import StartupPage
from ui.pages.unlock_page import UnlockPage
from ui.pages.extra_page import ExtraPage
from ui.pages.quarantine_page import QuarantinePage


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        title_characters = string.ascii_letters + string.digits + "!@#$%^&*()_-+=[]{};:,.<>?/`~"
        random_title = ''.join(random.choices(title_characters, k=12))
        self.setWindowTitle(random_title)

        icon_path = os.path.join(os.path.dirname(__file__), '..', 'icon.ico')
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self.setMinimumSize(800, 500)

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
        self.setWindowFlags(self.windowFlags() | Qt.WindowStaysOnTopHint)

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