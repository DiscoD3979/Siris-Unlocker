from PySide6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLabel, QHBoxLayout, QMessageBox
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QIcon
import os
import webbrowser

VERSION = "3.0.7"
CREATION_DATE = "10.03.2026"
UPDATE_DATE = "22.04.2026"

class MenuPage(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)

        main_layout.addStretch(1)

        center_layout = QVBoxLayout()
        center_layout.setAlignment(Qt.AlignCenter)
        center_layout.setSpacing(25)

        title = QLabel("⋆༺ Siris & Unlocker ༻⋆")
        title.setObjectName("mainTitle")
        title.setAlignment(Qt.AlignCenter)
        center_layout.addWidget(title)

        # Базовая директория для иконок
        icons_dir = os.path.join(os.path.dirname(__file__), '..', 'icons')

        # Кнопка 1: Диспетчер задач
        btn_task = self._create_button("Диспетчер задач", self.main_window.open_task_manager,
                                       os.path.join(icons_dir, "arrow-right.svg"))
        center_layout.addWidget(btn_task)

        # Кнопка 2: Автозагрузки
        btn_startup = self._create_button("Автозагрузки", self.main_window.open_startup,
                                          os.path.join(icons_dir, "settings.svg"))
        center_layout.addWidget(btn_startup)

        # Кнопка 3: Снять ограничения
        btn_unlock = self._create_button("Снять ограничения", self.main_window.open_unlock,
                                         os.path.join(icons_dir, "unlock.svg"))
        center_layout.addWidget(btn_unlock)

        # Кнопка 4: Прочие функции
        btn_extra = self._create_button("Прочие функции", self.main_window.open_extra,
                                        os.path.join(icons_dir, "tools.svg"))
        center_layout.addWidget(btn_extra)

        # Кнопка 5: Карантин
        btn_quarantine = self._create_button("Карантин", self.main_window.open_quarantine,
                                             os.path.join(icons_dir, "quarantine.svg"))
        center_layout.addWidget(btn_quarantine)

        main_layout.addLayout(center_layout)
        main_layout.addStretch(1)

        bottom_layout = QHBoxLayout()
        bottom_layout.setContentsMargins(10, 10, 10, 10)

        self.about_button = QPushButton("О программе")
        self.about_button.setObjectName("aboutButton")
        self.about_button.setFixedSize(90, 28)
        self.about_button.clicked.connect(self.show_about)
        bottom_layout.addWidget(self.about_button, alignment=Qt.AlignLeft)

        bottom_layout.addStretch()

        by_label = QLabel("By DiscoD3979")
        by_label.setObjectName("creditLabel")
        by_label.mouseDoubleClickEvent = self.open_github
        bottom_layout.addWidget(by_label, alignment=Qt.AlignRight)

        main_layout.addLayout(bottom_layout)
        self.setLayout(main_layout)

    def open_github(self, event):
        webbrowser.open("https://github.com/DiscoD3979")

    def _create_button(self, text, slot, icon_path=None):
        btn = QPushButton(text)
        btn.setObjectName("mainMenuButton")
        btn.setMinimumWidth(250)
        if icon_path and os.path.exists(icon_path):
            btn.setIcon(QIcon(icon_path))
            btn.setIconSize(QSize(24, 24))
        btn.clicked.connect(slot)
        return btn

    def show_about(self):
        about_text = (
            f"<b>SirisUnlocker</b><br><br>"
            f"<b>Создатель:</b> DiscoD3979<br>"
            f"<b>Дата создания:</b> {CREATION_DATE}<br>"
            f"<b>Дата обновления:</b> {UPDATE_DATE}<br>"
            f"<b>Версия:</b> {VERSION}<br>"
            f"<b>Описание:</b> Утилита для управления системой и снятия ограничений.<br>"
            f"<b>Авторские права:</b> © 2026 DiscoD3979"
        )
        QMessageBox.about(self, "О программе", about_text)