from PySide6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLabel, QHBoxLayout, QMessageBox
from PySide6.QtCore import Qt

VERSION = "2.5.3"
CREATION_DATE = "10.03.2026"
UPDATE_DATE = "19.04.2026"


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

        btn_task = QPushButton("Диспетчер задач")
        btn_task.setObjectName("mainMenuButton")
        btn_task.clicked.connect(self.main_window.open_task_manager)
        btn_task.setMinimumWidth(250)
        center_layout.addWidget(btn_task)

        btn_startup = QPushButton("Автозагрузки")
        btn_startup.setObjectName("mainMenuButton")
        btn_startup.clicked.connect(self.main_window.open_startup)
        btn_startup.setMinimumWidth(250)
        center_layout.addWidget(btn_startup)

        btn_unlock = QPushButton("Снять ограничения")
        btn_unlock.setObjectName("mainMenuButton")
        btn_unlock.clicked.connect(self.main_window.open_unlock)
        btn_unlock.setMinimumWidth(250)
        center_layout.addWidget(btn_unlock)

        btn_extra = QPushButton("Прочие функции")
        btn_extra.setObjectName("mainMenuButton")
        btn_extra.clicked.connect(self.main_window.open_extra)
        btn_extra.setMinimumWidth(250)
        center_layout.addWidget(btn_extra)

        btn_quarantine = QPushButton("Карантин")
        btn_quarantine.setObjectName("mainMenuButton")
        btn_quarantine.clicked.connect(self.main_window.open_quarantine)
        btn_quarantine.setMinimumWidth(250)
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
        bottom_layout.addWidget(by_label, alignment=Qt.AlignRight)

        main_layout.addLayout(bottom_layout)
        self.setLayout(main_layout)

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