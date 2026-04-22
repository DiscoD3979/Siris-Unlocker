import winreg
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QCheckBox, QLabel, QTabWidget,
    QAbstractItemView, QMessageBox
)
from PySide6.QtCore import Qt, QThread, Signal

# --- список всех ограничений реестра ---
RESTRICTIONS = [
    ("DisableTaskMgr", "Блокировка диспетчера задач", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr"),
    ("DisableRegistryTools", "Блокировка редактора реестра", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableRegistryTools"),
    ("DisableCMD", "Блокировка командной строки", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableCMD"),
    ("RestrictToPermittedSnapins", "Блокировка MMC", winreg.HKEY_CURRENT_USER,
     r"Software\Policies\Microsoft\MMC", "RestrictToPermittedSnapins"),
    ("NoControlPanel", "Блокировка панели управления и параметров Windows", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoControlPanel"),
    ("NoRun", "Блокировка окна 'Выполнить'", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoRun"),
    ("NoViewOnDrive", "Блокировка доступа к диску из проводника", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoViewOnDrive"),
    ("NoDrives", "Скрытие диска из проводника", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDrives"),
    ("NoFind", "Блокировка поиска в пуске", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoFind"),
    ("NoViewContextMenu", "Блокировка контекстного меню", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoViewContextMenu"),
    ("NoFolderOptions", "Блокировка настройки папок", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoFolderOptions"),
    ("NoSecurityTab", "Блокировка вкладки 'Безопасность'", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoSecurityTab"),
    ("NoFileMenu", "Скрытие меню 'Файл'", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoFileMenu"),
    ("NoClose", "Блокировка выключения компьютера через 'Пуск'", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoClose"),
    ("NoCommonGroups", "Скрытие разделов из меню 'Пуск'", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoCommonGroups"),
    ("StartMenuLogOff", "Скрытие выхода из системы в меню 'Пуск'", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "StartMenuLogOff"),
    ("NoChangingWallPaper", "Запрет на смену обоев", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop", "NoChangingWallPaper"),
    ("NoWinKeys", "Отключение горячих клавиш Windows", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoWinKeys"),
    ("NoSetTaskbar", "Запрет изменений панели задач и меню 'Пуск'", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoSetTaskbar"),
    ("DisableLockWorkstation", "Предотвращение блокировки системы", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableLockWorkstation"),
    ("DisableChangePassword", "Запрет на смену пароля", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableChangePassword"),
    ("NoTrayContextMenu", "Запрет контекстного меню на панели задач", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoTrayContextMenu"),
    ("DenyUsersFromMachGP", "Пользователи не могут обновлять политику компьютера", winreg.HKEY_LOCAL_MACHINE,
     r"Software\Policies\Microsoft\Windows\System", "DenyUsersFromMachGP"),
    ("HidePowerOptions", "Скрытие команд питания из меню 'Пуск'", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "HidePowerOptions"),
    ("DisableContextMenusInStart", "Запрет контекстных меню в 'Пуск'", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "DisableContextMenusInStart"),
    ("DisableSR", "Отключение восстановления системы", winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore", "DisableSR"),
    ("DisableConfig", "Отключение настройки восстановления системы", winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore", "DisableConfig"),
    ("NoLogoff", "Блокировка выхода из системы", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoLogoff"),
]

# --- вспомогательные функции работы с реестром ---
def is_restriction_active(hive, path, value_name):
    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        try:
            winreg.QueryValueEx(key, value_name)
            winreg.CloseKey(key)
            return True
        except FileNotFoundError:
            winreg.CloseKey(key)
            return False
    except FileNotFoundError:
        return False
    except Exception:
        return False

def remove_registry_value(hive, path, value_name):
    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
        try:
            winreg.DeleteValue(key, value_name)
            winreg.CloseKey(key)
            return True
        except FileNotFoundError:
            winreg.CloseKey(key)
            return True
    except Exception:
        return False

# --- поток сканирования ---
class ScanThread(QThread):
    finished = Signal(list)

    def run(self):
        found = []
        for key, desc, hive, path, value in RESTRICTIONS:
            if is_restriction_active(hive, path, value):
                found.append({
                    'name': key,
                    'desc': desc,
                    'path': f"{'HKCU' if hive == winreg.HKEY_CURRENT_USER else 'HKLM'}\\{path}\\{value}"
                })
        self.finished.emit(found)

# --- поток разблокировки (по одному) ---
class UnlockThread(QThread):
    step_unlocked = Signal(int, dict)  # индекс в списке, словарь ограничения
    finished = Signal(int)             # количество успешно разблокированных

    def __init__(self, restrictions_to_unlock):
        super().__init__()
        self.restrictions_to_unlock = restrictions_to_unlock  # список словарей

    def run(self):
        success_count = 0
        for idx, res in enumerate(self.restrictions_to_unlock):
            # найти соответствующий элемент в RESTRICTIONS по имени
            for key, desc, hive, path, value in RESTRICTIONS:
                if key == res['name']:
                    if remove_registry_value(hive, path, value):
                        success_count += 1
                        self.step_unlocked.emit(idx, res)
                    break
        self.finished.emit(success_count)

# --- вкладка сканирования ---
class ScanTab(QWidget):
    def __init__(self):
        super().__init__()
        self.found_restrictions = []
        self.unlock_thread = None
        self.scan_thread = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Ограничение", "Описание", "Путь"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

        bottom_layout = QHBoxLayout()
        self.auto_check = QCheckBox("Автоматическая разблокировка ограничений")
        bottom_layout.addWidget(self.auto_check)
        bottom_layout.addStretch()
        self.scan_button = QPushButton("Начать сканирование")
        self.scan_button.setObjectName("scanButton")
        self.scan_button.clicked.connect(self.start_scan)
        bottom_layout.addWidget(self.scan_button)
        layout.addLayout(bottom_layout)

        self.status_label = QLabel("Состояние: Ожидание действий")
        layout.addWidget(self.status_label)

        self.setLayout(layout)
        self.table.setRowCount(0)

    def start_scan(self):
        self.scan_button.setEnabled(False)
        self.status_label.setText("Состояние: Сканирование...")
        self.table.setRowCount(0)
        self.found_restrictions = []
        self.scan_thread = ScanThread()
        self.scan_thread.finished.connect(self.on_scan_finished)
        self.scan_thread.start()

    def on_scan_finished(self, found):
        self.found_restrictions = found
        self.table.setRowCount(len(found))
        for row, res in enumerate(found):
            self.table.setItem(row, 0, QTableWidgetItem(res['name']))
            self.table.setItem(row, 1, QTableWidgetItem(res['desc']))
            self.table.setItem(row, 2, QTableWidgetItem(res['path']))
        self.table.resizeColumnsToContents()
        self.table.setColumnWidth(0, 150)
        self.table.setColumnWidth(1, 250)
        self.table.horizontalHeader().setStretchLastSection(True)

        if found:
            self.status_label.setText(f"Состояние: Найдено {len(found)} ограничений.")
            if self.auto_check.isChecked():
                self.start_auto_unlock()
            else:
                self.scan_button.setEnabled(True)
        else:
            self.status_label.setText("Состояние: Ограничений не найдено.")
            self.scan_button.setEnabled(True)

    def start_auto_unlock(self):
        self.status_label.setText("Состояние: Автоматическая разблокировка...")
        self.scan_button.setEnabled(False)
        self.unlock_thread = UnlockThread(self.found_restrictions)
        self.unlock_thread.step_unlocked.connect(self.on_step_unlocked)
        self.unlock_thread.finished.connect(self.on_unlock_finished)
        self.unlock_thread.start()

    def on_step_unlocked(self, idx, res):
        # удалить строку из таблицы по индексу в текущем self.found_restrictions
        row_to_remove = None
        for row, r in enumerate(self.found_restrictions):
            if r['name'] == res['name']:
                row_to_remove = row
                break
        if row_to_remove is not None:
            self.table.removeRow(row_to_remove)
            del self.found_restrictions[row_to_remove]
        self.status_label.setText(f"Состояние: Разблокировано: {res['name']}")

    def on_unlock_finished(self, success_count):
        if not self.found_restrictions:
            self.status_label.setText(f"Состояние: Разблокировано {success_count} ограничений.")
        else:
            self.status_label.setText(f"Состояние: Разблокировано {success_count} из {len(self.found_restrictions) + success_count}. Осталось: {len(self.found_restrictions)}")
        self.scan_button.setEnabled(True)

# --- вкладка ручной разблокировки ---
class ManualUnlockTab(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.load_restrictions()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)

        title = QLabel("Список ограничений")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["", "Ограничение", "Описание"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        layout.addWidget(self.table)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        self.select_all_btn = QPushButton("Выбрать все")
        self.select_all_btn.setObjectName("selectAllBtn")
        self.select_all_btn.clicked.connect(self.toggle_select_all)
        btn_layout.addWidget(self.select_all_btn)

        self.unlock_btn = QPushButton("Разблокировать выбранные")
        self.unlock_btn.setObjectName("unlockBtn")
        self.unlock_btn.clicked.connect(self.unlock_selected)
        btn_layout.addWidget(self.unlock_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        self.setLayout(layout)

    def load_restrictions(self):
        self.table.setRowCount(len(RESTRICTIONS))
        for row, (key, desc, hive, path, value) in enumerate(RESTRICTIONS):
            chk_item = QTableWidgetItem()
            chk_item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            chk_item.setCheckState(Qt.Unchecked)
            self.table.setItem(row, 0, chk_item)

            key_item = QTableWidgetItem(key)
            key_item.setFlags(Qt.ItemIsEnabled)
            self.table.setItem(row, 1, key_item)

            desc_item = QTableWidgetItem(desc)
            desc_item.setFlags(Qt.ItemIsEnabled)
            self.table.setItem(row, 2, desc_item)

        self.table.resizeColumnsToContents()
        self.table.setColumnWidth(0, 30)
        self.table.horizontalHeader().setStretchLastSection(True)

    def toggle_select_all(self):
        if self.table.rowCount() == 0:
            return
        first_check = self.table.item(0, 0).checkState()
        new_state = Qt.Unchecked if first_check == Qt.Checked else Qt.Checked
        for row in range(self.table.rowCount()):
            self.table.item(row, 0).setCheckState(new_state)
        self.select_all_btn.setText("Снять все" if new_state == Qt.Checked else "Выбрать все")

    def unlock_selected(self):
        selected = []
        for row in range(self.table.rowCount()):
            if self.table.item(row, 0).checkState() == Qt.Checked:
                selected.append(row)

        if not selected:
            QMessageBox.information(self, "Информация", "Не выбрано ни одного ограничения.")
            return

        reply = QMessageBox.question(self, "Подтверждение",
                                     f"Разблокировать выбранные ограничения ({len(selected)} шт.)?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return

        success_count = 0
        for row in selected:
            key, desc, hive, path, value = RESTRICTIONS[row]
            if remove_registry_value(hive, path, value):
                success_count += 1

        if success_count == len(selected):
            QMessageBox.information(self, "Успех", f"Все выбранные ограничения ({success_count}) разблокированы.")
        else:
            QMessageBox.warning(self, "Предупреждение",
                                f"Разблокировано {success_count} из {len(selected)}. Некоторые не удались.")

        for row in selected:
            self.table.item(row, 0).setCheckState(Qt.Unchecked)
        self.select_all_btn.setText("Выбрать все")

# --- главная страница снять ограничения ---
class UnlockPage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.tabs = QTabWidget()
        self.tabs.addTab(ScanTab(), "Сканирование")
        self.tabs.addTab(ManualUnlockTab(), "Ручная разблокировка")
        layout.addWidget(self.tabs)
        self.setLayout(layout)