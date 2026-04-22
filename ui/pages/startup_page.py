# -*- coding: utf-8 -*-
import os
import winreg
import subprocess
import re
import datetime
import json
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QMenu, QAbstractItemView, QMessageBox,
    QTabWidget, QInputDialog, QLineEdit, QFileDialog, QCheckBox
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor

from core.startup_scanner import (
    get_registry_run,
    get_registry_runonce_ex,
    get_registry_winlogon,
    get_registry_shell_service_objects,
    get_registry_appinit_dlls,
    get_registry_known_dlls,
    get_services,
    get_startup_folders_all,
    get_scheduled_tasks_full,
    get_active_setup,
    get_logon_scripts,
    filetime_to_datetime,
    get_reg_key_timestamp,
    enum_reg_key,
    expand_env_string
)
from core.startup_manager import (
    disable_registry_entry,
    delete_folder_entry
)
from core.quarantine import add_to_quarantine, move_file_to_quarantine
from core.last_scan import get_last_scan_time, set_last_scan_time, MSK_TZ

# ------------------------------------------------------------
# Базовый класс с контекстным меню (общий для всех)
# ------------------------------------------------------------
class BaseStartupTab(QWidget):
    def __init__(self, columns):
        super().__init__()
        self.columns = columns
        self.entries = []
        self.last_scan_time = get_last_scan_time()
        self.new_color = QColor(100, 100, 0)

        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)

        top_layout = QHBoxLayout()
        top_layout.addStretch()

        self.help_btn = QPushButton("?")
        self.help_btn.setObjectName("helpButton")
        self.help_btn.setFixedSize(24, 24)
        self.help_btn.clicked.connect(self.show_help)
        top_layout.addWidget(self.help_btn)

        self.reset_new_btn = QPushButton("Сбросить новые")
        self.reset_new_btn.setObjectName("resetNewButton")
        self.reset_new_btn.clicked.connect(self.reset_new)
        top_layout.addWidget(self.reset_new_btn)

        self.refresh_btn = QPushButton("Обновить")
        self.refresh_btn.setObjectName("refreshButton")
        self.refresh_btn.clicked.connect(self.load_data)
        top_layout.addWidget(self.refresh_btn)

        layout.addLayout(top_layout)

        self.table = QTableWidget()
        self.table.setColumnCount(len(columns))
        self.table.setHorizontalHeaderLabels(columns)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        layout.addWidget(self.table)
        self.setLayout(layout)

        self.load_data()

    def load_data(self):
        pass

    def show_context_menu(self, position):
        pass

    def show_help(self):
        QMessageBox.information(self, "Справка", "Информация о данной вкладке.")

    def _update_table(self):
        self.table.setRowCount(len(self.entries))
        for row, entry in enumerate(self.entries):
            for col, key in enumerate(entry['display_order']):
                value = entry.get(key, '')
                self.table.setItem(row, col, QTableWidgetItem(str(value)))

        self.table.resizeColumnsToContents()
        min_widths = [200, 100, 150, 150]
        for col in range(self.table.columnCount()):
            current = self.table.columnWidth(col)
            if col < len(min_widths) and current < min_widths[col]:
                self.table.setColumnWidth(col, min_widths[col])
            elif col >= len(min_widths) and current < 100:
                self.table.setColumnWidth(col, 100)

        self.table.horizontalHeader().setStretchLastSection(True)
        # self._highlight_new_entries()

    def _is_new_entry(self, entry):
        if self.last_scan_time is None:
            return False
        created_str = entry.get('created', '')
        if not created_str or created_str == "Неизвестно":
            return False
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%H:%M/%d.%m.%Y"):
            try:
                dt = datetime.datetime.strptime(created_str, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=MSK_TZ)
                else:
                    dt = dt.astimezone(MSK_TZ)
                return dt > self.last_scan_time
            except ValueError:
                continue
        return False

    def _highlight_new_entries(self):
        for row, entry in enumerate(self.entries):
            if self._is_new_entry(entry):
                for col in range(self.table.columnCount()):
                    item = self.table.item(row, col)
                    if item:
                        item.setBackground(self.new_color)

    def reset_new(self):
        self.last_scan_time = datetime.datetime.now(MSK_TZ)
        set_last_scan_time(self.last_scan_time)
        self.load_data()

    def _delete_selected(self):
        """Массовое удаление выбранных записей (переопределяется в наследниках)."""
        pass

    # Вспомогательные методы для работы с реестром (используются в AppInitDLLsTab)
    def _read_reg_value(self, hive, path, name):
        try:
            access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            with winreg.OpenKey(hive, path, 0, access) as key:
                value, reg_type = winreg.QueryValueEx(key, name)
                return value
        except FileNotFoundError:
            return None
        except Exception:
            return None

    def _get_timestamp_str(self, hive, path):
        ts = get_reg_key_timestamp(hive, path)
        return filetime_to_datetime(ts)

# ------------------------------------------------------------
# Вкладка Run (реестр)
# ------------------------------------------------------------
class RegistryRunTab(BaseStartupTab):
    def __init__(self):
        super().__init__(["Имя", "Значение", "Дата создания"])
        self.hive_paths = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
        ]

    def load_data(self):
        entries = []
        raw = get_registry_run()
        for e in raw:
            entries.append({
                'display_order': ['name', 'command', 'created'],
                'name': e['name'],
                'command': e['command'],
                'created': e['created'],
                'hive': e.get('hive'),
                'path': e.get('path'),
                'type': e['type']
            })
        self.entries = entries
        self._update_table()

    def show_context_menu(self, position):
        selected_rows = list(set(idx.row() for idx in self.table.selectedIndexes()))
        menu = QMenu()
        help_action = menu.addAction("Справка")
        if selected_rows:
            menu.addSeparator()
            if len(selected_rows) == 1:
                delete_action = menu.addAction("Удалить запись")
                open_folder_action = menu.addAction("Открыть папку")
                edit_action = menu.addAction("Изменить значение")
            else:
                delete_action = menu.addAction(f"Удалить выбранные ({len(selected_rows)})")
                open_folder_action = None
                edit_action = None
        else:
            delete_action = open_folder_action = edit_action = None
        menu.addSeparator()
        add_action = menu.addAction("Добавить новую запись")
        action = menu.exec(self.table.mapToGlobal(position))

        if action == help_action:
            self.show_help()
        elif add_action and action == add_action:
            self._add_entry()
        elif selected_rows:
            if action == delete_action:
                if len(selected_rows) > 1:
                    self._delete_selected()
                else:
                    self._delete_entry(self.entries[selected_rows[0]])
            elif action == open_folder_action and len(selected_rows) == 1:
                self._open_folder(self.entries[selected_rows[0]])
            elif action == edit_action and len(selected_rows) == 1:
                self._edit_entry(self.entries[selected_rows[0]])

    def _delete_selected(self):
        selected_rows = list(set(idx.row() for idx in self.table.selectedIndexes()))
        if not selected_rows:
            return
        reply = QMessageBox.question(self, "Подтверждение",
                                     f"Переместить {len(selected_rows)} записей в карантин?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        for row in selected_rows:
            entry = self.entries[row]
            add_to_quarantine({
                'type': 'registry',
                'location': entry['path'],
                'name': entry['name'],
                'command': entry['command'],
                'hive_str': 'HKEY_CURRENT_USER' if entry['hive'] == winreg.HKEY_CURRENT_USER else 'HKEY_LOCAL_MACHINE',
                'path': entry['path']
            })
            disable_registry_entry(entry['hive'], entry['path'], entry['name'])
        self.load_data()

    def show_help(self):
        QMessageBox.information(self, "Справка: Run",
                                "Программы, запускаемые при входе в систему.\n"
                                "Удаляйте подозрительные записи, изменяйте пути или добавляйте новые.")

    def _add_entry(self):
        hive_names = [p[2] for p in self.hive_paths]
        hive, ok = QInputDialog.getItem(self, "Выбор куста", "Выберите раздел реестра:", hive_names, 0, False)
        if not ok:
            return
        idx = hive_names.index(hive)
        hive_handle, hive_path, _ = self.hive_paths[idx]

        name, ok = QInputDialog.getText(self, "Добавление записи", "Имя программы:")
        if not ok or not name:
            return
        command, ok = QInputDialog.getText(self, "Добавление записи", "Путь к исполняемому файлу:")
        if not ok or not command:
            return

        try:
            with winreg.OpenKey(hive_handle, hive_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, command)
            QMessageBox.information(self, "Успех", "Запись добавлена.")
            self.load_data()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось добавить запись: {e}")

    def _edit_entry(self, entry):
        new_value, ok = QInputDialog.getText(self, "Изменение значения",
                                             "Новое значение:", QLineEdit.Normal, entry['command'])
        if ok and new_value != entry['command']:
            try:
                with winreg.OpenKey(entry['hive'], entry['path'], 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, entry['name'], 0, winreg.REG_SZ, new_value)
                QMessageBox.information(self, "Успех", "Значение обновлено.")
                self.load_data()
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось изменить значение: {e}")

    def _delete_entry(self, entry):
        reply = QMessageBox.question(self, "Подтверждение",
                                     f"Переместить запись '{entry['name']}' в карантин?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        add_to_quarantine({
            'type': 'registry',
            'location': entry['path'],
            'name': entry['name'],
            'command': entry['command'],
            'hive_str': 'HKEY_CURRENT_USER' if entry['hive'] == winreg.HKEY_CURRENT_USER else 'HKEY_LOCAL_MACHINE',
            'path': entry['path']
        })
        if disable_registry_entry(entry['hive'], entry['path'], entry['name']):
            self.load_data()

    def _open_folder(self, entry):
        cmd = entry['command']
        if cmd and os.path.exists(cmd):
            folder = os.path.dirname(cmd)
            if os.path.isdir(folder):
                os.startfile(folder)

# ------------------------------------------------------------
# Вкладка RunOnce (реестр)
# ------------------------------------------------------------
class RegistryRunOnceTab(BaseStartupTab):
    def __init__(self):
        super().__init__(["Имя", "Значение", "Дата создания"])
        self.hive_paths = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
        ]

    def load_data(self):
        entries = []
        raw = get_registry_runonce_ex()
        for e in raw:
            entries.append({
                'display_order': ['name', 'command', 'created'],
                'name': e['name'],
                'command': e['command'],
                'created': e['created'],
                'hive': e.get('hive'),
                'path': e.get('path'),
                'type': e['type']
            })
        self.entries = entries
        self._update_table()

    def show_context_menu(self, position):
        selected_rows = list(set(idx.row() for idx in self.table.selectedIndexes()))
        menu = QMenu()
        help_action = menu.addAction("Справка")
        if selected_rows:
            menu.addSeparator()
            if len(selected_rows) == 1:
                delete_action = menu.addAction("Удалить запись")
                open_folder_action = menu.addAction("Открыть папку")
                edit_action = menu.addAction("Изменить значение")
            else:
                delete_action = menu.addAction(f"Удалить выбранные ({len(selected_rows)})")
                open_folder_action = None
                edit_action = None
        else:
            delete_action = open_folder_action = edit_action = None
        menu.addSeparator()
        add_action = menu.addAction("Добавить новую запись")
        action = menu.exec(self.table.mapToGlobal(position))

        if action == help_action:
            self.show_help()
        elif add_action and action == add_action:
            self._add_entry()
        elif selected_rows:
            if action == delete_action:
                if len(selected_rows) > 1:
                    self._delete_selected()
                else:
                    self._delete_entry(self.entries[selected_rows[0]])
            elif action == open_folder_action and len(selected_rows) == 1:
                self._open_folder(self.entries[selected_rows[0]])
            elif action == edit_action and len(selected_rows) == 1:
                self._edit_entry(self.entries[selected_rows[0]])

    def _delete_selected(self):
        selected_rows = list(set(idx.row() for idx in self.table.selectedIndexes()))
        if not selected_rows:
            return
        reply = QMessageBox.question(self, "Подтверждение",
                                     f"Переместить {len(selected_rows)} записей в карантин?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        for row in selected_rows:
            entry = self.entries[row]
            add_to_quarantine({
                'type': 'registry',
                'location': entry['path'],
                'name': entry['name'],
                'command': entry['command'],
                'hive_str': 'HKEY_CURRENT_USER' if entry['hive'] == winreg.HKEY_CURRENT_USER else 'HKEY_LOCAL_MACHINE',
                'path': entry['path']
            })
            disable_registry_entry(entry['hive'], entry['path'], entry['name'])
        self.load_data()

    def show_help(self):
        QMessageBox.information(self, "Справка: RunOnce",
                                "Записи выполняются один раз при следующем входе в систему, затем удаляются.")

    def _add_entry(self):
        hive_names = [p[2] for p in self.hive_paths]
        hive, ok = QInputDialog.getItem(self, "Выбор куста", "Выберите раздел реестра:", hive_names, 0, False)
        if not ok:
            return
        idx = hive_names.index(hive)
        hive_handle, hive_path, _ = self.hive_paths[idx]

        name, ok = QInputDialog.getText(self, "Добавление записи", "Имя программы:")
        if not ok or not name:
            return
        command, ok = QInputDialog.getText(self, "Добавление записи", "Путь к исполняемому файлу:")
        if not ok or not command:
            return

        try:
            with winreg.OpenKey(hive_handle, hive_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, command)
            QMessageBox.information(self, "Успех", "Запись добавлена.")
            self.load_data()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось добавить запись: {e}")

    def _edit_entry(self, entry):
        new_value, ok = QInputDialog.getText(self, "Изменение значения",
                                             "Новое значение:", QLineEdit.Normal, entry['command'])
        if ok and new_value != entry['command']:
            try:
                with winreg.OpenKey(entry['hive'], entry['path'], 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, entry['name'], 0, winreg.REG_SZ, new_value)
                QMessageBox.information(self, "Успех", "Значение обновлено.")
                self.load_data()
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось изменить значение: {e}")

    def _delete_entry(self, entry):
        reply = QMessageBox.question(self, "Подтверждение",
                                     f"Переместить запись '{entry['name']}' в карантин?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        add_to_quarantine({
            'type': 'registry',
            'location': entry['path'],
            'name': entry['name'],
            'command': entry['command'],
            'hive_str': 'HKEY_CURRENT_USER' if entry['hive'] == winreg.HKEY_CURRENT_USER else 'HKEY_LOCAL_MACHINE',
            'path': entry['path']
        })
        if disable_registry_entry(entry['hive'], entry['path'], entry['name']):
            self.load_data()

    def _open_folder(self, entry):
        cmd = entry['command']
        if cmd and os.path.exists(cmd):
            folder = os.path.dirname(cmd)
            if os.path.isdir(folder):
                os.startfile(folder)

# ------------------------------------------------------------
# Вкладка Winlogon
# ------------------------------------------------------------
class WinlogonTab(BaseStartupTab):
    def __init__(self):
        super().__init__(["Параметр", "Значение", "Дата создания"])
        self.winlogon_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        self.hive = winreg.HKEY_LOCAL_MACHINE

    def load_data(self):
        entries = []
        raw = get_registry_winlogon()
        for e in raw:
            entries.append({
                'display_order': ['name', 'command', 'created'],
                'name': e['name'],
                'command': e['command'],
                'created': e['created'],
                'type': e['type']
            })
        self.entries = entries
        self._update_table()

    def show_context_menu(self, position):
        selected_rows = list(set(idx.row() for idx in self.table.selectedIndexes()))
        menu = QMenu()
        help_action = menu.addAction("Справка")
        if selected_rows:
            menu.addSeparator()
            if len(selected_rows) == 1:
                delete_action = menu.addAction("Удалить параметр")
                edit_action = menu.addAction("Изменить значение")
                open_folder_action = menu.addAction("Открыть папку")
            else:
                delete_action = menu.addAction(f"Удалить выбранные ({len(selected_rows)})")
                edit_action = open_folder_action = None
        else:
            delete_action = edit_action = open_folder_action = None
        action = menu.exec(self.table.mapToGlobal(position))

        if action == help_action:
            self.show_help()
        elif selected_rows:
            if action == delete_action:
                if len(selected_rows) > 1:
                    self._delete_selected()
                else:
                    self._delete_entry(self.entries[selected_rows[0]])
            elif action == edit_action and len(selected_rows) == 1:
                self._edit_value(self.entries[selected_rows[0]])
            elif action == open_folder_action and len(selected_rows) == 1:
                self._open_folder(self.entries[selected_rows[0]])

    def _delete_selected(self):
        selected_rows = list(set(idx.row() for idx in self.table.selectedIndexes()))
        if not selected_rows:
            return
        reply = QMessageBox.question(self, "Подтверждение",
                                     f"Удалить {len(selected_rows)} параметров? Это может нарушить загрузку системы.",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        for row in selected_rows:
            entry = self.entries[row]
            try:
                with winreg.OpenKey(self.hive, self.winlogon_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, entry['name'])
            except Exception:
                pass
        self.load_data()

    def show_help(self):
        QMessageBox.information(self, "Справка: Winlogon",
                                "Параметры Userinit и Shell определяют, какие программы запускаются при входе.")

    def _edit_value(self, entry):
        new_value, ok = QInputDialog.getText(
            self, f"Изменение {entry['name']}", "Новое значение:", QLineEdit.Normal, entry['command']
        )
        if ok and new_value != entry['command']:
            try:
                with winreg.OpenKey(self.hive, self.winlogon_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, entry['name'], 0, winreg.REG_SZ, new_value)
                QMessageBox.information(self, "Успех", "Значение обновлено.")
                self.load_data()
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось изменить значение:\n{e}")

    def _delete_entry(self, entry):
        reply = QMessageBox.question(self, "Подтверждение",
                                     f"Удалить параметр '{entry['name']}'?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        try:
            with winreg.OpenKey(self.hive, self.winlogon_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, entry['name'])
            QMessageBox.information(self, "Успех", "Параметр удалён.")
            self.load_data()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось удалить параметр: {e}")

    def _open_folder(self, entry):
        match = re.search(r'([a-zA-Z]:[^,\s]+)', entry['command'])
        if match:
            path = match.group(1)
            if os.path.exists(path):
                folder = os.path.dirname(path)
                if os.path.isdir(folder):
                    os.startfile(folder)
                    return
        QMessageBox.information(self, "Информация", "Не удалось определить папку.")

# ------------------------------------------------------------
# Вкладка ShellServiceObjects
# ------------------------------------------------------------
class ShellServiceObjectsTab(BaseStartupTab):
    def __init__(self):
        super().__init__(["Имя", "CLSID", "Дата создания"])
        self.path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"
        self.hive = winreg.HKEY_LOCAL_MACHINE

    def load_data(self):
        entries = []
        raw = get_registry_shell_service_objects()
        for e in raw:
            entries.append({
                'display_order': ['name', 'command', 'created'],
                'name': e['name'],
                'command': e['command'],
                'created': e['created'],
                'type': e['type']
            })
        self.entries = entries
        self._update_table()

    def show_context_menu(self, position):
        selected_rows = list(set(idx.row() for idx in self.table.selectedIndexes()))
        menu = QMenu()
        help_action = menu.addAction("Справка")
        if selected_rows:
            menu.addSeparator()
            if len(selected_rows) == 1:
                delete_action = menu.addAction("Удалить запись")
                open_reg_action = menu.addAction("Открыть в реестре")
            else:
                delete_action = menu.addAction(f"Удалить выбранные ({len(selected_rows)})")
                open_reg_action = None
        else:
            delete_action = open_reg_action = None
        action = menu.exec(self.table.mapToGlobal(position))

        if action == help_action:
            self.show_help()
        elif selected_rows:
            if action == delete_action:
                if len(selected_rows) > 1:
                    self._delete_selected()
                else:
                    self._delete_entry(self.entries[selected_rows[0]])
            elif action == open_reg_action and len(selected_rows) == 1:
                self._open_in_registry(self.entries[selected_rows[0]])

    def _delete_selected(self):
        selected_rows = list(set(idx.row() for idx in self.table.selectedIndexes()))
        if not selected_rows:
            return
        reply = QMessageBox.question(self, "Подтверждение",
                                     f"Удалить {len(selected_rows)} записей?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        for row in selected_rows:
            entry = self.entries[row]
            try:
                with winreg.OpenKey(self.hive, self.path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, entry['name'])
            except Exception:
                pass
        self.load_data()

    def show_help(self):
        QMessageBox.information(self, "Справка: ShellServiceObjects",
                                "Объекты, загружаемые оболочкой Windows (проводником).")

    def _delete_entry(self, entry):
        reply = QMessageBox.question(self, "Подтверждение",
                                     f"Удалить запись '{entry['name']}'?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        try:
            with winreg.OpenKey(self.hive, self.path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, entry['name'])
            QMessageBox.information(self, "Успех", "Запись удалена.")
            self.load_data()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось удалить запись: {e}")

    def _open_in_registry(self, entry):
        reg_path = f"{self.path}\\{entry['name']}"
        try:
            subprocess.run(f'regedit /e temp.reg "{reg_path}"', shell=True, capture_output=True)
            os.startfile("regedit.exe")
        except Exception:
            QMessageBox.information(self, "Информация", "Не удалось открыть редактор реестра.")

# ------------------------------------------------------------
# Вкладка AppInit_DLLs (ПОЛНОСТЬЮ ПЕРЕРАБОТАНА)
# ------------------------------------------------------------
class AppInitDLLsTab(BaseStartupTab):
    def __init__(self):
        # Сначала задаём атрибуты, чтобы они были доступны в load_data()
        self.win_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
        self.hive_hklm = winreg.HKEY_LOCAL_MACHINE
        self.cursor_path = r"Control Panel\Desktop"
        self.hive_hkcu = winreg.HKEY_CURRENT_USER
        # Теперь вызываем конструктор базового класса (он вызовет load_data)
        super().__init__(["Параметр", "Значение", "Дата создания", "Примечание"])

    def _read_reg_value(self, hive, path, name):
        try:
            access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            with winreg.OpenKey(hive, path, 0, access) as key:
                value, _ = winreg.QueryValueEx(key, name)
                return value
        except FileNotFoundError:
            return None
        except Exception:
            return None

    def _get_timestamp_str(self, hive, path):
        ts = get_reg_key_timestamp(hive, path)
        return filetime_to_datetime(ts)

    def _write_reg_value(self, hive, path, name, value, reg_type):
        try:
            access = winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
            with winreg.OpenKey(hive, path, 0, access) as key:
                winreg.SetValueEx(key, name, 0, reg_type, value)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось записать значение: {e}")

    def load_data(self):
        entries = []
        # 1. AppInit_DLLs (REG_SZ)
        appinit_val = self._read_reg_value(self.hive_hklm, self.win_path, "AppInit_DLLs")
        entries.append({
            'display_order': ['name', 'command', 'created', 'note'],
            'name': 'AppInit_DLLs',
            'command': appinit_val if appinit_val is not None else '',
            'created': self._get_timestamp_str(self.hive_hklm, self.win_path),
            'note': 'Список DLL',
            'hive': self.hive_hklm,
            'path': self.win_path,
            'type': 'appinit',
            'reg_type': winreg.REG_SZ
        })
        # 2. LoadAppInit_DLLs (REG_DWORD)
        load_val = self._read_reg_value(self.hive_hklm, self.win_path, "LoadAppInit_DLLs")
        entries.append({
            'display_order': ['name', 'command', 'created', 'note'],
            'name': 'LoadAppInit_DLLs',
            'command': 'Включено' if load_val == 1 else 'Отключено',
            'created': self._get_timestamp_str(self.hive_hklm, self.win_path),
            'note': 'Вкл/Откл',
            'hive': self.hive_hklm,
            'path': self.win_path,
            'type': 'appinit',
            'reg_type': winreg.REG_DWORD
        })
        # 3. CMDLINE (REG_SZ)
        cmdline_val = self._read_reg_value(self.hive_hklm, self.win_path, "CMDLINE")
        entries.append({
            'display_order': ['name', 'command', 'created', 'note'],
            'name': 'CMDLINE',
            'command': cmdline_val if cmdline_val is not None else '',
            'created': self._get_timestamp_str(self.hive_hklm, self.win_path),
            'note': 'Аргументы CMD',
            'hive': self.hive_hklm,
            'path': self.win_path,
            'type': 'appinit',
            'reg_type': winreg.REG_SZ
        })
        # 4. EnableCursorSuppression (REG_DWORD в HKCU)
        cursor_val = self._read_reg_value(self.hive_hkcu, self.cursor_path, "EnableCursorSuppression")
        entries.append({
            'display_order': ['name', 'command', 'created', 'note'],
            'name': 'EnableCursorSuppression',
            'command': 'Подавление' if cursor_val == 1 else 'Обычный',
            'created': self._get_timestamp_str(self.hive_hkcu, self.cursor_path),
            'note': 'Курсор',
            'hive': self.hive_hkcu,
            'path': self.cursor_path,
            'type': 'appinit',
            'reg_type': winreg.REG_DWORD
        })
        self.entries = entries
        self._update_table()

    def show_context_menu(self, position):
        selected_rows = list(set(idx.row() for idx in self.table.selectedIndexes()))
        menu = QMenu()
        help_action = menu.addAction("Справка")
        if selected_rows and len(selected_rows) == 1:
            entry = self.entries[selected_rows[0]]
            menu.addSeparator()
            edit_action = menu.addAction("Изменить значение")
            if entry['name'] in ('LoadAppInit_DLLs', 'EnableCursorSuppression'):
                toggle_action = menu.addAction("Переключить состояние")
            else:
                toggle_action = None
        else:
            edit_action = toggle_action = None
        action = menu.exec(self.table.mapToGlobal(position))

        if action == help_action:
            self.show_help()
        elif selected_rows and len(selected_rows) == 1:
            entry = self.entries[selected_rows[0]]
            if action == edit_action:
                self._edit_value(entry)
            elif action == toggle_action:
                self._toggle_value(entry)

    def show_help(self):
        QMessageBox.information(self, "Справка: AppInit_DLLs",
                                "AppInit_DLLs: DLL, загружаемые в каждый процесс.\n"
                                "LoadAppInit_DLLs: включает механизм AppInit.\n"
                                "CMDLINE: дополнительные параметры командной строки.\n"
                                "EnableCursorSuppression: управление подавлением курсора (1 — подавлять, 0 — нет).")

    def _edit_value(self, entry):
        if entry['reg_type'] == winreg.REG_DWORD:
            current = '1' if entry['command'] in ('Включено', 'Подавление') else '0'
            new_val, ok = QInputDialog.getText(self, f"Изменение {entry['name']}",
                                               "Введите 1 (вкл) или 0 (откл):", QLineEdit.Normal, current)
            if ok:
                try:
                    ival = int(new_val)
                    if ival not in (0, 1):
                        raise ValueError
                except ValueError:
                    QMessageBox.warning(self, "Ошибка", "Введите 0 или 1.")
                    return
        else:
            new_val, ok = QInputDialog.getText(self, f"Изменение {entry['name']}",
                                               "Новое значение:", QLineEdit.Normal, entry['command'])
        if ok:
            self._write_reg_value(entry['hive'], entry['path'], entry['name'], new_val, entry['reg_type'])
            self.load_data()

    def _toggle_value(self, entry):
        if entry['name'] == 'LoadAppInit_DLLs':
            new_state = 0 if entry['command'] == 'Включено' else 1
        elif entry['name'] == 'EnableCursorSuppression':
            new_state = 0 if entry['command'] == 'Подавление' else 1
        else:
            return
        self._write_reg_value(entry['hive'], entry['path'], entry['name'], new_state, winreg.REG_DWORD)
        self.load_data()

# ------------------------------------------------------------
# Вкладка KnownDLLs
# ------------------------------------------------------------
class KnownDLLsTab(BaseStartupTab):
    def __init__(self):
        super().__init__(["Имя DLL", "Путь", "Дата создания"])
        self.path = r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
        self.hive = winreg.HKEY_LOCAL_MACHINE

    def load_data(self):
        entries = []
        raw = get_registry_known_dlls()
        for e in raw:
            entries.append({
                'display_order': ['name', 'command', 'created'],
                'name': e['name'],
                'command': e['command'],
                'created': e['created'],
                'type': e['type']
            })
        self.entries = entries
        self._update_table()

    def show_context_menu(self, position):
        selected_rows = list(set(idx.row() for idx in self.table.selectedIndexes()))
        menu = QMenu()
        help_action = menu.addAction("Справка")
        if selected_rows:
            menu.addSeparator()
            delete_action = menu.addAction(f"Удалить выбранные ({len(selected_rows)})")
        else:
            delete_action = None
        action = menu.exec(self.table.mapToGlobal(position))

        if action == help_action:
            self.show_help()
        elif selected_rows and action == delete_action:
            self._delete_selected()

    def _delete_selected(self):
        selected_rows = list(set(idx.row() for idx in self.table.selectedIndexes()))
        if not selected_rows:
            return
        reply = QMessageBox.question(self, "Подтверждение",
                                     f"Удалить {len(selected_rows)} записей?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        for row in selected_rows:
            entry = self.entries[row]
            try:
                with winreg.OpenKey(self.hive, self.path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, entry['name'])
            except Exception:
                pass
        self.load_data()

    def show_help(self):
        QMessageBox.information(self, "Справка: KnownDLLs",
                                "Список известных системных DLL. Удаление не рекомендуется.")

# ------------------------------------------------------------
# Вкладка Папки автозагрузки
# ------------------------------------------------------------
class StartupFoldersTab(BaseStartupTab):
    def __init__(self):
        super().__init__(["Имя файла", "Путь", "Дата создания"])
        self.folders = [
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.expandvars(r"%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup"),
        ]

    def load_data(self):
        entries = []
        raw = get_startup_folders_all()
        for e in raw:
            entries.append({
                'display_order': ['name', 'command', 'created'],
                'name': e['name'],
                'command': e['command'],
                'created': e['created'],
                'type': e['type'],
                'location': e.get('location')
            })
        self.entries = entries
        self._update_table()

    def show_context_menu(self, position):
        selected_rows = list(set(idx.row() for idx in self.table.selectedIndexes()))
        menu = QMenu()
        help_action = menu.addAction("Справка")
        if selected_rows:
            menu.addSeparator()
            if len(selected_rows) == 1:
                delete_action = menu.addAction("Удалить файл")
                open_folder_action = menu.addAction("Открыть папку")
            else:
                delete_action = menu.addAction(f"Удалить выбранные ({len(selected_rows)})")
                open_folder_action = None
        else:
            delete_action = open_folder_action = None
        menu.addSeparator()
        add_action = menu.addAction("Добавить файл в автозагрузку")
        action = menu.exec(self.table.mapToGlobal(position))

        if action == help_action:
            self.show_help()
        elif add_action and action == add_action:
            self._add_file()
        elif selected_rows:
            if action == delete_action:
                if len(selected_rows) > 1:
                    self._delete_selected()
                else:
                    self._delete_entry(self.entries[selected_rows[0]])
            elif action == open_folder_action and len(selected_rows) == 1:
                self._open_folder(self.entries[selected_rows[0]])

    def _delete_selected(self):
        selected_rows = list(set(idx.row() for idx in self.table.selectedIndexes()))
        if not selected_rows:
            return
        reply = QMessageBox.question(self, "Подтверждение",
                                     f"Переместить {len(selected_rows)} файлов в карантин?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        for row in selected_rows:
            entry = self.entries[row]
            quarantine_path = move_file_to_quarantine(entry['command'])
            add_to_quarantine({
                'type': 'folder',
                'location': entry.get('location', ''),
                'name': entry['name'],
                'command': entry['command'],
                'quarantine_path': quarantine_path
            })
        self.load_data()

    def show_help(self):
        QMessageBox.information(self, "Справка: Папки автозагрузки",
                                "Файлы и ярлыки в этих папках запускаются при входе пользователя.")

    def _add_file(self):
        folder_names = ["Текущий пользователь", "Все пользователи"]
        choice, ok = QInputDialog.getItem(self, "Выбор папки", "Куда добавить?", folder_names, 0, False)
        if not ok:
            return
        target_folder = self.folders[0] if choice == "Текущий пользователь" else self.folders[1]
        file_path, _ = QFileDialog.getOpenFileName(self, "Выберите файл для автозагрузки", "",
                                                   "Программы (*.exe);;Ярлыки (*.lnk);;Все файлы (*)")
        if not file_path:
            return
        import shutil
        try:
            dest = os.path.join(target_folder, os.path.basename(file_path))
            shutil.copy2(file_path, dest)
            QMessageBox.information(self, "Успех", f"Файл скопирован в {target_folder}")
            self.load_data()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось скопировать файл: {e}")

    def _delete_entry(self, entry):
        reply = QMessageBox.question(self, "Подтверждение",
                                     f"Переместить файл '{entry['name']}' в карантин?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        quarantine_path = move_file_to_quarantine(entry['command'])
        add_to_quarantine({
            'type': 'folder',
            'location': entry.get('location', ''),
            'name': entry['name'],
            'command': entry['command'],
            'quarantine_path': quarantine_path
        })
        self.load_data()

    def _open_folder(self, entry):
        if os.path.exists(entry['command']):
            folder = os.path.dirname(entry['command'])
            if os.path.isdir(folder):
                os.startfile(folder)

# ------------------------------------------------------------
# Вкладка Службы
# ------------------------------------------------------------
class ServicesTab(BaseStartupTab):
    def __init__(self):
        super().__init__(["Имя службы", "Путь к исполняемому файлу", "Дата создания"])

    def load_data(self):
        entries = []
        raw = get_services()
        for e in raw:
            entries.append({
                'display_order': ['name', 'command', 'created'],
                'name': e['name'],
                'command': e['command'],
                'created': e['created']
            })
        self.entries = entries
        self._update_table()

    def show_context_menu(self, position):
        selected_rows = list(set(idx.row() for idx in self.table.selectedIndexes()))
        menu = QMenu()
        help_action = menu.addAction("Справка")
        if selected_rows:
            menu.addSeparator()
            if len(selected_rows) == 1:
                delete_action = menu.addAction("Удалить службу (через sc delete)")
                open_folder_action = menu.addAction("Открыть папку")
                edit_action = menu.addAction("Изменить путь")
            else:
                delete_action = menu.addAction(f"Удалить выбранные ({len(selected_rows)})")
                open_folder_action = edit_action = None
        else:
            delete_action = open_folder_action = edit_action = None
        action = menu.exec(self.table.mapToGlobal(position))

        if action == help_action:
            self.show_help()
        elif selected_rows:
            if action == delete_action:
                if len(selected_rows) > 1:
                    self._delete_selected()
                else:
                    self._delete_service(self.entries[selected_rows[0]])
            elif action == open_folder_action and len(selected_rows) == 1:
                self._open_folder(self.entries[selected_rows[0]])
            elif action == edit_action and len(selected_rows) == 1:
                self._edit_service(self.entries[selected_rows[0]])

    def _delete_selected(self):
        selected_rows = list(set(idx.row() for idx in self.table.selectedIndexes()))
        if not selected_rows:
            return
        reply = QMessageBox.question(self, "Подтверждение",
                                     f"Удалить {len(selected_rows)} служб?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        for row in selected_rows:
            entry = self.entries[row]
            try:
                subprocess.run(['sc', 'delete', entry['name']], capture_output=True, check=True)
            except Exception:
                pass
        self.load_data()

    def show_help(self):
        QMessageBox.information(self, "Справка: Службы",
                                "Службы с автоматическим запуском.")

    def _delete_service(self, entry):
        reply = QMessageBox.question(self, "Подтверждение",
                                     f"Удалить службу '{entry['name']}'?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        try:
            subprocess.run(['sc', 'delete', entry['name']], capture_output=True, check=True)
            QMessageBox.information(self, "Успех", "Служба удалена.")
            self.load_data()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось удалить службу: {e}")

    def _open_folder(self, entry):
        cmd = entry['command']
        if cmd and os.path.exists(cmd):
            folder = os.path.dirname(cmd)
            if os.path.isdir(folder):
                os.startfile(folder)

    def _edit_service(self, entry):
        new_path, ok = QInputDialog.getText(self, "Изменение пути",
                                            "Новый путь к исполняемому файлу:", QLineEdit.Normal, entry['command'])
        if ok and new_path != entry['command']:
            try:
                subprocess.run(['sc', 'config', entry['name'], 'binPath=', new_path], capture_output=True, check=True)
                QMessageBox.information(self, "Успех", "Путь службы изменён.")
                self.load_data()
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось изменить путь: {e}")

# ------------------------------------------------------------
# Вкладка Планировщик задач
# ------------------------------------------------------------
class ScheduledTasksTab(BaseStartupTab):
    def __init__(self):
        super().__init__(["Имя задачи", "Состояние", "Автор", "Создан"])

    def load_data(self):
        tasks = []
        raw = get_scheduled_tasks_full()
        for item in raw:
            tasks.append({
                'display_order': ['name', 'state', 'author', 'created'],
                'name': item.get('name', ''),
                'state': item.get('state', ''),
                'author': item.get('author', ''),
                'created': item.get('created', '')
            })
        self.entries = tasks
        self._update_table()

    def show_context_menu(self, position):
        selected_rows = list(set(idx.row() for idx in self.table.selectedIndexes()))
        menu = QMenu()
        help_action = menu.addAction("Справка")
        if selected_rows:
            menu.addSeparator()
            if len(selected_rows) == 1:
                delete_action = menu.addAction("Удалить задачу")
                toggle_action = menu.addAction("Отключить/Включить")
                open_folder_action = menu.addAction("Открыть папку")
            else:
                delete_action = menu.addAction(f"Удалить выбранные ({len(selected_rows)})")
                toggle_action = open_folder_action = None
        else:
            delete_action = toggle_action = open_folder_action = None
        menu.addSeparator()
        add_action = menu.addAction("Создать новую задачу")
        action = menu.exec(self.table.mapToGlobal(position))

        if action == help_action:
            self.show_help()
        elif add_action and action == add_action:
            self._create_task()
        elif selected_rows:
            if action == delete_action:
                if len(selected_rows) > 1:
                    self._delete_selected()
                else:
                    self._delete_task(self.entries[selected_rows[0]])
            elif action == toggle_action and len(selected_rows) == 1:
                self._toggle_task(self.entries[selected_rows[0]])
            elif action == open_folder_action and len(selected_rows) == 1:
                self._open_task_folder(self.entries[selected_rows[0]])

    def _delete_selected(self):
        selected_rows = list(set(idx.row() for idx in self.table.selectedIndexes()))
        if not selected_rows:
            return
        reply = QMessageBox.question(self, "Подтверждение",
                                     f"Удалить {len(selected_rows)} задач?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        for row in selected_rows:
            entry = self.entries[row]
            try:
                subprocess.run(['schtasks', '/delete', '/tn', entry['name'], '/f'], capture_output=True, check=True)
            except Exception:
                pass
        self.load_data()

    def show_help(self):
        QMessageBox.information(self, "Справка: Планировщик задач",
                                "Здесь отображаются только пользовательские задачи.")

    def _delete_task(self, entry):
        reply = QMessageBox.question(self, "Подтверждение",
                                     f"Удалить задачу '{entry['name']}'?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        try:
            subprocess.run(['schtasks', '/delete', '/tn', entry['name'], '/f'], capture_output=True, check=True)
            QMessageBox.information(self, "Успех", "Задача удалена.")
            self.load_data()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось удалить задачу: {e}")

    def _toggle_task(self, entry):
        current_state = entry.get('state', '')
        if current_state == "Отключено":
            cmd = ['schtasks', '/change', '/tn', entry['name'], '/enable']
        else:
            cmd = ['schtasks', '/change', '/tn', entry['name'], '/disable']
        reply = QMessageBox.question(self, "Подтверждение",
                                     f"{'Включить' if current_state == 'Отключено' else 'Отключить'} задачу '{entry['name']}'?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        try:
            subprocess.run(cmd, capture_output=True, check=True)
            QMessageBox.information(self, "Успех", "Состояние изменено.")
            self.load_data()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось изменить состояние: {e}")

    def _open_task_folder(self, entry):
        try:
            result = subprocess.run(['schtasks', '/query', '/tn', entry['name'], '/xml'], capture_output=True, text=True)
            if result.returncode != 0:
                return
            import xml.etree.ElementTree as ET
            root = ET.fromstring(result.stdout)
            for cmd_elem in root.findall('.//Command'):
                command = cmd_elem.text
                if command and os.path.exists(command):
                    folder = os.path.dirname(command)
                    if os.path.isdir(folder):
                        os.startfile(folder)
                        return
        except Exception:
            pass
        QMessageBox.information(self, "Информация", "Не удалось определить папку.")

    def _create_task(self):
        name, ok = QInputDialog.getText(self, "Создание задачи", "Имя задачи:")
        if not ok or not name:
            return
        command, ok = QInputDialog.getText(self, "Создание задачи", "Путь к программе:")
        if not ok or not command:
            return
        schedule, ok = QInputDialog.getItem(self, "Расписание", "Когда запускать?",
                                            ["При входе", "При запуске системы"], 0, False)
        if not ok:
            return
        trigger = "/sc onlogon" if schedule == "При входе" else "/sc onstart"
        try:
            subprocess.run(['schtasks', '/create', '/tn', name, '/tr', command, trigger, '/f'],
                           capture_output=True, check=True)
            QMessageBox.information(self, "Успех", "Задача создана.")
            self.load_data()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось создать задачу: {e}")

# ------------------------------------------------------------
# Вкладка Active Setup
# ------------------------------------------------------------
class ActiveSetupTab(BaseStartupTab):
    def __init__(self):
        super().__init__(["Компонент", "Команда (StubPath)", "Дата создания"])
        self.paths = [
            r"SOFTWARE\Microsoft\Active Setup\Installed Components",
            r"SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components"
        ]
        self.hive = winreg.HKEY_LOCAL_MACHINE

    def load_data(self):
        entries = []
        raw = get_active_setup()
        for e in raw:
            entries.append({
                'display_order': ['name', 'command', 'created'],
                'name': e['name'],
                'command': e['command'],
                'created': e['created'],
                'location': e['location']
            })
        self.entries = entries
        self._update_table()

    def show_context_menu(self, position):
        selected_rows = list(set(idx.row() for idx in self.table.selectedIndexes()))
        menu = QMenu()
        help_action = menu.addAction("Справка")
        if selected_rows:
            menu.addSeparator()
            if len(selected_rows) == 1:
                delete_action = menu.addAction("Удалить компонент")
                open_folder_action = menu.addAction("Открыть папку")
                edit_action = menu.addAction("Изменить команду")
            else:
                delete_action = menu.addAction(f"Удалить выбранные ({len(selected_rows)})")
                open_folder_action = edit_action = None
        else:
            delete_action = open_folder_action = edit_action = None
        menu.addSeparator()
        add_action = menu.addAction("Добавить новый компонент")
        action = menu.exec(self.table.mapToGlobal(position))

        if action == help_action:
            self.show_help()
        elif add_action and action == add_action:
            self._add_entry()
        elif selected_rows:
            if action == delete_action:
                if len(selected_rows) > 1:
                    self._delete_selected()
                else:
                    self._delete_entry(self.entries[selected_rows[0]])
            elif action == open_folder_action and len(selected_rows) == 1:
                self._open_folder(self.entries[selected_rows[0]])
            elif action == edit_action and len(selected_rows) == 1:
                self._edit_entry(self.entries[selected_rows[0]])

    def _delete_selected(self):
        selected_rows = list(set(idx.row() for idx in self.table.selectedIndexes()))
        if not selected_rows:
            return
        reply = QMessageBox.question(self, "Подтверждение",
                                     f"Удалить {len(selected_rows)} компонентов?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        for row in selected_rows:
            entry = self.entries[row]
            loc = entry['location']
            match = re.search(r'Реестр: (.+?)$', loc)
            if match:
                reg_path = match.group(1)
                try:
                    winreg.DeleteKey(self.hive, reg_path)
                except Exception:
                    pass
        self.load_data()

    def show_help(self):
        QMessageBox.information(self, "Справка: Active Setup",
                                "Компоненты Active Setup выполняются один раз при первом входе пользователя.")

    def _add_entry(self):
        name, ok = QInputDialog.getText(self, "Добавление компонента", "Имя компонента (GUID или произвольное):")
        if not ok or not name:
            return
        command, ok = QInputDialog.getText(self, "Добавление компонента", "Путь к StubPath:")
        if not ok or not command:
            return
        path_choice, ok = QInputDialog.getItem(self, "Выбор раздела", "Куда добавить?",
                                               ["HKLM", "HKLM (WOW6432)"], 0, False)
        if not ok:
            return
        reg_path = self.paths[0] if path_choice == "HKLM" else self.paths[1]
        try:
            with winreg.CreateKey(self.hive, f"{reg_path}\\{name}") as key:
                winreg.SetValueEx(key, "StubPath", 0, winreg.REG_SZ, command)
            QMessageBox.information(self, "Успех", "Компонент добавлен.")
            self.load_data()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось добавить компонент: {e}")

    def _edit_entry(self, entry):
        new_value, ok = QInputDialog.getText(self, f"Изменение {entry['name']}",
                                             "Новый путь к StubPath:", QLineEdit.Normal, entry['command'])
        if ok and new_value != entry['command']:
            try:
                loc = entry['location']
                match = re.search(r'Реестр: (.+?)$', loc)
                if not match:
                    return
                reg_path = match.group(1)
                with winreg.OpenKey(self.hive, reg_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, "StubPath", 0, winreg.REG_SZ, new_value)
                QMessageBox.information(self, "Успех", "Значение обновлено.")
                self.load_data()
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось изменить значение: {e}")

    def _delete_entry(self, entry):
        reply = QMessageBox.question(self, "Подтверждение",
                                     f"Удалить компонент '{entry['name']}'?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        try:
            loc = entry['location']
            match = re.search(r'Реестр: (.+?)$', loc)
            if match:
                reg_path = match.group(1)
                winreg.DeleteKey(self.hive, reg_path)
            QMessageBox.information(self, "Успех", "Компонент удалён.")
            self.load_data()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось удалить компонент: {e}")

    def _open_folder(self, entry):
        cmd = entry['command']
        if cmd and os.path.exists(cmd):
            folder = os.path.dirname(cmd)
            if os.path.isdir(folder):
                os.startfile(folder)

# ------------------------------------------------------------
# Вкладка Logon Scripts
# ------------------------------------------------------------
class LogonScriptsTab(BaseStartupTab):
    def __init__(self):
        super().__init__(["Имя", "Значение", "Дата создания"])
        self.reg_path = r"Environment"
        self.hive = winreg.HKEY_CURRENT_USER

    def load_data(self):
        entries = []
        raw = get_logon_scripts()
        for e in raw:
            entries.append({
                'display_order': ['name', 'command', 'created'],
                'name': e['name'],
                'command': e['command'],
                'created': e['created'],
                'type': e['type']
            })
        self.entries = entries
        self._update_table()

    def show_context_menu(self, position):
        selected_rows = list(set(idx.row() for idx in self.table.selectedIndexes()))
        menu = QMenu()
        help_action = menu.addAction("Справка")
        if selected_rows:
            menu.addSeparator()
            if len(selected_rows) == 1:
                delete_action = menu.addAction("Удалить скрипт")
                open_folder_action = menu.addAction("Открыть папку")
                edit_action = menu.addAction("Изменить значение")
            else:
                delete_action = menu.addAction(f"Удалить выбранные ({len(selected_rows)})")
                open_folder_action = edit_action = None
        else:
            delete_action = open_folder_action = edit_action = None
        menu.addSeparator()
        add_action = menu.addAction("Добавить скрипт входа")
        action = menu.exec(self.table.mapToGlobal(position))

        if action == help_action:
            self.show_help()
        elif add_action and action == add_action:
            self._add_entry()
        elif selected_rows:
            if action == delete_action:
                if len(selected_rows) > 1:
                    self._delete_selected()
                else:
                    self._delete_entry(self.entries[selected_rows[0]])
            elif action == open_folder_action and len(selected_rows) == 1:
                self._open_folder(self.entries[selected_rows[0]])
            elif action == edit_action and len(selected_rows) == 1:
                self._edit_entry(self.entries[selected_rows[0]])

    def _delete_selected(self):
        selected_rows = list(set(idx.row() for idx in self.table.selectedIndexes()))
        if not selected_rows:
            return
        reply = QMessageBox.question(self, "Подтверждение",
                                     f"Удалить {len(selected_rows)} скриптов?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        for row in selected_rows:
            entry = self.entries[row]
            try:
                with winreg.OpenKey(self.hive, self.reg_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, entry['name'])
            except Exception:
                pass
        self.load_data()

    def show_help(self):
        QMessageBox.information(self, "Справка: Logon Scripts",
                                "Скрипт, выполняемый при входе пользователя (UserInitMprLogonScript).")

    def _add_entry(self):
        command, ok = QInputDialog.getText(self, "Добавление скрипта входа",
                                           "Путь к исполняемому файлу или скрипту:")
        if not ok or not command:
            return
        try:
            with winreg.OpenKey(self.hive, self.reg_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "UserInitMprLogonScript", 0, winreg.REG_SZ, command)
            QMessageBox.information(self, "Успех", "Скрипт добавлен.")
            self.load_data()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось добавить скрипт: {e}")

    def _edit_entry(self, entry):
        new_value, ok = QInputDialog.getText(self, "Изменение значения",
                                             "Новое значение:", QLineEdit.Normal, entry['command'])
        if ok and new_value != entry['command']:
            try:
                with winreg.OpenKey(self.hive, self.reg_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, entry['name'], 0, winreg.REG_SZ, new_value)
                QMessageBox.information(self, "Успех", "Значение обновлено.")
                self.load_data()
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось изменить значение: {e}")

    def _delete_entry(self, entry):
        reply = QMessageBox.question(self, "Подтверждение",
                                     f"Удалить скрипт '{entry['name']}'?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        try:
            with winreg.OpenKey(self.hive, self.reg_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, entry['name'])
            QMessageBox.information(self, "Успех", "Скрипт удалён.")
            self.load_data()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось удалить скрипт: {e}")

    def _open_folder(self, entry):
        cmd = entry['command']
        if cmd and os.path.exists(cmd):
            folder = os.path.dirname(cmd)
            if os.path.isdir(folder):
                os.startfile(folder)

# ------------------------------------------------------------
# Основная страница автозагрузок
# ------------------------------------------------------------
class StartupPage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.main_tabs = QTabWidget()

        self.registry_tabs = QTabWidget()
        self.registry_tabs.addTab(RegistryRunTab(), "Run")
        self.registry_tabs.addTab(RegistryRunOnceTab(), "RunOnce")
        self.registry_tabs.addTab(WinlogonTab(), "Winlogon")
        self.registry_tabs.addTab(ShellServiceObjectsTab(), "ShellServiceObjects")
        self.registry_tabs.addTab(AppInitDLLsTab(), "AppInit_DLLs")
        self.registry_tabs.addTab(KnownDLLsTab(), "KnownDLLs")
        self.main_tabs.addTab(self.registry_tabs, "Реестр")

        self.main_tabs.addTab(StartupFoldersTab(), "Папки автозагрузки")
        self.main_tabs.addTab(ScheduledTasksTab(), "Планировщик задач")
        self.main_tabs.addTab(ServicesTab(), "Службы")
        self.main_tabs.addTab(ActiveSetupTab(), "Active Setup")
        self.main_tabs.addTab(LogonScriptsTab(), "Logon Scripts")

        layout.addWidget(self.main_tabs)
        self.setLayout(layout)