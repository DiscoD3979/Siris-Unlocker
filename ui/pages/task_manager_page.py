import hashlib
import subprocess
import os
import psutil
import ctypes
import shiboken6
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
    QTreeWidget, QTreeWidgetItem, QMenu, QHeaderView, QAbstractItemView, QMessageBox,
    QSlider, QLabel
)
from PySide6.QtCore import Qt, QTimer, QRect, Property, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QColor, QPainter, QFont

from core.process_manager import (
    get_process_list, is_process_critical, set_process_critical,
    kill_process, suspend_process, resume_process, find_executable_in_path,
    is_suspicious_process, get_signature_info
)
from core.virustotal import check_file_virustotal


class ToggleSwitch(QSlider):
    def __init__(self, parent=None):
        super().__init__(Qt.Horizontal, parent)
        self.setRange(0, 1)
        self.setPageStep(1)
        self.setFixedSize(40, 20)

        self._anim = QPropertyAnimation(self, b"handle_pos")
        self._anim.setDuration(150)
        self._anim.setEasingCurve(QEasingCurve.InOutCubic)

        self.valueChanged.connect(self._on_value_changed)

    def _on_value_changed(self, val):
        self._anim.setEndValue(val)
        self._anim.start()

    def _get_handle_pos(self):
        return self.value()

    def _set_handle_pos(self, val):
        self.setValue(val)

    handle_pos = Property(int, _get_handle_pos, _set_handle_pos)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        track_rect = QRect(2, 2, self.width() - 4, self.height() - 4)
        if self.value() == 1:
            painter.setBrush(QColor("#430261"))
        else:
            painter.setBrush(QColor("#555555"))
        painter.setPen(Qt.NoPen)
        painter.drawRoundedRect(track_rect, 8, 8)

        progress = self._anim.currentValue() if self._anim.state() == QPropertyAnimation.Running else self.value()
        handle_x = int(2 + (self.width() - self.height()) * progress)
        handle_rect = QRect(handle_x, 2, self.height() - 4, self.height() - 4)
        painter.setBrush(QColor("#FFFFFF"))
        painter.drawEllipse(handle_rect)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.setValue(1 - self.value())
            # НЕ вызываем super().mousePressEvent, чтобы избежать двойного переключения
            event.accept()
        else:
            super().mousePressEvent(event)

class TaskManagerPage(QWidget):
    def __init__(self):
        super().__init__()
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(6, 6, 6, 6)
        main_layout.setSpacing(5)

        # === Верхняя панель ===
        top_layout = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Поиск процесса...")
        self.search_edit.textChanged.connect(self.on_search_text_changed)

        auto_layout = QHBoxLayout()
        auto_layout.setSpacing(3)
        self.auto_refresh_toggle = ToggleSwitch()
        self.auto_refresh_toggle.setValue(0)                     # по умолчанию ВЫКЛ (серый)
        self.auto_refresh_toggle.valueChanged.connect(self.toggle_auto_refresh)
        auto_label = QLabel("Автообновление")
        auto_label.setStyleSheet("color: #a0a0a0; font-size: 8pt;")
        auto_layout.addWidget(self.auto_refresh_toggle)
        auto_layout.addWidget(auto_label)

        self.run_edit = QLineEdit()
        self.run_edit.setPlaceholderText("Введите команду... (explorer.exe)")
        self.run_edit.returnPressed.connect(self.execute_command)

        self.execute_btn = QPushButton("Выполнить")
        self.execute_btn.clicked.connect(self.execute_command)

        top_layout.addWidget(self.search_edit)
        top_layout.addLayout(auto_layout)
        top_layout.addWidget(self.run_edit)
        top_layout.addWidget(self.execute_btn)
        main_layout.addLayout(top_layout)

        # === Таблица процессов ===
        self.tree = QTreeWidget()
        self.tree.setColumnCount(4)
        self.tree.setHeaderLabels(["Имя Процесса", "Айди", "Критичный", "Расположение"])
        self.tree.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tree.header().setSectionsMovable(True)
        self.tree.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tree.setSelectionMode(QAbstractItemView.SingleSelection)

        header = self.tree.header()
        header.setSectionResizeMode(0, QHeaderView.Interactive)
        header.setSectionResizeMode(1, QHeaderView.Interactive)
        header.setSectionResizeMode(2, QHeaderView.Interactive)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        self.tree.setColumnWidth(0, 200)
        self.tree.setColumnWidth(1, 80)
        self.tree.setColumnWidth(2, 80)

        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_context_menu)

        main_layout.addWidget(self.tree)
        self.setLayout(main_layout)

        self.all_processes = []
        self.items_by_pid = {}
        self.group_items = {}
        self.expanded_pids = set()
        self.expanded_groups = {}
        self.first_load = True
        self.critical_color = QColor("#ff5a5a")
        self.suspicious_color = QColor("#4cff88")

        self.auto_refresh_enabled = False          # соответствует значению по умолчанию
        self.timer = QTimer()
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.refresh_processes)
        # таймер НЕ запускаем, так как автообновление выключено

        self._create_groups()
        # Запускаем первоначальное построение дерева
        self.refresh_processes()

    # ------------------------------------------------------------
    def _categorize_top_level_item(self, item):
        """Определяет категорию для элемента верхнего уровня по пути и имени."""
        path = item.text(3).lower()
        name = item.text(0).lower()
        if path.startswith('c:\\windows\\') or path.startswith('c:\\windows\\system32\\'):
            if name in ['system', 'system idle process', 'registry', 'smss.exe', 'csrss.exe',
                        'wininit.exe', 'services.exe', 'lsass.exe', 'svchost.exe', 'winlogon.exe', 'dwm.exe']:
                return 'system'
            else:
                return 'background'
        else:
            return 'user'

    # ------------------------------------------------------------
    def toggle_auto_refresh(self, value):
        self.auto_refresh_enabled = bool(value)
        if self.auto_refresh_enabled:
            self.timer.start()
        else:
            self.timer.stop()

    def execute_command(self):
        command = self.run_edit.text().strip()
        if not command:
            return
        try:
            # Если указан существующий файл, запускаем его напрямую
            if os.path.exists(command):
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", command, None, None, 1
                )
            else:
                # Ищем исполняемый файл в системном PATH
                import shutil
                full_path = shutil.which(command)
                if full_path:
                    ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", full_path, None, None, 1
                    )
                else:
                    # Запускаем как есть (например, если переданы аргументы)
                    ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", command, None, None, 1
                    )
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось выполнить команду: {e}")

    # ------------------------------------------------------------
    def save_expanded_state(self):
        # Сохраняем состояние групп
        self.expanded_groups = {}
        for key, group in self.group_items.items():
            if shiboken6.isValid(group):
                self.expanded_groups[key] = group.isExpanded()

        # Сохраняем состояние процессов по PID (как в старом коде)
        self.expanded_pids.clear()
        for pid, item in self.items_by_pid.items():
            if item.isExpanded():
                self.expanded_pids.add(pid)

    def restore_expanded_state(self):
        # Восстанавливаем группы
        for key, group in self.group_items.items():
            if key in getattr(self, 'expanded_groups', {}):
                group.setExpanded(self.expanded_groups[key])
            else:
                group.setExpanded(True)  # По умолчанию группы развёрнуты

        # Восстанавливаем процессы по PID
        for pid in self.expanded_pids:
            if pid in self.items_by_pid:
                self.items_by_pid[pid].setExpanded(True)

    def refresh_processes(self):
        if not self.auto_refresh_enabled and not self.first_load:
            return

        self.save_expanded_state()
        self.all_processes = get_process_list()
        self.rebuild_tree()

        if self.first_load:
            self.tree.expandAll()  # Раскрывает всё, включая группы и процессы
            self.first_load = False
        else:
            self.restore_expanded_state()
        self.apply_filter()

    def rebuild_tree(self):
        self.tree.clear()
        self.items_by_pid.clear()

        # Создаём элементы для всех процессов
        for proc in self.all_processes:
            pid = proc['pid']
            name = proc['name'] or "?"
            path = proc['exe'] or "Нет доступа"
            critical = "Да" if is_process_critical(proc) else "Нет"

            item = QTreeWidgetItem([name, str(pid), critical, path])

            if critical == "Да":
                for col in range(4):
                    item.setForeground(col, self.critical_color)
            elif is_suspicious_process(proc):
                for col in range(4):
                    item.setForeground(col, self.suspicious_color)

            self.items_by_pid[pid] = item

        # Определяем PID процессов explorer.exe
        explorer_pids = {
            proc['pid'] for proc in self.all_processes
            if proc.get('name') and proc['name'].lower() == 'explorer.exe'
        }

        # Строим иерархию и собираем элементы верхнего уровня
        top_level_items = []
        for proc in self.all_processes:
            pid = proc['pid']
            ppid = proc.get('ppid')
            item = self.items_by_pid[pid]

            if ppid in explorer_pids:
                top_level_items.append(item)
            elif ppid in self.items_by_pid and ppid != pid:
                self.items_by_pid[ppid].addChild(item)
            else:
                top_level_items.append(item)

        # Сортируем элементы верхнего уровня: сначала пользовательские, потом системные
        def sort_key(item):
            path = item.text(3).lower()
            return 1 if path.startswith("c:\\windows") else 0
        top_level_items.sort(key=sort_key)

        # Пересоздаём группы
        user_group = QTreeWidgetItem(["Приложения", "", "", ""])
        background_group = QTreeWidgetItem(["Фоновые процессы", "", "", ""])
        system_group = QTreeWidgetItem(["Системные процессы", "", "", ""])

        for group in (user_group, background_group, system_group):
            group.setFlags(group.flags() & ~Qt.ItemIsSelectable)
            group.setFirstColumnSpanned(True)
            font = QFont()
            font.setBold(True)
            group.setFont(0, font)
            group.setForeground(0, QColor("#AAAAAA"))

        self.group_items = {
            'user': user_group,
            'background': background_group,
            'system': system_group
        }

        # Распределяем элементы верхнего уровня по категориям
        for item in top_level_items:
            category = self._categorize_top_level_item(item)
            self.group_items[category].addChild(item)

        # Добавляем группы в дерево
        self.tree.addTopLevelItem(self.group_items['user'])
        self.tree.addTopLevelItem(self.group_items['background'])
        self.tree.addTopLevelItem(self.group_items['system'])

    def on_search_text_changed(self):
        self.apply_filter()

    def apply_filter(self):
        filter_text = self.search_edit.text().strip().lower()

        if not filter_text:
            for item in self.items_by_pid.values():
                item.setHidden(False)
            for group in self.group_items.values():
                group.setHidden(False)
                group.setExpanded(True)
            return

        # Сначала всё скрываем
        for item in self.items_by_pid.values():
            item.setHidden(True)

        # Показываем подходящие элементы и раскрываем родителей
        for item in self.items_by_pid.values():
            match = any(filter_text in item.text(col).lower() for col in range(4))
            if match:
                item.setHidden(False)

                # Раскрываем всех родителей
                parent = item.parent()
                while parent:
                    parent.setHidden(False)
                    parent.setExpanded(True)
                    parent = parent.parent()

        # Показываем только группы, где есть видимые элементы
        for group in self.group_items.values():
            has_visible = False
            for i in range(group.childCount()):
                if not group.child(i).isHidden():
                    has_visible = True
                    break
            group.setHidden(not has_visible)
            if has_visible:
                group.setExpanded(True)

    def _create_groups(self):
        """Создаёт три группы верхнего уровня (используется при инициализации)."""
        user_group = QTreeWidgetItem(["Приложения", "", "", ""])
        background_group = QTreeWidgetItem(["Фоновые процессы", "", "", ""])
        system_group = QTreeWidgetItem(["Системные процессы", "", "", ""])

        for group in (user_group, background_group, system_group):
            group.setFlags(group.flags() & ~Qt.ItemIsSelectable)
            group.setFirstColumnSpanned(True)
            font = QFont()
            font.setBold(True)
            group.setFont(0, font)
            group.setForeground(0, QColor("#AAAAAA"))

        self.group_items = {
            'user': user_group,
            'background': background_group,
            'system': system_group
        }

    # ------------------------------------------------------------
    def show_context_menu(self, position):
        item = self.tree.currentItem()
        if not item or not shiboken6.isValid(item) or item in self.group_items.values():
            return

        pid = int(item.text(1))
        proc_info = next((p for p in self.all_processes if p['pid'] == pid), None)
        if not proc_info:
            return

        menu = QMenu()
        kill_action = menu.addAction("Убить процесс")
        suspend_action = menu.addAction("Заморозить процесс")
        resume_action = menu.addAction("Разморозить процесс")
        menu.addSeparator()
        toggle_critical_action = menu.addAction("Сменить критичность")
        menu.addSeparator()
        open_folder_action = menu.addAction("Открыть папку с файлом")
        menu.addSeparator()
        vt_action = menu.addAction("Проверить на VirusTotal")
        menu.addSeparator()
        sig_action = menu.addAction("Информация о подписи")

        action = menu.exec(self.tree.mapToGlobal(position))

        if action == kill_action:
            self._confirm_and_kill(pid, proc_info)
        elif action == suspend_action:
            if suspend_process(pid):
                QMessageBox.information(self, "Успех", f"Процесс {proc_info['name']} ({pid}) заморожен.")
                self.refresh_processes()
            else:
                QMessageBox.warning(self, "Ошибка", "Не удалось заморозить процесс.")
        elif action == resume_action:
            if resume_process(pid):
                QMessageBox.information(self, "Успех", f"Процесс {proc_info['name']} ({pid}) разморожен.")
                self.refresh_processes()
            else:
                QMessageBox.warning(self, "Ошибка", "Не удалось разморозить процесс.")
        elif action == toggle_critical_action:
            current = is_process_critical(proc_info)
            set_process_critical(pid, not current)
            self.refresh_processes()
        elif action == open_folder_action:
            self.open_process_folder(proc_info)
        elif action == vt_action:
            self.check_virustotal(proc_info)
        elif action == sig_action:
            self._show_signature_info(proc_info)

    def _confirm_and_kill(self, pid, proc_info):
        critical = is_process_critical(proc_info)
        if critical:
            reply = QMessageBox.question(
                self, "Подтверждение",
                f"Процесс '{proc_info['name']}' ({pid}) отмечен как критический.\n"
                "Его завершение может привести к нестабильной работе системы.\n\n"
                "Вы уверены, что хотите продолжить?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply != QMessageBox.Yes:
                return
        if kill_process(pid):
            QMessageBox.information(self, "Успех", f"Процесс {proc_info['name']} ({pid}) завершён.")
            self.refresh_processes()
        else:
            QMessageBox.warning(self, "Ошибка", "Не удалось завершить процесс.")

    def _show_signature_info(self, proc_info):
        exe_path = proc_info.get('exe')
        if not exe_path or exe_path == "Нет доступа" or not os.path.isfile(exe_path):
            QMessageBox.warning(self, "Предупреждение", "Не удалось определить путь к исполняемому файлу.")
            return
        sig = get_signature_info(exe_path)
        if not sig:
            QMessageBox.information(self, "Информация о подписи", "Не удалось получить информацию о подписи.")
            return
        status = sig['status']
        signer = sig.get('signer', 'Не указан')
        issuer = sig.get('issuer', 'Не указан')
        status_text = "Действительна" if status == 'Valid' else ("Не подписана" if status == 'NotSigned' else status)
        msg = f"Статус: {status_text}\n\nИздатель:\n{signer}\n\nЭмитент:\n{issuer}"
        QMessageBox.information(self, "Информация о цифровой подписи", msg)

    def check_virustotal(self, proc_info):
        exe_path = proc_info.get('exe')
        if not exe_path or exe_path == "Нет доступа" or not os.path.isfile(exe_path):
            QMessageBox.warning(self, "Предупреждение", "Не удалось определить путь к исполняемому файлу.")
            return
        malicious, total, link = check_file_virustotal(exe_path, self)
        if malicious is None:
            return
        if total == 0 and malicious == 0:
            try:
                with open(exe_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
            except Exception:
                file_hash = "не удалось вычислить"
            QMessageBox.information(self, "Результат проверки",
                                    f"Файл не найден в базе VirusTotal.\n\nХэш файла: {file_hash}")
        else:
            msg = f"Файл: {os.path.basename(exe_path)}\nОбнаружено вредоносных: {malicious} из {total}\n\n"
            if link:
                msg += f"Ссылка на отчёт:\n{link}"
            else:
                msg += "Отчёт недоступен."
            QMessageBox.information(self, "Результат проверки", msg)

    def open_process_folder(self, proc_info):
        exe_path = proc_info.get('exe')
        if not exe_path or exe_path == "Нет доступа" or not os.path.isfile(exe_path):
            return
        folder = os.path.dirname(exe_path)
        if os.path.isdir(folder):
            subprocess.Popen(f'explorer /select,"{exe_path}"')