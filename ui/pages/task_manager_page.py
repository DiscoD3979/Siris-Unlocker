import hashlib
import subprocess
import os
import psutil
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
    QTreeWidget, QTreeWidgetItem, QMenu, QHeaderView, QAbstractItemView, QMessageBox,
    QCheckBox
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor

from core.process_manager import (
    get_process_list, is_process_critical, set_process_critical,
    kill_process, suspend_process, resume_process, find_executable_in_path,
    is_suspicious_process, get_signature_info
)
from core.virustotal import check_file_virustotal


class TaskManagerPage(QWidget):
    def __init__(self):
        super().__init__()

        main_layout = QVBoxLayout()

        # === Верхняя панель ===
        top_layout = QHBoxLayout()

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Поиск процесса...")
        self.search_edit.textChanged.connect(self.on_search_text_changed)

        self.run_edit = QLineEdit()
        self.run_edit.setPlaceholderText("Введите имя (explorer.exe)")
        self.run_button = QPushButton("Запустить")
        self.run_button.clicked.connect(self.run_process)

        self.auto_refresh_check = QCheckBox("Автообновление (1 сек)")
        self.auto_refresh_check.setChecked(True)
        self.auto_refresh_check.toggled.connect(self.toggle_auto_refresh)

        top_layout.addWidget(self.search_edit)
        top_layout.addWidget(self.run_edit)
        top_layout.addWidget(self.run_button)
        top_layout.addWidget(self.auto_refresh_check)
        main_layout.addLayout(top_layout)

        # === Таблица процессов ===
        self.tree = QTreeWidget()
        self.tree.setColumnCount(4)
        self.tree.setHeaderLabels(["Файл", "Айди", "Критический", "Расположение"])
        self.tree.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tree.header().setSectionsMovable(False)
        self.tree.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tree.setSelectionMode(QAbstractItemView.SingleSelection)

        header = self.tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Interactive)
        header.setSectionResizeMode(2, QHeaderView.Interactive)
        header.setSectionResizeMode(3, QHeaderView.Stretch)

        self.tree.setColumnWidth(1, 80)
        self.tree.setColumnWidth(2, 100)

        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_context_menu)

        main_layout.addWidget(self.tree)
        self.setLayout(main_layout)

        self.all_processes = []
        self.items_by_pid = {}
        self.expanded_pids = set()
        self.first_load = True
        self.critical_color = QColor(80, 0, 0)
        self.suspicious_color = QColor(0, 80, 0)

        self.timer = QTimer()
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.refresh_processes)
        self.timer.start()

        self.refresh_processes()

    # ------------------------------------------------------------
    def toggle_auto_refresh(self, checked):
        if checked:
            self.timer.start()
        else:
            self.timer.stop()

    # ------------------------------------------------------------
    def refresh_processes(self):
        self.save_expanded_state()
        self.all_processes = get_process_list()
        self.rebuild_tree()
        if self.first_load:
            self.tree.expandAll()
            self.first_load = False
        else:
            self.restore_expanded_state()
        self.apply_filter()

    def save_expanded_state(self):
        self.expanded_pids.clear()
        for pid, item in self.items_by_pid.items():
            if item.isExpanded():
                self.expanded_pids.add(pid)

    def restore_expanded_state(self):
        for pid in self.expanded_pids:
            if pid in self.items_by_pid:
                self.items_by_pid[pid].setExpanded(True)

    def rebuild_tree(self):
        self.tree.clear()
        self.items_by_pid.clear()

        for proc in self.all_processes:
            pid = proc['pid']
            name = proc['name'] or "?"
            path = proc['exe'] or "Нет доступа"
            critical = "Да" if is_process_critical(proc) else "Нет"

            item = QTreeWidgetItem([name, str(pid), critical, path])

            if critical == "Да":
                for col in range(4):
                    item.setBackground(col, self.critical_color)
            else:
                if is_suspicious_process(proc):
                    for col in range(4):
                        item.setBackground(col, self.suspicious_color)

            self.items_by_pid[pid] = item

        explorer_pids = {
            proc['pid'] for proc in self.all_processes
            if proc.get('name') and proc['name'].lower() == 'explorer.exe'
        }

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

        def sort_key(item):
            path = item.text(3).lower()
            return 1 if path.startswith("c:\\windows") else 0

        top_level_items.sort(key=sort_key)

        for item in top_level_items:
            self.tree.addTopLevelItem(item)

    def on_search_text_changed(self):
        self.apply_filter()

    def apply_filter(self):
        filter_text = self.search_edit.text().strip().lower()
        if not filter_text:
            for item in self.items_by_pid.values():
                item.setHidden(False)
            return

        for item in self.items_by_pid.values():
            match = any(filter_text in item.text(col).lower() for col in range(4))
            item.setHidden(not match)

    # ------------------------------------------------------------
    def show_context_menu(self, position):
        item = self.tree.currentItem()
        if not item:
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
        menu.addSeparator()
        if self._is_item_suspicious(item):
            reason_action = menu.addAction("Почему подозрительный?")

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
            self._show_signature_info_enhanced(proc_info)
        elif 'reason_action' in locals() and action == reason_action:
            self._show_suspicious_reason(proc_info)

    def _confirm_and_kill(self, pid, proc_info):
        critical = is_process_critical(proc_info)
        if critical:
            reply = QMessageBox.question(
                self,
                "Подтверждение",
                f"Процесс '{proc_info['name']}' ({pid}) отмечен как критический.\n"
                "Его завершение может привести к нестабильной работе системы.\n\n"
                "Вы уверены, что хотите продолжить?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply != QMessageBox.Yes:
                return

        if kill_process(pid):
            QMessageBox.information(self, "Успех", f"Процесс {proc_info['name']} ({pid}) завершён.")
            self.refresh_processes()
        else:
            QMessageBox.warning(self, "Ошибка", "Не удалось завершить процесс.")

    def _is_item_suspicious(self, item):
        if item.text(2) == "Да":
            return False
        color = item.background(0).color()
        return color == self.suspicious_color

    def _show_signature_info_enhanced(self, proc_info):
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

        # Текстовая замена статуса
        if status == 'Valid':
            status_text = "Действительна"
        elif status == 'NotSigned':
            status_text = "Не подписана"
        else:
            status_text = status

        msg = (
            f"Статус: {status_text}\n\n"
            f"Издатель:\n{signer}\n\n"
            f"Эмитент:\n{issuer}"
        )
        QMessageBox.information(self, "Информация о цифровой подписи", msg)

    def _show_suspicious_reason(self, proc_info):
        reasons = []
        exe = proc_info.get('exe')
        name = proc_info.get('name', '').lower()

        if exe and not exe.lower().startswith('c:\\windows'):
            system_names = ['svchost.exe', 'lsass.exe', 'winlogon.exe', 'services.exe', 'csrss.exe',
                            'smss.exe', 'wininit.exe', 'spoolsv.exe', 'taskhostw.exe', 'dwm.exe',
                            'explorer.exe', 'rundll32.exe']
            if name in system_names:
                reasons.append(f"- Имя процесса '{name}' похоже на системное, но путь не системный.")

        if not reasons:
            reasons.append("- Не удалось определить причину. Возможно, процесс был помечен по другим критериям.")
        msg = "Процесс помечен как подозрительный по следующим причинам:\n\n" + "\n".join(reasons)
        QMessageBox.information(self, "Подозрительный процесс", msg)

    # ------------------------------------------------------------
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
            msg = (f"Файл: {os.path.basename(exe_path)}\n"
                   f"Обнаружено вредоносных: {malicious} из {total}\n\n")
            if link:
                msg += f"Ссылка на отчёт:\n{link}"
            else:
                msg += "Отчёт недоступен."
            QMessageBox.information(self, "Результат проверки", msg)

    def run_process(self):
        name = self.run_edit.text().strip()
        if not name:
            return

        if not os.path.isabs(name) and not name.startswith('"'):
            full_path = find_executable_in_path(name)
            if full_path:
                name = full_path

        try:
            creationflags = subprocess.CREATE_NEW_CONSOLE if os.name == 'nt' else 0
            subprocess.Popen(name, shell=True, creationflags=creationflags)
        except Exception:
            pass

    def open_process_folder(self, proc_info):
        exe_path = proc_info.get('exe')
        if not exe_path or exe_path == "Нет доступа" or not os.path.isfile(exe_path):
            return
        folder = os.path.dirname(exe_path)
        if os.path.isdir(folder):
            subprocess.Popen(f'explorer /select,"{exe_path}"')