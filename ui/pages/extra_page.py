# ---------- Импорты (оставляем как есть) ----------
import webbrowser
import subprocess
import winreg
import os
from ctypes import wintypes
import shutil
import tempfile
import sys
import hashlib
import ctypes
import psutil
import platform
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QGridLayout, QPushButton, QLabel, QMessageBox,
    QFileDialog, QMenu, QApplication, QToolTip
)
from PySide6.QtCore import Qt, QAbstractNativeEventFilter

from core.virustotal import check_file_virustotal

# ------------------------------------------------------------
# Константы для глобальной горячей клавиши
# ------------------------------------------------------------
MOD_ALT = 0x0001
VK_GRAVE = 0xC0          # клавиша ` (тильда)
WM_HOTKEY = 0x0312
HOTKEY_ID_LAUNCH = 2     # один ID на всё

# ------------------------------------------------------------
# Фильтр событий (оставляем тот же)
# ------------------------------------------------------------
class HotkeyFilter(QAbstractNativeEventFilter):
    def __init__(self, parent_window, extra_page):
        super().__init__()
        self.parent_window = parent_window
        self.extra_page = extra_page

    def nativeEventFilter(self, eventType, message):
        if eventType == "windows_generic_MSG":
            msg = wintypes.MSG.from_address(int(message))
            if msg.message == WM_HOTKEY and msg.wParam == HOTKEY_ID_LAUNCH:
                self.extra_page.activate_or_launch()
                return True, 0
        return False, 0

# ------------------------------------------------------------
# Страница ExtraPage (только нужные изменения)
# ------------------------------------------------------------
class ExtraPage(QWidget):
    def __init__(self):
        super().__init__()
        self.parent_window = None
        self.hotkey_filter = None
        self.hotkey_registered = False

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(6, 6, 6, 6)
        main_layout.setSpacing(5)

        grid = QGridLayout()
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(8)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)

        button_min_width = 200
        button_min_height = 38

        row = 0
        # Ряд 1
        self.btn_drweb = self._create_button("DoctorWeb", self.open_drweb,
                                             "Открыть официальный сайт Dr.Web CureIt для загрузки лечащей утилиты",
                                             min_width=button_min_width, min_height=button_min_height)
        self.btn_uac = self._create_button("UAC", self.enable_uac_level3,
                                           "Включить контроль учётных записей (UAC) на максимальный уровень",
                                           min_width=button_min_width, min_height=button_min_height)
        grid.addWidget(self.btn_drweb, row, 0)
        grid.addWidget(self.btn_uac, row, 1)

        row += 1
        self.btn_hosts = self._create_button("Восст. Hosts", self.restore_hosts,
                                             "Восстановить файл hosts до стандартного состояния Windows",
                                             min_width=button_min_width, min_height=button_min_height)
        self.btn_clean = self._create_button("Очистка Temp", self.clean_temp,
                                             "Удалить временные файлы из папок Temp, Windows\\Temp и Prefetch",
                                             min_width=button_min_width, min_height=button_min_height)
        grid.addWidget(self.btn_hosts, row, 0)
        grid.addWidget(self.btn_clean, row, 1)

        row += 1
        self.btn_defender = self._create_button("Защит. Windows", self.toggle_defender,
                                                "Включить или отключить антивирусную программу 'Защитник Windows'",
                                                min_width=button_min_width, min_height=button_min_height)
        self.btn_assoc = self._create_button("Сброс ассоциаций .exe", self.reset_exe_assoc,
                                             "Восстановить стандартную ассоциацию для исполняемых .exe файлов",
                                             min_width=button_min_width, min_height=button_min_height)
        grid.addWidget(self.btn_defender, row, 0)
        grid.addWidget(self.btn_assoc, row, 1)

        row += 1
        self.btn_vt = self._create_button("VirusTotal", self.check_file_vt,
                                          "Проверить выбранный файл на наличие угроз через сервис VirusTotal",
                                          min_width=button_min_width, min_height=button_min_height)
        self.btn_restart_explorer = self._create_button("↻ Explorer", self.restart_explorer,
                                                        "Перезапустить процесс проводника Windows (explorer.exe)",
                                                        min_width=button_min_width, min_height=button_min_height)
        grid.addWidget(self.btn_vt, row, 0)
        grid.addWidget(self.btn_restart_explorer, row, 1)

        row += 1
        self.btn_sysinfo = self._create_button("Инфо системы", self.show_system_info,
                                               "Показать подробную информацию о системе (ЦП, ОЗУ, GPU, ОС)",
                                               min_width=button_min_width, min_height=button_min_height)
        self.btn_sfc = self._create_button("SFC /Scannow", self.run_sfc,
                                           "Запустить проверку и восстановление целостности системных файлов Windows",
                                           min_width=button_min_width, min_height=button_min_height)
        grid.addWidget(self.btn_sysinfo, row, 0)
        grid.addWidget(self.btn_sfc, row, 1)

        row += 1
        self.btn_startup_menu = self._create_button("+ Автозагрузка", self.show_startup_menu,
                                                    "Добавить SirisUnlocker в автозапуск (реестр, планировщик, папка или оболочка)",
                                                    min_width=button_min_width, min_height=button_min_height)
        self.btn_remove_startup = self._create_button("- Автозагрузка", self.remove_self_from_startup,
                                                      "Удалить SirisUnlocker из всех мест автозагрузки",
                                                      min_width=button_min_width, min_height=button_min_height)
        grid.addWidget(self.btn_startup_menu, row, 0)
        grid.addWidget(self.btn_remove_startup, row, 1)

        row += 1
        self.always_on_top_btn = self._create_button("Поверх окон", self.toggle_always_on_top,
                                                     "Переключить режим отображения окна поверх всех остальных окон",
                                                     min_width=button_min_width, min_height=button_min_height)
        self.always_on_top_btn.setCheckable(True)
        self.always_on_top_btn.setChecked(True)
        self.btn_safe = self._create_button("Safe режим (cmd)", self.boot_safe_mode,
                                            "Перезагрузить компьютер в безопасном режиме с поддержкой командной строки",
                                            min_width=button_min_width, min_height=button_min_height)
        grid.addWidget(self.always_on_top_btn, row, 0)
        grid.addWidget(self.btn_safe, row, 1)

        row += 1
        self.btn_normal = self._create_button("Обычный режим", self.boot_normal_mode,
                                              "Отключить безопасный режим и перезагрузить компьютер в обычном режиме",
                                              min_width=button_min_width, min_height=button_min_height)
        self.btn_reset_shell = self._create_button("Сброс Shell", self.reset_shell,
                                                   "Восстановить стандартную оболочку Windows (explorer.exe) и параметр Userinit",
                                                   min_width=button_min_width, min_height=button_min_height)
        grid.addWidget(self.btn_normal, row, 0)
        grid.addWidget(self.btn_reset_shell, row, 1)

        row += 1
        self.btn_sticky_replace = self._create_button("Подм. залип.", self.replace_sticky_keys,
                                                      "Заменить sethc.exe (залипание клавиш) на SirisUnlocker (требуется перезагрузка)",
                                                      min_width=button_min_width, min_height=button_min_height)
        self.btn_sticky_restore = self._create_button("Восст. залип.", self.restore_sticky_keys,
                                                      "Восстановить оригинальный файл sethc.exe из резервной копии",
                                                      min_width=button_min_width, min_height=button_min_height)
        grid.addWidget(self.btn_sticky_replace, row, 0)
        grid.addWidget(self.btn_sticky_restore, row, 1)

        row += 1
        self.btn_utilman_replace = self._create_button("Подм. спец.", self.replace_utilman,
                                                       "Заменить Utilman.exe (специальные возможности) на SirisUnlocker (требуется перезагрузка)",
                                                       min_width=button_min_width, min_height=button_min_height)
        self.btn_utilman_restore = self._create_button("Восст. спец.", self.restore_utilman,
                                                       "Восстановить оригинальный Utilman.exe из резервной копии",
                                                       min_width=button_min_width, min_height=button_min_height)
        grid.addWidget(self.btn_utilman_replace, row, 0)
        grid.addWidget(self.btn_utilman_restore, row, 1)

        # ---- ЕДИНСТВЕННАЯ КНОПКА ДЛЯ ГОРЯЧЕЙ КЛАВИШИ ----
        row += 1
        self.btn_hotkey = self._create_button("Alt+` (показать/запуск)", self.toggle_hotkey,
                                              "Глобальная клавиша: показать окно, если оно есть, иначе запустить программу",
                                              min_width=button_min_width, min_height=button_min_height)
        self.btn_hotkey.setCheckable(True)
        # По умолчанию можно включить (true), но тогда надо регистрировать хоткей сразу после showEvent
        # Оставим false – пользователь включит сам кнопкой
        self.btn_hotkey.setChecked(False)
        grid.addWidget(self.btn_hotkey, row, 0, 1, 2)   # растягиваем на две колонки

        # Растягиваем все строки
        for r in range(row + 1):
            grid.setRowStretch(r, 1)

        main_layout.addLayout(grid)
        main_layout.addStretch(1)
        self.setLayout(main_layout)

    def _create_button(self, text, slot, tooltip, min_width=140, min_height=36):
        btn = QPushButton(text)
        btn.setMinimumWidth(min_width)
        btn.setMinimumHeight(min_height)
        btn.setToolTip(tooltip)
        btn.clicked.connect(slot)
        return btn

    def set_parent_window(self, window):
        self.parent_window = window

    def _check_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    # ------------------------------------------------------
    #  Горячая клавиша (объединённая логика)
    # ------------------------------------------------------
    def toggle_hotkey(self):
        if not self.parent_window:
            self.btn_hotkey.setChecked(False)
            return
        if self.btn_hotkey.isChecked():
            success = self.register_hotkey(HOTKEY_ID_LAUNCH, VK_GRAVE)
            if success:
                self.hotkey_registered = True
                QMessageBox.information(self, "Успех", "Горячая клавиша Alt+` зарегистрирована.")
            else:
                self.btn_hotkey.setChecked(False)
                QMessageBox.critical(self, "Ошибка", "Не удалось зарегистрировать Alt+`. Возможно, клавиша уже занята.")
        else:
            self.unregister_hotkey(HOTKEY_ID_LAUNCH)
            self.hotkey_registered = False
            QMessageBox.information(self, "Успех", "Горячая клавиша Alt+` отключена.")

    def register_hotkey(self, hotkey_id, vk_code):
        if not self.parent_window:
            return False
        try:
            hwnd = int(self.parent_window.winId())
            result = ctypes.windll.user32.RegisterHotKey(hwnd, hotkey_id, MOD_ALT, vk_code)
            if result:
                if self.hotkey_filter is None:
                    self.hotkey_filter = HotkeyFilter(self.parent_window, self)
                    QApplication.instance().installNativeEventFilter(self.hotkey_filter)
                return True
            return False
        except Exception as e:
            print(f"RegisterHotKey failed: {e}")
            return False

    def unregister_hotkey(self, hotkey_id):
        if not self.parent_window:
            return
        try:
            hwnd = int(self.parent_window.winId())
            ctypes.windll.user32.UnregisterHotKey(hwnd, hotkey_id)
        except Exception as e:
            print(f"UnregisterHotKey failed: {e}")

    def activate_or_launch(self):
        """
        Вызывается по Alt+`:
        - Если главное окно существует (даже скрыто в трее) → показать и активировать.
        - Если окна нет (приложение закрыто) → запустить новый процесс.
        """
        if self.parent_window is not None:
            # Окно существует (скорее всего скрыто). Показываем и активируем.
            self.parent_window.showNormal()
            self.parent_window.raise_()
            self.parent_window.activateWindow()
        else:
            # Приложение полностью выгружено – запускаем новый экземпляр
            exe_path = self._get_self_exe()
            if exe_path:
                try:
                    subprocess.Popen([exe_path])
                except Exception as e:
                    QMessageBox.critical(self, "Ошибка", f"Не удалось запустить SirisUnlocker: {e}")

    # ---------- Стандартные методы ----------
    def open_drweb(self):
        webbrowser.open("https://free.drweb.uz/download+cureit+free/")

    def enable_uac_level3(self):
        reply = QMessageBox.question(self, "Подтверждение",
                                     "Включить UAC на уровень 3? Потребуется перезагрузка.",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        try:
            path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "EnableLUA", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ConsentPromptBehaviorAdmin", 0, winreg.REG_DWORD, 2)
                winreg.SetValueEx(key, "PromptOnSecureDesktop", 0, winreg.REG_DWORD, 1)
            QMessageBox.information(self, "Успех", "UAC настроен. Перезагрузите компьютер.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось изменить UAC: {e}")

    def restore_hosts(self):
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        backup_path = hosts_path + ".backup"
        default_content = (
            "# Copyright (c) 1993-2009 Microsoft Corp.\n"
            "#\n"
            "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\n"
            "#\n"
            "# This file contains the mappings of IP addresses to host names. Each\n"
            "# entry should be kept on an individual line. The IP address should\n"
            "# be placed in the first column followed by the corresponding host name.\n"
            "# The IP address and the host name should be separated by at least one\n"
            "# space.\n"
            "#\n"
            "# Additionally, comments (such as these) may be inserted on individual\n"
            "# lines or following the machine name denoted by a '#' symbol.\n"
            "#\n"
            "# For example:\n"
            "#\n"
            "#      102.54.94.97     rhino.acme.com          # source server\n"
            "#       38.25.63.10     x.acme.com              # x client host\n"
            "\n"
            "# localhost name resolution is handled within DNS itself.\n"
            "#	127.0.0.1       localhost\n"
            "#	::1             localhost\n"
        )
        reply = QMessageBox.question(self, "Подтверждение",
                                     f"Восстановить hosts? Будет создана резервная копия: {backup_path}",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        try:
            if os.path.exists(hosts_path):
                shutil.copy2(hosts_path, backup_path)
            with open(hosts_path, 'w', encoding='utf-8') as f:
                f.write(default_content)
            QMessageBox.information(self, "Успех", "Файл hosts восстановлен.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось восстановить hosts: {e}")

    def clean_temp(self):
        reply = QMessageBox.question(self, "Подтверждение",
                                     "Очистить временные файлы? Занятые файлы будут пропущены.",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        folders = [tempfile.gettempdir(), r"C:\Windows\Temp", r"C:\Windows\Prefetch"]
        total_deleted = 0
        total_errors = 0
        for folder in folders:
            if not os.path.exists(folder):
                continue
            for root, dirs, files in os.walk(folder, topdown=False):
                for name in files:
                    try:
                        os.remove(os.path.join(root, name))
                        total_deleted += 1
                    except Exception:
                        total_errors += 1
                for name in dirs:
                    try:
                        os.rmdir(os.path.join(root, name))
                    except Exception:
                        pass
        QMessageBox.information(self, "Результат",
                                f"Очистка завершена.\nУдалено файлов: {total_deleted}\nПропущено: {total_errors}")

    def reset_exe_assoc(self):
        reply = QMessageBox.question(self, "Подтверждение",
                                     "Сбросить ассоциации .exe к стандартным?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        try:
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, ".exe", 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, "exefile")
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, "exefile\\shell\\open\\command", 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, '"%1" %*')
            QMessageBox.information(self, "Успех", "Ассоциации .exe восстановлены.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сбросить ассоциации: {e}")

    def check_file_vt(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Выберите файл", "", "Все файлы (*)")
        if not file_path:
            return
        malicious, total, link = check_file_virustotal(file_path, self)
        if malicious is None:
            return
        if total == 0 and malicious == 0:
            try:
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
            except Exception:
                file_hash = "не удалось вычислить"
            QMessageBox.information(self, "Результат", f"Файл не найден в базе VirusTotal.\nХэш: {file_hash}")
        else:
            msg = (f"Файл: {os.path.basename(file_path)}\n"
                   f"Обнаружено вредоносных: {malicious} из {total}\n\n"
                   f"Ссылка: {link}" if link else "Отчёт недоступен.")
            QMessageBox.information(self, "Результат", msg)

    def toggle_always_on_top(self):
        if not self.parent_window:
            return
        on = self.always_on_top_btn.isChecked()
        self.parent_window.setWindowFlag(Qt.WindowStaysOnTopHint, on)
        self.parent_window.hide()
        self.parent_window.show()
        self.parent_window.raise_()

    # ---------- Новые методы ----------
    def run_sfc(self):
        if not self._check_admin():
            QMessageBox.critical(self, "Ошибка", "Необходимы права администратора.")
            return
        reply = QMessageBox.question(self, "Подтверждение",
                                     "Запустить проверку и восстановление системных файлов (sfc /scannow)?\n"
                                     "Процесс может занять длительное время.",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        try:
            subprocess.Popen('sfc /scannow', shell=True)
            QMessageBox.information(self, "Запущено", "Сканирование системных файлов запущено в отдельном окне.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось запустить sfc: {e}")

    def toggle_defender(self):
        if not self._check_admin():
            QMessageBox.critical(self, "Ошибка", "Необходимы права администратора.")
            return
        reply = QMessageBox.question(self, "Защитник Windows",
                                     "Выберите действие:\nYes - Включить\nNo - Отключить",
                                     QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
        if reply == QMessageBox.Cancel:
            return
        enable = (reply == QMessageBox.Yes)
        try:
            key_path = r"SOFTWARE\Policies\Microsoft\Windows Defender"
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                winreg.SetValueEx(key, "DisableAntiSpyware", 0, winreg.REG_DWORD, 0 if enable else 1)
            subprocess.run("gpupdate /force", shell=True, capture_output=True)
            QMessageBox.information(self, "Успех", f"Защитник {'включен' if enable else 'отключен'}. Рекомендуется перезагрузка.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось изменить настройки Защитника: {e}")

    def restart_explorer(self):
        try:
            subprocess.run("taskkill /f /im explorer.exe", shell=True, capture_output=True)
            subprocess.run("start explorer.exe", shell=True)
            QMessageBox.information(self, "Успех", "Проводник перезапущен.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось перезапустить Проводник: {e}")

    # --- Автозагрузка (единое меню) ---
    def show_startup_menu(self):
        menu = QMenu(self)
        menu.addAction("Реестр (HKCU\\Run)", self.add_self_to_startup_registry)
        menu.addAction("Планировщик задач", self.add_self_to_startup_task)
        menu.addAction("Вместе с Explorer", self.add_self_with_explorer)
        menu.addAction("CMDLINE (быстрый)", self.add_self_to_startup_cmdline)
        menu.exec(self.btn_startup_menu.mapToGlobal(self.btn_startup_menu.rect().bottomLeft()))

    def _get_self_exe(self):
        if getattr(sys, 'frozen', False):
            return os.path.abspath(sys.executable)
        elif hasattr(sys, '_MEIPASS'):
            return os.path.abspath(sys.executable)
        else:
            return sys.executable

    def add_self_to_startup_registry(self):
        exe = self._get_self_exe()
        if not exe:
            return
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Run",
                                 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "SirisUnlocker", 0, winreg.REG_SZ, f'"{exe}"')
            winreg.CloseKey(key)
            QMessageBox.information(self, "Успех", "Добавлено в автозагрузку (реестр).")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось добавить: {e}")

    def add_self_to_startup_task(self):
        exe = self._get_self_exe()
        if not exe:
            return
        task_name = "SirisUnlocker_Startup"
        try:
            result = subprocess.run(
                f'schtasks /create /tn "{task_name}" /tr "{exe}" /sc onlogon /f',
                shell=True, capture_output=True, text=True
            )
            if result.returncode == 0:
                QMessageBox.information(self, "Успех", "Задача в планировщике создана.")
            else:
                QMessageBox.critical(self, "Ошибка", f"Не удалось создать задачу:\n{result.stderr}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось создать задачу: {e}")

    def add_self_with_explorer(self):
        """Запуск SirisUnlocker вместе с Explorer (без замены оболочки)."""
        exe = self._get_self_exe()
        if not exe:
            return
        try:
            # Создаём ярлык в папке автозагрузки
            startup_folder = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
            shortcut_path = os.path.join(startup_folder, "SirisUnlocker.lnk")
            ps_cmd = f'$WshShell = New-Object -ComObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut("{shortcut_path}"); $Shortcut.TargetPath = "{exe}"; $Shortcut.Save()'
            result = subprocess.run(["powershell", "-Command", ps_cmd], shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                QMessageBox.information(self, "Успех", f"Ярлык создан в {startup_folder}")
            else:
                QMessageBox.critical(self, "Ошибка", f"Не удалось создать ярлык:\n{result.stderr}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось создать ярлык: {e}")

    def add_self_to_startup_cmdline(self):
        """Самый быстрый запуск через CMDLINE в реестре (требует прав администратора)."""
        if not self._check_admin():
            QMessageBox.critical(self, "Ошибка", "Необходимы права администратора.")
            return
        exe = self._get_self_exe()
        if not exe:
            return
        try:
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "SirisUnlocker", 0, winreg.REG_SZ, f'"{exe}"')
            QMessageBox.information(self, "Успех", "Добавлено в автозагрузку через HKLM\\Run.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось добавить: {e}")

    def remove_self_from_startup(self):
        name = "SirisUnlocker"
        removed = 0
        # Реестр HKCU
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Run",
                                 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, name)
            winreg.CloseKey(key)
            removed += 1
        except:
            pass
        # Реестр HKLM
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                                 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, name)
            winreg.CloseKey(key)
            removed += 1
        except:
            pass
        # Планировщик
        try:
            subprocess.run('schtasks /delete /tn "SirisUnlocker_Startup" /f', shell=True, capture_output=True)
            removed += 1
        except:
            pass
        # Папка Startup
        startup_folder = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
        shortcut_path = os.path.join(startup_folder, "SirisUnlocker.lnk")
        if os.path.exists(shortcut_path):
            try:
                os.remove(shortcut_path)
                removed += 1
            except:
                pass
        if removed > 0:
            QMessageBox.information(self, "Успех", f"Удалено записей автозагрузки: {removed}")
        else:
            QMessageBox.information(self, "Информация", "Записи автозагрузки не найдены.")

    # --- Безопасный режим ---
    def boot_safe_mode(self):
        reply = QMessageBox.question(self, "Подтверждение",
                                     "Перезагрузить в безопасном режиме с командной строкой?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        try:
            subprocess.run('bcdedit /set {current} safeboot minimal', shell=True, check=True)
            subprocess.run('bcdedit /set {current} safebootalternateshell yes', shell=True, check=True)
            subprocess.run('bcdedit /set {current} basevideo on', shell=True, check=True)
            os.system('shutdown /r /t 5')
            QMessageBox.information(self, "Готово", "Перезагрузка через 5 секунд.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось настроить безопасный режим: {e}")

    def boot_normal_mode(self):
        reply = QMessageBox.question(self, "Подтверждение",
                                     "Отключить безопасный режим и перезагрузиться?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        try:
            subprocess.run('bcdedit /deletevalue {current} safeboot', shell=True, check=True)
            subprocess.run('bcdedit /deletevalue {current} safebootalternateshell', shell=True, check=True)
            subprocess.run('bcdedit /deletevalue {current} basevideo', shell=True, check=True)
            os.system('shutdown /r /t 5')
            QMessageBox.information(self, "Готово", "Перезагрузка через 5 секунд.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось отключить безопасный режим: {e}")

    # --- Информация о системе ---
    def show_system_info(self):
        try:
            cpu = platform.processor()
            ram = f"{psutil.virtual_memory().total / (1024**3):.1f} GB"
            gpu = "Неизвестно"
            try:
                import wmi
                c = wmi.WMI()
                for g in c.Win32_VideoController():
                    gpu = g.Name
                    break
            except:
                try:
                    result = subprocess.run(['powershell', '(Get-WmiObject Win32_VideoController).Name'],
                                            capture_output=True, text=True)
                    if result.returncode == 0 and result.stdout.strip():
                        gpu = result.stdout.strip().split('\n')[0]
                except:
                    pass
            os_info = f"{platform.system()} {platform.release()} ({platform.version()})"
            info_text = (f"<b>Операционная система:</b> {os_info}<br>"
                         f"<b>Процессор:</b> {cpu}<br>"
                         f"<b>ОЗУ:</b> {ram}<br>"
                         f"<b>Видеокарта:</b> {gpu}<br>"
                         f"<b>Имя компьютера:</b> {platform.node()}")
            QMessageBox.information(self, "Информация о системе", info_text)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось получить информацию: {e}")

    # --- Сброс оболочки (полный сброс Winlogon) ---
    def reset_shell(self):
        if not self._check_admin():
            QMessageBox.critical(self, "Ошибка", "Необходимы права администратора.")
            return
        reply = QMessageBox.question(self, "Подтверждение",
                                     "Сбросить оболочку Windows (Shell и Userinit) к стандартным значениям?\n"
                                     "Потребуется перезагрузка.",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                                 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "Shell", 0, winreg.REG_SZ, "explorer.exe")
            winreg.SetValueEx(key, "Userinit", 0, winreg.REG_SZ, r"C:\Windows\system32\userinit.exe,")
            winreg.CloseKey(key)
            QMessageBox.information(self, "Успех", "Оболочка сброшена. Перезагрузитесь.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сбросить Shell: {e}")

    # ---------- Подмена системных файлов через MoveFileEx ----------
    MOVEFILE_DELAY_UNTIL_REBOOT = 0x4

    def _replace_system_file_on_reboot(self, src, dst):
        try:
            backup = dst + ".bak"
            if not os.path.exists(backup):
                shutil.copy2(dst, backup)
            ctypes.windll.kernel32.MoveFileExW(src, dst, self.MOVEFILE_DELAY_UNTIL_REBOOT)
            return True
        except Exception:
            return False

    def replace_sticky_keys(self):
        if not self._check_admin():
            QMessageBox.critical(self, "Ошибка", "Необходимы права администратора.")
            return
        exe = self._get_self_exe()
        if not exe:
            return
        system32 = os.environ.get('SystemRoot', 'C:\\Windows') + '\\System32'
        sethc_path = os.path.join(system32, 'sethc.exe')
        if not os.path.exists(sethc_path):
            QMessageBox.critical(self, "Ошибка", "sethc.exe не найден.")
            return
        if self._replace_system_file_on_reboot(exe, sethc_path):
            QMessageBox.information(self, "Успех", "Подмена запланирована. Перезагрузите компьютер для применения.")
        else:
            QMessageBox.critical(self, "Ошибка", "Не удалось запланировать подмену.")

    def restore_sticky_keys(self):
        if not self._check_admin():
            QMessageBox.critical(self, "Ошибка", "Нужны права администратора.")
            return
        system32 = os.environ.get('SystemRoot', 'C:\\Windows') + '\\System32'
        sethc_path = os.path.join(system32, 'sethc.exe')
        backup_path = sethc_path + '.bak'
        if not os.path.exists(backup_path):
            QMessageBox.information(self, "Информация", "Резервная копия не найдена.")
            return
        if self._replace_system_file_on_reboot(backup_path, sethc_path):
            QMessageBox.information(self, "Успех", "Восстановление запланировано. Перезагрузите компьютер.")
        else:
            QMessageBox.critical(self, "Ошибка", "Не удалось запланировать восстановление.")

    def replace_utilman(self):
        if not self._check_admin():
            QMessageBox.critical(self, "Ошибка", "Нужны права администратора.")
            return
        exe = self._get_self_exe()
        if not exe:
            return
        system32 = os.environ.get('SystemRoot', 'C:\\Windows') + '\\System32'
        utilman_path = os.path.join(system32, 'Utilman.exe')
        if not os.path.exists(utilman_path):
            QMessageBox.critical(self, "Ошибка", "Utilman.exe не найден.")
            return
        if self._replace_system_file_on_reboot(exe, utilman_path):
            QMessageBox.information(self, "Успех", "Подмена запланирована. Перезагрузите компьютер.")
        else:
            QMessageBox.critical(self, "Ошибка", "Не удалось запланировать подмену.")

    def restore_utilman(self):
        if not self._check_admin():
            QMessageBox.critical(self, "Ошибка", "Нужны права администратора.")
            return
        system32 = os.environ.get('SystemRoot', 'C:\\Windows') + '\\System32'
        utilman_path = os.path.join(system32, 'Utilman.exe')
        backup_path = utilman_path + '.bak'
        if not os.path.exists(backup_path):
            QMessageBox.information(self, "Информация", "Резервная копия не найдена.")
            return
        if self._replace_system_file_on_reboot(backup_path, utilman_path):
            QMessageBox.information(self, "Успех", "Восстановление запланировано. Перезагрузите компьютер.")
        else:
            QMessageBox.critical(self, "Ошибка", "Не удалось запланировать восстановление.")

    # ---------- Глобальные горячие клавиши ----------
    def toggle_hotkey_show(self):
        if not self.parent_window:
            self.btn_hotkey_show.setChecked(False)
            return
        if self.btn_hotkey_show.isChecked():
            success = self.register_hotkey(HOTKEY_ID_SHOW, VK_T)
            if success:
                self.hotkey_show_registered = True
                QMessageBox.information(self, "Успех", "Горячая клавиша Alt+T зарегистрирована.")
            else:
                self.btn_hotkey_show.setChecked(False)
                QMessageBox.critical(self, "Ошибка", "Не удалось зарегистрировать Alt+T. Возможно, она уже занята.")
        else:
            self.unregister_hotkey(HOTKEY_ID_SHOW)
            self.hotkey_show_registered = False
            QMessageBox.information(self, "Успех", "Горячая клавиша Alt+T отключена.")

    def toggle_hotkey_launch(self):
        if self.btn_hotkey_launch.isChecked():
            success = self.register_hotkey(HOTKEY_ID_LAUNCH, VK_GRAVE)
            if success:
                self.hotkey_launch_registered = True
                QMessageBox.information(self, "Успех", "Горячая клавиша Alt+` зарегистрирована.")
            else:
                self.btn_hotkey_launch.setChecked(False)
                QMessageBox.critical(self, "Ошибка", "Не удалось зарегистрировать Alt+`. Возможно, она уже занята.")
        else:
            self.unregister_hotkey(HOTKEY_ID_LAUNCH)
            self.hotkey_launch_registered = False
            QMessageBox.information(self, "Успех", "Горячая клавиша Alt+` отключена.")

    def register_hotkey(self, hotkey_id, vk_code):
        if not self.parent_window:
            return False
        try:
            hwnd = int(self.parent_window.winId())
            result = ctypes.windll.user32.RegisterHotKey(hwnd, hotkey_id, MOD_ALT, vk_code)
            if result:
                if self.hotkey_filter is None:
                    self.hotkey_filter = HotkeyFilter(self.parent_window, self)
                    QApplication.instance().installNativeEventFilter(self.hotkey_filter)
                return True
            return False
        except Exception as e:
            print(f"RegisterHotKey failed: {e}")
            return False

    def unregister_hotkey(self, hotkey_id):
        if not self.parent_window:
            return
        try:
            hwnd = int(self.parent_window.winId())
            ctypes.windll.user32.UnregisterHotKey(hwnd, hotkey_id)
        except Exception as e:
            print(f"UnregisterHotKey failed: {e}")

    def launch_or_activate(self):
        """Запускает новый экземпляр SirisUnlocker или активирует существующий."""
        exe_path = self._get_self_exe()
        if not exe_path:
            return
        try:
            subprocess.Popen([exe_path])
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось запустить SirisUnlocker: {e}")