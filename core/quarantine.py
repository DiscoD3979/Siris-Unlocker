import os
import json
import shutil
import uuid
import datetime
import winreg
import subprocess
from pathlib import Path

# ---------- Константы ----------
DATA_DIR = Path(__file__).parent.parent / "data"
QUARANTINE_FILE = DATA_DIR / "quarantine.json"
QUARANTINE_FILES_DIR = DATA_DIR / "quarantine_files"
RETENTION_DAYS = 30  # Хранить записи не более 30 дней (0 = не удалять)

# ---------- Внутренние функции ----------
def _ensure_dirs():
    DATA_DIR.mkdir(exist_ok=True)
    QUARANTINE_FILES_DIR.mkdir(exist_ok=True)

def _load_json():
    _ensure_dirs()
    if QUARANTINE_FILE.exists():
        try:
            with open(QUARANTINE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return []
    return []

def _save_json(data):
    with open(QUARANTINE_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def _cleanup_old_entries(data, max_days=RETENTION_DAYS):
    """Удаляет записи старше max_days дней."""
    if max_days <= 0:
        return data
    cutoff = datetime.datetime.now() - datetime.timedelta(days=max_days)
    new_data = []
    for entry in data:
        date_str = entry.get('quarantine_date')
        if date_str:
            try:
                dt = datetime.datetime.fromisoformat(date_str)
                if dt > cutoff:
                    new_data.append(entry)
                    continue
            except:
                pass
        # Если даты нет или старше - пропускаем
        # Также удаляем связанный файл из карантинной папки
        if entry.get('quarantine_path'):
            try:
                os.remove(entry['quarantine_path'])
            except:
                pass
    return new_data

# ---------- Публичные функции ----------
def load_quarantine():
    """Возвращает список записей карантина."""
    data = _load_json()
    if RETENTION_DAYS > 0:
        data = _cleanup_old_entries(data)
        _save_json(data)
    return data

def add_to_quarantine(entry):
    """
    Добавляет запись в карантин.
    entry должен содержать ключи: type, location, name, command.
    Для 'folder' также 'quarantine_path' (если был перемещён файл).
    """
    data = _load_json()
    entry['id'] = str(uuid.uuid4())
    entry['quarantine_date'] = datetime.datetime.now().isoformat()
    data.append(entry)
    _save_json(data)

def remove_from_quarantine(entry_id):
    """Удаляет запись из карантина по ID (без восстановления)."""
    data = _load_json()
    # Находим запись для возможного удаления файла из карантинной папки
    for entry in data:
        if entry.get('id') == entry_id:
            if entry.get('quarantine_path'):
                try:
                    os.remove(entry['quarantine_path'])
                except:
                    pass
            break
    data = [e for e in data if e.get('id') != entry_id]
    _save_json(data)

def move_file_to_quarantine(file_path):
    """Перемещает файл в карантинную папку, возвращает новый путь."""
    if not os.path.isfile(file_path):
        return None
    _ensure_dirs()
    name = os.path.basename(file_path)
    dest = QUARANTINE_FILES_DIR / f"{uuid.uuid4()}_{name}"
    shutil.move(file_path, dest)
    return str(dest)

def restore_from_quarantine(entry):
    """
    Восстанавливает запись из карантина в систему.
    Возвращает True при успехе.
    """
    etype = entry.get('type')
    try:
        if etype == 'registry':
            hive_str = entry.get('hive_str', 'HKEY_CURRENT_USER')
            hive = winreg.HKEY_CURRENT_USER if hive_str == 'HKEY_CURRENT_USER' else winreg.HKEY_LOCAL_MACHINE
            path = entry['path']
            name = entry['name']
            command = entry['command']
            # Создаём ключ, если его нет
            with winreg.CreateKey(hive, path) as key:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, command)
            return True

        elif etype == 'folder':
            src = entry.get('quarantine_path')
            dst = entry.get('command')
            if src and dst and os.path.exists(src):
                # Убедимся, что папка назначения существует
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.move(src, dst)
                return True

        elif etype == 'winlogon':
            hive = winreg.HKEY_LOCAL_MACHINE
            path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            name = entry['name']
            value = entry['command']
            with winreg.CreateKey(hive, path) as key:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
            return True

        elif etype == 'scheduled_task':
            # Восстановление задачи планировщика
            name = entry['name']
            command = entry['command']
            # Простейший способ: создать задачу с запуском при входе
            subprocess.run(
                ['schtasks', '/create', '/tn', name, '/tr', command, '/sc', 'onlogon', '/f'],
                capture_output=True, check=False
            )
            return True

        elif etype == 'service':
            # Восстановление службы (только если сохранили полный ImagePath)
            name = entry['name']
            command = entry['command']
            subprocess.run(
                ['sc', 'create', name, 'binPath=', command, 'start=', 'auto'],
                capture_output=True, check=False
            )
            return True

        elif etype == 'active_setup':
            # Восстановление компонента Active Setup
            loc = entry.get('location', '')
            # Извлекаем путь реестра из строки "Active Setup: HKLM\SOFTWARE\..."
            import re
            match = re.search(r'Active Setup:\s*(.+)', loc)
            if not match:
                return False
            reg_path = match.group(1).strip()
            hive = winreg.HKEY_LOCAL_MACHINE
            # Создаём ключ компонента
            full_path = f"{reg_path}\\{entry['name']}"
            with winreg.CreateKey(hive, full_path) as key:
                winreg.SetValueEx(key, "StubPath", 0, winreg.REG_SZ, entry['command'])
            return True

        elif etype == 'appinit':
            # Восстановление AppInit_DLLs
            hive = winreg.HKEY_LOCAL_MACHINE
            path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
            name = entry['name']
            value = entry['command']
            with winreg.CreateKey(hive, path) as key:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
            return True

        elif etype == 'shellservice':
            # Восстановление ShellServiceObjectDelayLoad
            hive = winreg.HKEY_LOCAL_MACHINE
            path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"
            name = entry['name']
            value = entry['command']
            with winreg.CreateKey(hive, path) as key:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
            return True

        else:
            # Неизвестный тип
            return False
    except Exception as e:
        # Логирование ошибки можно добавить при необходимости
        # print(f"Restore error: {e}")
        return False

def export_quarantine(file_path):
    """Экспортирует карантин в указанный JSON-файл."""
    data = load_quarantine()
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def import_quarantine(file_path, merge=True):
    """
    Импортирует записи из JSON-файла.
    Если merge=True, добавляет к существующим, иначе заменяет.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        imported = json.load(f)
    if merge:
        data = _load_json()
        # Простая дедупликация по id
        existing_ids = {e.get('id') for e in data}
        for entry in imported:
            if entry.get('id') not in existing_ids:
                data.append(entry)
        _save_json(data)
    else:
        _save_json(imported)