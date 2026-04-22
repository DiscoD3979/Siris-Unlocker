import os
import winreg
import subprocess
import shutil
from core.quarantine import add_to_quarantine, move_file_to_quarantine

# ------------------------------------------------------------
# Вспомогательные функции работы с реестром
# ------------------------------------------------------------
def _open_registry_key(hive, path, write=False):
    """Открывает ключ реестра с нужными правами и флагами WOW64."""
    access = winreg.KEY_WOW64_64KEY
    if write:
        access |= winreg.KEY_SET_VALUE
    else:
        access |= winreg.KEY_READ
    try:
        return winreg.OpenKey(hive, path, 0, access)
    except FileNotFoundError:
        if write:
            return winreg.CreateKey(hive, path)
        raise

def _delete_registry_value(hive, path, name):
    """Удаляет значение из реестра."""
    try:
        with _open_registry_key(hive, path, write=True) as key:
            winreg.DeleteValue(key, name)
        return True
    except Exception:
        return False

def _set_registry_value(hive, path, name, value, reg_type=winreg.REG_SZ):
    """Записывает значение в реестр."""
    try:
        with _open_registry_key(hive, path, write=True) as key:
            winreg.SetValueEx(key, name, 0, reg_type, value)
        return True
    except Exception:
        return False

# ------------------------------------------------------------
# Управление отдельными записями
# ------------------------------------------------------------
def delete_startup_entry(entry, move_to_quarantine=True):
    """
    Удаляет запись автозагрузки.
    Если move_to_quarantine=True, предварительно сохраняет в карантин.
    Возвращает True при успехе.
    """
    etype = entry.get('type')
    if move_to_quarantine:
        # Адаптируем запись под формат карантина
        q_entry = {
            'type': etype,
            'name': entry.get('name'),
            'command': entry.get('command'),
            'location': entry.get('location', ''),
        }
        if etype == 'registry' or etype == 'registry_ex':
            q_entry['hive_str'] = 'HKEY_CURRENT_USER' if entry.get('hive') == winreg.HKEY_CURRENT_USER else 'HKEY_LOCAL_MACHINE'
            q_entry['path'] = entry.get('path')
        elif etype == 'folder':
            # Перемещаем файл в карантинную папку
            file_path = entry.get('command')
            if os.path.isfile(file_path):
                q_entry['quarantine_path'] = move_file_to_quarantine(file_path)
        add_to_quarantine(q_entry)

    # Выполняем удаление
    try:
        if etype in ('registry', 'registry_ex'):
            hive = entry.get('hive')
            path = entry.get('path')
            name = entry.get('name')
            return _delete_registry_value(hive, path, name)

        elif etype == 'folder':
            file_path = entry.get('command')
            if os.path.isfile(file_path):
                os.remove(file_path)
                return True

        elif etype == 'winlogon':
            hive = winreg.HKEY_LOCAL_MACHINE
            path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            name = entry.get('name')
            return _delete_registry_value(hive, path, name)

        elif etype == 'shellservice':
            hive = winreg.HKEY_LOCAL_MACHINE
            path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"
            name = entry.get('name')
            return _delete_registry_value(hive, path, name)

        elif etype == 'appinit':
            hive = winreg.HKEY_LOCAL_MACHINE
            path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
            name = entry.get('name')
            return _delete_registry_value(hive, path, name)

        elif etype == 'knowndlls':
            hive = winreg.HKEY_LOCAL_MACHINE
            path = r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
            name = entry.get('name')
            return _delete_registry_value(hive, path, name)

        elif etype == 'service':
            service_name = entry.get('name')
            subprocess.run(['sc', 'delete', service_name], capture_output=True, check=False)
            return True

        elif etype == 'scheduled_task':
            task_name = entry.get('name')
            subprocess.run(['schtasks', '/delete', '/tn', task_name, '/f'], capture_output=True, check=False)
            return True

        elif etype == 'active_setup':
            # Удаление ключа Active Setup
            hive = winreg.HKEY_LOCAL_MACHINE
            loc = entry.get('location', '')
            import re
            match = re.search(r'Active Setup:\s*(.+)', loc)
            if match:
                reg_path = match.group(1).strip()
                full_path = f"{reg_path}\\{entry['name']}"
                try:
                    winreg.DeleteKey(hive, full_path)
                    return True
                except:
                    pass

        elif etype == 'logon_script':
            hive = winreg.HKEY_CURRENT_USER
            path = r"Environment"
            name = entry.get('name')
            return _delete_registry_value(hive, path, name)

    except Exception:
        return False
    return False

def edit_startup_entry(entry, new_command):
    """
    Изменяет команду (путь) для существующей записи.
    Возвращает True при успехе.
    """
    etype = entry.get('type')
    try:
        if etype in ('registry', 'registry_ex'):
            hive = entry.get('hive')
            path = entry.get('path')
            name = entry.get('name')
            return _set_registry_value(hive, path, name, new_command)

        elif etype == 'folder':
            # Для папок автозагрузки нельзя просто изменить команду — это файл.
            # Можно переименовать файл, но обычно не требуется.
            return False

        elif etype == 'winlogon':
            hive = winreg.HKEY_LOCAL_MACHINE
            path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            name = entry.get('name')
            return _set_registry_value(hive, path, name, new_command)

        elif etype == 'shellservice':
            hive = winreg.HKEY_LOCAL_MACHINE
            path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"
            name = entry.get('name')
            return _set_registry_value(hive, path, name, new_command)

        elif etype == 'appinit':
            hive = winreg.HKEY_LOCAL_MACHINE
            path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
            name = entry.get('name')
            return _set_registry_value(hive, path, name, new_command)

        elif etype == 'service':
            service_name = entry.get('name')
            subprocess.run(['sc', 'config', service_name, 'binPath=', new_command], capture_output=True, check=False)
            return True

        elif etype == 'scheduled_task':
            task_name = entry.get('name')
            # Изменение задачи через schtasks /change /tn name /tr newcommand
            subprocess.run(['schtasks', '/change', '/tn', task_name, '/tr', new_command], capture_output=True, check=False)
            return True

        elif etype == 'active_setup':
            hive = winreg.HKEY_LOCAL_MACHINE
            loc = entry.get('location', '')
            import re
            match = re.search(r'Active Setup:\s*(.+)', loc)
            if match:
                reg_path = match.group(1).strip()
                full_path = f"{reg_path}\\{entry['name']}"
                with _open_registry_key(hive, full_path, write=True) as key:
                    winreg.SetValueEx(key, "StubPath", 0, winreg.REG_SZ, new_command)
                return True

        elif etype == 'logon_script':
            hive = winreg.HKEY_CURRENT_USER
            path = r"Environment"
            name = entry.get('name')
            return _set_registry_value(hive, path, name, new_command)

    except Exception:
        return False
    return False

def create_startup_entry(entry_type, **kwargs):
    """
    Создаёт новую запись автозагрузки.
    entry_type: 'registry', 'folder', 'winlogon', 'scheduled_task', 'service', 'active_setup', 'logon_script'
    kwargs должны содержать необходимые параметры (name, command, hive, path и т.д.)
    Возвращает True при успехе.
    """
    try:
        if entry_type == 'registry':
            hive = kwargs.get('hive')
            path = kwargs.get('path')
            name = kwargs.get('name')
            command = kwargs.get('command')
            return _set_registry_value(hive, path, name, command)

        elif entry_type == 'folder':
            target_folder = kwargs.get('target_folder')
            file_path = kwargs.get('file_path')
            if not os.path.isfile(file_path):
                return False
            dest = os.path.join(target_folder, os.path.basename(file_path))
            shutil.copy2(file_path, dest)
            return True

        elif entry_type == 'winlogon':
            name = kwargs.get('name')
            command = kwargs.get('command')
            hive = winreg.HKEY_LOCAL_MACHINE
            path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            return _set_registry_value(hive, path, name, command)

        elif entry_type == 'scheduled_task':
            name = kwargs.get('name')
            command = kwargs.get('command')
            trigger = kwargs.get('trigger', '/sc onlogon')
            subprocess.run(['schtasks', '/create', '/tn', name, '/tr', command, trigger, '/f'],
                           capture_output=True, check=False)
            return True

        elif entry_type == 'service':
            name = kwargs.get('name')
            command = kwargs.get('command')
            subprocess.run(['sc', 'create', name, 'binPath=', command, 'start=', 'auto'],
                           capture_output=True, check=False)
            return True

        elif entry_type == 'active_setup':
            name = kwargs.get('name')
            command = kwargs.get('command')
            reg_path = kwargs.get('reg_path')  # e.g. "SOFTWARE\Microsoft\Active Setup\Installed Components"
            hive = winreg.HKEY_LOCAL_MACHINE
            full_path = f"{reg_path}\\{name}"
            with winreg.CreateKey(hive, full_path) as key:
                winreg.SetValueEx(key, "StubPath", 0, winreg.REG_SZ, command)
            return True

        elif entry_type == 'logon_script':
            name = "UserInitMprLogonScript"
            command = kwargs.get('command')
            hive = winreg.HKEY_CURRENT_USER
            path = r"Environment"
            return _set_registry_value(hive, path, name, command)

        elif entry_type == 'appinit':
            name = kwargs.get('name')
            command = kwargs.get('command')
            hive = winreg.HKEY_LOCAL_MACHINE
            path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
            return _set_registry_value(hive, path, name, command)

    except Exception:
        return False
    return False

def delete_startup_entries_batch(entries, move_to_quarantine=True):
    """Массовое удаление записей. Возвращает количество успешно удалённых."""
    success = 0
    for entry in entries:
        if delete_startup_entry(entry, move_to_quarantine):
            success += 1
    return success

def file_exists_in_entry(entry):
    """Проверяет, существует ли файл, на который ссылается запись."""
    cmd = entry.get('command', '')
    if not cmd:
        return False
    # Для некоторых типов команда может быть не путём к файлу (например, CLSID)
    if entry.get('type') in ('shellservice', 'knowndlls'):
        return False
    # Извлекаем путь (первое слово до пробела, если есть аргументы)
    path = cmd.split(' ')[0].strip('"')
    return os.path.exists(path)

# ------------------------------------------------------------
# Совместимость со старым кодом (disable_registry_entry, delete_folder_entry)
# ------------------------------------------------------------
def disable_registry_entry(hive, path, name):
    """Удаляет значение реестра (для обратной совместимости)."""
    return _delete_registry_value(hive, path, name)

def delete_folder_entry(full_path):
    """Удаляет файл из папки автозагрузки."""
    try:
        os.remove(full_path)
        return True
    except Exception:
        return False