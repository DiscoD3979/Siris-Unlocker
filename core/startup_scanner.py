import os
import winreg
import subprocess
import json
import datetime
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# ------------------------------------------------------------
# Кэш в памяти и на диске
# ------------------------------------------------------------
_CACHE = None
_CACHE_TIMESTAMP = None
_CACHE_FILE = Path(__file__).parent.parent / "data" / "startup_cache.json"
_CACHE_LIFETIME = 60  # секунд, после которых кэш считается устаревшим

def _clear_cache():
    global _CACHE, _CACHE_TIMESTAMP
    _CACHE = None
    _CACHE_TIMESTAMP = None

def _load_cache_from_disk():
    """Загружает кэш из файла, если он существует."""
    if _CACHE_FILE.exists():
        try:
            with open(_CACHE_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # Проверяем структуру
                if isinstance(data, dict) and 'entries' in data and 'timestamp' in data:
                    return data['entries'], data['timestamp']
        except:
            pass
    return None, 0

def _save_cache_to_disk(entries):
    """Сохраняет кэш на диск."""
    _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    data = {
        'entries': entries,
        'timestamp': time.time()
    }
    with open(_CACHE_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def _get_cached():
    """Возвращает кэшированные записи, если они актуальны."""
    global _CACHE, _CACHE_TIMESTAMP
    # Сначала проверяем память
    if _CACHE is not None and _CACHE_TIMESTAMP is not None:
        if time.time() - _CACHE_TIMESTAMP < _CACHE_LIFETIME:
            return _CACHE
    # Пробуем загрузить с диска
    entries, disk_ts = _load_cache_from_disk()
    if entries and time.time() - disk_ts < _CACHE_LIFETIME:
        _CACHE = entries
        _CACHE_TIMESTAMP = disk_ts
        return entries
    return None

def _set_cache(entries):
    global _CACHE, _CACHE_TIMESTAMP
    _CACHE = entries
    _CACHE_TIMESTAMP = time.time()
    _save_cache_to_disk(entries)

# ------------------------------------------------------------
# Вспомогательные функции
# ------------------------------------------------------------
def filetime_to_datetime(ft):
    if ft is None or ft == 0:
        return "Неизвестно"
    try:
        seconds = ft / 10000000.0
        dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=seconds)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "Ошибка"

def get_reg_key_timestamp(hive, subkey):
    try:
        access = winreg.KEY_READ
        if hive == winreg.HKEY_LOCAL_MACHINE:
            access |= winreg.KEY_WOW64_64KEY
        with winreg.OpenKey(hive, subkey, 0, access) as key:
            info = winreg.QueryInfoKey(key)
            return info[2]
    except Exception:
        return None

def enum_reg_key(hive, subkey, include_timestamp=True):
    entries = []
    timestamp = get_reg_key_timestamp(hive, subkey) if include_timestamp else None
    try:
        access = winreg.KEY_READ
        if hive == winreg.HKEY_LOCAL_MACHINE:
            access |= winreg.KEY_WOW64_64KEY
        with winreg.OpenKey(hive, subkey, 0, access) as key:
            i = 0
            while True:
                try:
                    name, value, typ = winreg.EnumValue(key, i)
                    if typ == winreg.REG_EXPAND_SZ:
                        value = winreg.ExpandEnvironmentStrings(value)
                    entries.append((name, value, timestamp))
                    i += 1
                except OSError:
                    break
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return entries

def get_file_creation_time(path):
    try:
        ctime = os.path.getctime(path)
        dt = datetime.datetime.fromtimestamp(ctime)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""

def expand_env_string(s):
    try:
        return winreg.ExpandEnvironmentStrings(s)
    except Exception:
        return s

# ------------------------------------------------------------
# Функции-сканеры (каждая возвращает список словарей)
# ------------------------------------------------------------
def get_registry_run():
    entries = []
    paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    for hive, path in paths:
        for name, command, timestamp in enum_reg_key(hive, path):
            entries.append({
                'location': f"Реестр: {path}",
                'name': name,
                'command': command,
                'created': filetime_to_datetime(timestamp),
                'type': 'registry',
                'hive': hive,
                'path': path
            })
    return entries

def get_registry_runonce_ex():
    entries = []
    path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"
    try:
        access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, access) as key:
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey_path = f"{path}\\{subkey_name}"
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path, 0, access) as subkey:
                        sub_timestamp = get_reg_key_timestamp(winreg.HKEY_LOCAL_MACHINE, subkey_path)
                        for name, command, _ in enum_reg_key(subkey, '', include_timestamp=False):
                            entries.append({
                                'location': f"Реестр: {subkey_path}",
                                'name': name,
                                'command': command,
                                'created': filetime_to_datetime(sub_timestamp),
                                'type': 'registry_ex'
                            })
                    i += 1
                except OSError:
                    break
    except:
        pass
    return entries

def get_registry_winlogon():
    entries = []
    winlogon_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    hive = winreg.HKEY_LOCAL_MACHINE
    try:
        access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        with winreg.OpenKey(hive, winlogon_path, 0, access) as key:
            timestamp = get_reg_key_timestamp(hive, winlogon_path)
            for value_name in ['Userinit', 'Shell', 'Notify']:
                try:
                    value, typ = winreg.QueryValueEx(key, value_name)
                    if typ == winreg.REG_EXPAND_SZ:
                        value = expand_env_string(value)
                    entries.append({
                        'location': f"Реестр: {winlogon_path}",
                        'name': value_name,
                        'command': value,
                        'created': filetime_to_datetime(timestamp),
                        'type': 'winlogon'
                    })
                except FileNotFoundError:
                    pass
    except:
        pass
    return entries

def get_registry_shell_service_objects():
    entries = []
    path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"
    for name, clsid, timestamp in enum_reg_key(winreg.HKEY_LOCAL_MACHINE, path):
        entries.append({
            'location': f"Реестр: {path}",
            'name': name,
            'command': clsid,
            'created': filetime_to_datetime(timestamp),
            'type': 'shellservice'
        })
    return entries

def get_registry_appinit_dlls():
    entries = []
    path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
    try:
        access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, access) as key:
            timestamp = get_reg_key_timestamp(winreg.HKEY_LOCAL_MACHINE, path)
            dlls, typ = winreg.QueryValueEx(key, "AppInit_DLLs")
            if dlls:
                if typ == winreg.REG_EXPAND_SZ:
                    dlls = expand_env_string(dlls)
                entries.append({
                    'location': f"Реестр: {path}",
                    'name': "AppInit_DLLs",
                    'command': dlls,
                    'created': filetime_to_datetime(timestamp),
                    'type': 'appinit'
                })
    except:
        pass
    return entries

def get_registry_known_dlls():
    entries = []
    path = r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
    for name, dll, timestamp in enum_reg_key(winreg.HKEY_LOCAL_MACHINE, path):
        entries.append({
            'location': f"Реестр: {path}",
            'name': name,
            'command': dll,
            'created': filetime_to_datetime(timestamp),
            'type': 'knowndlls'
        })
    return entries

def get_services():
    entries = []
    services_path = r"SYSTEM\CurrentControlSet\Services"
    try:
        access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, services_path, 0, access) as key:
            i = 0
            while True:
                try:
                    service_name = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, service_name, 0, access) as skey:
                        try:
                            start, _ = winreg.QueryValueEx(skey, "Start")
                            if start == 2:  # Автоматический запуск
                                image_path, typ = winreg.QueryValueEx(skey, "ImagePath")
                                if typ == winreg.REG_EXPAND_SZ:
                                    image_path = expand_env_string(image_path)
                                timestamp = get_reg_key_timestamp(winreg.HKEY_LOCAL_MACHINE, f"{services_path}\\{service_name}")
                                entries.append({
                                    'location': f"Службы: {service_name}",
                                    'name': service_name,
                                    'command': image_path,
                                    'created': filetime_to_datetime(timestamp),
                                    'type': 'service'
                                })
                        except:
                            pass
                    i += 1
                except OSError:
                    break
    except:
        pass
    return entries

def get_startup_folders_all():
    entries = []
    folders = [
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.expandvars(r"%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup"),
    ]
    for folder in folders:
        if not os.path.isdir(folder):
            continue
        for item in os.listdir(folder):
            full = os.path.join(folder, item)
            if os.path.isfile(full):
                entries.append({
                    'location': f"Папка: {folder}",
                    'name': item,
                    'command': full,
                    'created': get_file_creation_time(full),
                    'type': 'folder'
                })
    return entries

def get_scheduled_tasks_full():
    """Возвращает только пользовательские задачи (не системные)."""
    tasks = []
    try:
        ps_cmd = (
            "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
            "Get-ScheduledTask | ForEach-Object { "
            "$task = $_; "
            "$info = Get-ScheduledTaskInfo -TaskName $task.TaskName -ErrorAction SilentlyContinue; "
            "$actions = $task.Actions | ForEach-Object { $_.Execute } | Where-Object { $_ } | Select-Object -First 1; "
            "[PSCustomObject]@{ "
            "TaskName = $task.TaskName; "
            "TaskPath = $task.TaskPath; "
            "State = $task.State.value__; "
            "Author = $task.Author; "
            "Date = $task.Date; "
            "Executable = $actions "
            "} } | ConvertTo-Json -Compress"
        )
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        result = subprocess.run(
            ['powershell', '-Command', ps_cmd],
            capture_output=True,
            text=False,
            check=False,
            startupinfo=startupinfo
        )
        stdout = result.stdout.decode('utf-8', errors='replace')
        if result.returncode != 0:
            return tasks
        data = json.loads(stdout)
        if not isinstance(data, list):
            data = [data]

        computer_name = os.environ.get('COMPUTERNAME', '').upper()
        current_user = os.environ.get('USERNAME', '')

        for item in data:
            task_name = item.get('TaskName', '')
            task_path = item.get('TaskPath', '')
            author = item.get('Author', '') or ''
            executable = item.get('Executable', '') or ''
            state_val = item.get('State')

            # Фильтрация системных задач
            if task_path.lower().startswith(r'\microsoft\windows\\'):
                continue
            if 'microsoft' in author.lower() or 'корпорация майкрософт' in author.lower():
                continue
            system_accounts = [
                'nt authority\\system',
                'nt authority\\local service',
                'nt authority\\network service'
            ]
            if author.lower() in system_accounts:
                continue
            if computer_name and author.strip().upper().startswith(computer_name + '$'):
                continue
            if not author and not any(x in task_path.lower() for x in [current_user.lower(), 'appdata', 'user']):
                continue
            if executable:
                exec_lower = os.path.expandvars(executable).lower()
                system_paths = [
                    r'c:\windows\system32',
                    r'c:\windows\syswow64',
                    r'c:\windows\system',
                ]
                if any(sp.lower() in exec_lower for sp in system_paths):
                    continue

            # Преобразование состояния
            if state_val == 3:
                state = "Готово"
            elif state_val == 4:
                state = "Выполняется"
            elif state_val == 1:
                state = "Отключено"
            else:
                state = f"Неизвестно ({state_val})"

            # Форматирование даты
            created = item.get('Date', '')
            if created and isinstance(created, str):
                try:
                    if '.' in created:
                        created = created.split('.')[0]
                    if '+' in created:
                        created = created.split('+')[0]
                    dt = datetime.datetime.fromisoformat(created[:19])
                    created = dt.strftime("%H:%M/%d.%m.%Y")
                except:
                    created = "Неизвестно"
            else:
                created = ""

            tasks.append({
                'name': task_name,
                'state': state,
                'author': author,
                'created': created
            })
    except Exception:
        pass
    return tasks

def get_active_setup():
    entries = []
    paths = [
        r"SOFTWARE\Microsoft\Active Setup\Installed Components",
        r"SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components"
    ]
    for path in paths:
        for name, value, timestamp in enum_reg_key(winreg.HKEY_LOCAL_MACHINE, path):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{path}\\{name}", 0,
                                    winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                    try:
                        stub_path, _ = winreg.QueryValueEx(key, "StubPath")
                        if stub_path:
                            if isinstance(stub_path, str) and stub_path.startswith("%"):
                                stub_path = expand_env_string(stub_path)
                            entries.append({
                                'location': f"Active Setup: {path}",
                                'name': name,
                                'command': stub_path,
                                'created': filetime_to_datetime(timestamp),
                                'type': 'active_setup'
                            })
                    except:
                        pass
            except:
                pass
    return entries

def get_logon_scripts():
    entries = []
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_READ) as key:
            script, _ = winreg.QueryValueEx(key, "UserInitMprLogonScript")
            if script:
                entries.append({
                    'location': "Реестр: HKCU\\Environment",
                    'name': "UserInitMprLogonScript",
                    'command': script,
                    'created': filetime_to_datetime(get_reg_key_timestamp(winreg.HKEY_CURRENT_USER, r"Environment")),
                    'type': 'logon_script'
                })
    except:
        pass
    return entries

# ------------------------------------------------------------
# Параллельное сканирование
# ------------------------------------------------------------
_SCANNERS = [
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
]

def get_all_startup_entries(use_cache=True, force_refresh=False):
    """
    Возвращает список всех записей автозагрузки.
    Если use_cache=True и кэш актуален, возвращает кэшированные данные.
    При force_refresh=True игнорирует кэш и выполняет полное сканирование.
    """
    if use_cache and not force_refresh:
        cached = _get_cached()
        if cached is not None:
            return cached

    entries = []
    # Параллельный запуск всех сканеров
    with ThreadPoolExecutor(max_workers=min(len(_SCANNERS), 8)) as executor:
        future_to_scanner = {executor.submit(scanner): scanner for scanner in _SCANNERS}
        for future in as_completed(future_to_scanner):
            try:
                result = future.result()
                entries.extend(result)
            except Exception:
                # Игнорируем ошибки в отдельных сканерах
                pass

    if use_cache:
        _set_cache(entries)
    return entries