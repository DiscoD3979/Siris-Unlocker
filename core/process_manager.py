import psutil
import os
import subprocess
import json
import shutil
from functools import lru_cache

# ==================== Глобальные настройки ====================

user_critical = {}

# ==================== Основные функции работы с процессами ====================

def get_process_list():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'ppid']):
        try:
            processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return processes

def is_process_critical(proc_info):
    pid = proc_info['pid']
    if pid in user_critical:
        return user_critical[pid]
    exe = proc_info.get('exe')
    if exe and exe.lower().startswith('c:\\windows'):
        return True
    return False

def set_process_critical(pid, critical):
    user_critical[pid] = critical

def kill_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.kill()
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False

def suspend_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.suspend()
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False

def resume_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.resume()
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False

def find_executable_in_path(name):
    return shutil.which(name)

# ==================== Информация о цифровой подписи (кэш) ====================

@lru_cache(maxsize=256)
def _get_cached_signature_info(exe_path):
    if not exe_path or not os.path.isfile(exe_path):
        return None
    escaped_path = exe_path.replace("'", "''")
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE

        ps_cmd = f"Get-AuthenticodeSignature -FilePath '{escaped_path}' | ConvertTo-Json"
        result = subprocess.run(
            ['powershell', '-Command', ps_cmd],
            capture_output=True,
            text=True,
            encoding='utf-8',
            check=False,
            startupinfo=startupinfo
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        data = json.loads(result.stdout)
        if not data:
            return None
        status = data.get('Status', 'Unknown')
        signer = data.get('SignerCertificate', {}).get('Subject', '')
        issuer = data.get('SignerCertificate', {}).get('Issuer', '')
        return {
            'status': status,
            'signer': signer,
            'issuer': issuer
        }
    except (json.JSONDecodeError, subprocess.SubprocessError):
        return None

def get_signature_info(exe_path):
    return _get_cached_signature_info(exe_path)

def is_suspicious_process(proc_info):
    exe = proc_info.get('exe')
    name = proc_info.get('name', '').lower()
    if not exe or exe == "Нет доступа":
        return False
    if exe.lower().startswith('c:\\windows'):
        return False
    system_names = [
        'svchost.exe', 'lsass.exe', 'winlogon.exe', 'services.exe', 'csrss.exe',
        'smss.exe', 'wininit.exe', 'spoolsv.exe', 'taskhostw.exe', 'dwm.exe',
        'explorer.exe', 'rundll32.exe'
    ]
    if name in system_names:
        return True
    return False

# ==================== Запуск приложений ====================

def launch_application(command):
    """
    Запускает указанную команду или исполняемый файл.
    Команда может содержать аргументы.
    """
    if not command:
        return False
    try:
        subprocess.Popen(command, shell=True)
        return True
    except Exception:
        return False