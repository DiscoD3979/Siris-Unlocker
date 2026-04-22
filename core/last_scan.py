import os
import datetime
from pathlib import Path

# Московское время (UTC+3, фиксированное, без DST)
MSK_OFFSET = datetime.timedelta(hours=3)
MSK_TZ = datetime.timezone(MSK_OFFSET, name="MSK")

# Путь к файлу с временем последнего сканирования
LAST_SCAN_FILE = Path(__file__).parent.parent / "data" / "last_scan.txt"

# Кэш в памяти
_CACHED_TIME = None
_CACHED_TIMESTAMP = None

def _ensure_data_dir():
    """Создаёт папку data, если её нет."""
    data_dir = LAST_SCAN_FILE.parent
    if not data_dir.exists():
        data_dir.mkdir(parents=True, exist_ok=True)

def _now_msk():
    """Возвращает текущее время в МСК с timezone."""
    return datetime.datetime.now(datetime.timezone.utc).astimezone(MSK_TZ)

def _parse_msk(timestamp_str):
    """Парсит строку ISO формата и приводит к МСК, если возможно."""
    try:
        dt = datetime.datetime.fromisoformat(timestamp_str)
        if dt.tzinfo is None:
            # Считаем, что старые записи были в локальном времени без зоны, приводим к МСК
            dt = dt.replace(tzinfo=MSK_TZ)
        else:
            dt = dt.astimezone(MSK_TZ)
        return dt
    except Exception:
        return None

def get_last_scan_time():
    """Возвращает datetime последнего сканирования в МСК, или None, если файла нет."""
    global _CACHED_TIME, _CACHED_TIMESTAMP
    now = _now_msk()
    if _CACHED_TIME is not None and _CACHED_TIMESTAMP is not None:
        if (now - _CACHED_TIMESTAMP).total_seconds() < 1:
            return _CACHED_TIME

    if not LAST_SCAN_FILE.exists():
        _CACHED_TIME = None
        _CACHED_TIMESTAMP = now
        return None

    try:
        with open(LAST_SCAN_FILE, 'r', encoding='utf-8') as f:
            timestamp_str = f.read().strip()
            if timestamp_str:
                dt = _parse_msk(timestamp_str)
                _CACHED_TIME = dt
                _CACHED_TIMESTAMP = now
                return dt
    except Exception:
        pass

    _CACHED_TIME = None
    _CACHED_TIMESTAMP = now
    return None

def get_last_scan_timestamp():
    """Возвращает timestamp (float) последнего сканирования или 0."""
    dt = get_last_scan_time()
    return dt.timestamp() if dt else 0.0

def set_last_scan_time(dt=None):
    """Сохраняет время последнего сканирования в МСК (атомарно)."""
    _ensure_data_dir()
    if dt is None:
        dt = _now_msk()
    else:
        # Приводим к МСК, если передано другое время
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=MSK_TZ)
        else:
            dt = dt.astimezone(MSK_TZ)

    iso_str = dt.isoformat()
    temp_file = LAST_SCAN_FILE.with_suffix('.tmp')
    try:
        with open(temp_file, 'w', encoding='utf-8') as f:
            f.write(iso_str)
        os.replace(temp_file, LAST_SCAN_FILE)  # атомарная замена
    except Exception:
        if temp_file.exists():
            temp_file.unlink(missing_ok=True)
        raise

    global _CACHED_TIME, _CACHED_TIMESTAMP
    _CACHED_TIME = dt
    _CACHED_TIMESTAMP = _now_msk()

def clear_last_scan():
    """Удаляет файл с временем последнего сканирования."""
    if LAST_SCAN_FILE.exists():
        try:
            os.remove(LAST_SCAN_FILE)
            global _CACHED_TIME, _CACHED_TIMESTAMP
            _CACHED_TIME = None
            _CACHED_TIMESTAMP = None
        except Exception:
            pass

def is_first_scan():
    """Возвращает True, если сканирование ещё не проводилось."""
    return get_last_scan_time() is None

def reset_scan_time():
    """Устанавливает время последнего сканирования в текущее."""
    set_last_scan_time()