import hashlib
import os
import json
import time
import base64
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from PySide6.QtWidgets import QMessageBox

# ------------------------------------------------------------
# Конфигурация
# ------------------------------------------------------------
_ENCRYPTED_KEY = "OWJjODhkMDJlYTdjMzFiYmM3Y2JjYTAxMDdiMzEwMzU0YTRjOWU5NWIyNTRiMDQ1ZWRkNDgyMzVjYzY5M2I5NA=="
_DEFAULT_API_KEY = base64.b64decode(_ENCRYPTED_KEY).decode('utf-8')
_BASE_URL = "https://www.virustotal.com/api/v3/files/"
_RATE_LIMIT_INTERVAL = 15.0  # секунд между запросами (4 в минуту = 15 сек)
_MAX_RETRIES = 3
_TIMEOUT = 15

# Глобальное состояние для rate limiting
_last_request_time = 0.0

# ------------------------------------------------------------
# Вспомогательные функции
# ------------------------------------------------------------
def _get_cache_path():
    cache_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(cache_dir, exist_ok=True)
    return os.path.join(cache_dir, "vt_cache.json")

def _load_cache():
    cache_path = _get_cache_path()
    if os.path.exists(cache_path):
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            pass
    return {}

def _save_cache(cache):
    cache_path = _get_cache_path()
    try:
        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump(cache, f, indent=2)
    except:
        pass

def _is_cache_fresh(timestamp):
    return (time.time() - timestamp) < 7 * 24 * 3600

def _rate_limit_wait():
    """Ожидание для соблюдения лимита запросов."""
    global _last_request_time
    elapsed = time.time() - _last_request_time
    if elapsed < _RATE_LIMIT_INTERVAL:
        time.sleep(_RATE_LIMIT_INTERVAL - elapsed)
    _last_request_time = time.time()

def _requests_session(proxy=None):
    """Создаёт сессию requests с настроенными повторными попытками."""
    session = requests.Session()
    retries = Retry(
        total=_MAX_RETRIES,
        backoff_factor=1.0,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('https://', adapter)
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
    elif 'HTTP_PROXY' in os.environ or 'HTTPS_PROXY' in os.environ:
        # Используем системные переменные окружения
        pass  # requests автоматически подхватывает HTTP_PROXY/HTTPS_PROXY
    return session

# ------------------------------------------------------------
# Основная функция проверки файла (совместимость с GUI)
# ------------------------------------------------------------
def check_file_virustotal(file_path, parent_widget=None, api_key=None, proxy=None):
    """
    Проверяет файл через VirusTotal API.
    Возвращает (malicious, total, link) или (None, None, None) при ошибке.
    """
    if not os.path.isfile(file_path):
        if parent_widget:
            QMessageBox.warning(parent_widget, "Ошибка", "Файл не существует.")
        return None, None, None

    file_hash = calculate_sha256(file_path)
    if not file_hash:
        if parent_widget:
            QMessageBox.critical(parent_widget, "Ошибка", "Не удалось вычислить хэш файла.")
        return None, None, None

    # Проверка кэша
    cache = _load_cache()
    if file_hash in cache:
        entry = cache[file_hash]
        if _is_cache_fresh(entry.get('timestamp', 0)):
            return entry.get('malicious', 0), entry.get('total', 0), entry.get('link')

    # Выполнение запроса с rate limiting
    _rate_limit_wait()

    headers = {"x-apikey": api_key or _DEFAULT_API_KEY}
    url = _BASE_URL + file_hash

    session = _requests_session(proxy)
    try:
        response = session.get(url, headers=headers, timeout=_TIMEOUT)
    except requests.exceptions.RequestException as e:
        if parent_widget:
            QMessageBox.critical(parent_widget, "Ошибка соединения",
                                 f"Не удалось подключиться к VirusTotal:\n{str(e)}")
        return None, None, None

    if response.status_code == 200:
        data = response.json()
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        undetected = stats.get('undetected', 0)
        harmless = stats.get('harmless', 0)
        total = malicious + suspicious + undetected + harmless
        link = f"https://www.virustotal.com/gui/file/{file_hash}"

        # Сохраняем в кэш
        cache[file_hash] = {
            'malicious': malicious,
            'total': total,
            'link': link,
            'timestamp': time.time()
        }
        _save_cache(cache)

        return malicious, total, link

    elif response.status_code == 404:
        # Файл не найден в базе
        cache[file_hash] = {
            'malicious': 0,
            'total': 0,
            'link': None,
            'timestamp': time.time()
        }
        _save_cache(cache)
        return 0, 0, None
    else:
        if parent_widget:
            QMessageBox.critical(parent_widget, "Ошибка API",
                                 f"Ошибка VirusTotal API: {response.status_code}\n{response.text[:200]}")
        return None, None, None

# ------------------------------------------------------------
# Дополнительные функции
# ------------------------------------------------------------
def calculate_sha256(file_path):
    """Вычисляет SHA256 хэш файла."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for block in iter(lambda: f.read(8192), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception:
        return None

def check_hashes_batch(hashes, api_key=None, proxy=None):
    """
    Проверяет список хэшей (до 500) через VirusTotal.
    Возвращает словарь {hash: {'malicious': int, 'total': int, 'link': str}}.
    """
    if not hashes:
        return {}
    if len(hashes) > 500:
        hashes = hashes[:500]  # Ограничение API

    # Проверяем кэш сначала
    cache = _load_cache()
    result = {}
    hashes_to_fetch = []
    for h in hashes:
        if h in cache and _is_cache_fresh(cache[h].get('timestamp', 0)):
            result[h] = {
                'malicious': cache[h].get('malicious', 0),
                'total': cache[h].get('total', 0),
                'link': cache[h].get('link')
            }
        else:
            hashes_to_fetch.append(h)

    if not hashes_to_fetch:
        return result

    _rate_limit_wait()
    headers = {"x-apikey": api_key or _DEFAULT_API_KEY}
    session = _requests_session(proxy)

    # Пакетный запрос (POST /files/analyse с несколькими хэшами? В v3 нет batch GET, нужно делать отдельные запросы)
    # Реализуем последовательно с rate limiting
    for h in hashes_to_fetch:
        url = _BASE_URL + h
        try:
            response = session.get(url, headers=headers, timeout=_TIMEOUT)
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                undetected = stats.get('undetected', 0)
                harmless = stats.get('harmless', 0)
                total = malicious + suspicious + undetected + harmless
                link = f"https://www.virustotal.com/gui/file/{h}"
                result[h] = {'malicious': malicious, 'total': total, 'link': link}
                cache[h] = {'malicious': malicious, 'total': total, 'link': link, 'timestamp': time.time()}
            elif response.status_code == 404:
                result[h] = {'malicious': 0, 'total': 0, 'link': None}
                cache[h] = {'malicious': 0, 'total': 0, 'link': None, 'timestamp': time.time()}
            else:
                result[h] = {'malicious': 0, 'total': 0, 'link': None, 'error': response.status_code}
        except Exception as e:
            result[h] = {'malicious': 0, 'total': 0, 'link': None, 'error': str(e)}
        _rate_limit_wait()

    _save_cache(cache)
    return result

def clear_cache():
    """Очищает кэш VirusTotal."""
    cache_path = _get_cache_path()
    if os.path.exists(cache_path):
        os.remove(cache_path)

# ------------------------------------------------------------
# Для обратной совместимости с GUI
# ------------------------------------------------------------
def check_file_virustotal_simple(file_path):
    """Упрощённый вызов без GUI-родителя."""
    return check_file_virustotal(file_path, parent_widget=None)