import os
import random
import string
import subprocess
import sys
import argparse
import shutil
import time
from pathlib import Path

# Цвета для вывода (если терминал поддерживает)
try:
    from colorama import init, Fore, Style
    init()
    COLORS = True
except ImportError:
    # fallback
    class Fore:
        GREEN = RED = YELLOW = CYAN = RESET = ''
    COLORS = False

def print_info(msg):
    print(f"{Fore.CYAN if COLORS else ''}[INFO] {msg}{Fore.RESET if COLORS else ''}")

def print_ok(msg):
    print(f"{Fore.GREEN if COLORS else ''}[OK] {msg}{Fore.RESET if COLORS else ''}")

def print_warning(msg):
    print(f"{Fore.YELLOW if COLORS else ''}[WARNING] {msg}{Fore.RESET if COLORS else ''}")

def print_error(msg):
    print(f"{Fore.RED if COLORS else ''}[ERROR] {msg}{Fore.RESET if COLORS else ''}")

def random_name(length=8):
    return ''.join(random.choices(string.ascii_lowercase, k=length)) + '.exe'

def ensure_unique_path(directory, base_name):
    name, ext = os.path.splitext(base_name)
    counter = 1
    candidate = os.path.join(directory, base_name)
    while os.path.exists(candidate):
        candidate = os.path.join(directory, f"{name}_{counter}{ext}")
        counter += 1
    return candidate

def check_required_files():
    """Проверяет наличие всех необходимых для сборки файлов."""
    required = {
        'SirisUnlocker.spec': 'Файл спецификации PyInstaller',
        'icon.ico': 'Иконка приложения',
        'ui/styles.qss': 'Файл стилей'
    }
    missing = []
    for path, desc in required.items():
        if not os.path.exists(path):
            missing.append(f"{desc} ({path})")
            print_warning(f"Отсутствует {desc}: {path}")
    if missing:
        print_error("Не найдены следующие файлы. Сборка может быть неполной.")
        if input("Продолжить? (y/N): ").strip().lower() != 'y':
            sys.exit(1)
    else:
        print_ok("Все необходимые файлы найдены.")

def ensure_data_in_spec():
    """Проверяет, добавлена ли папка data в spec-файл, и добавляет при необходимости."""
    spec_path = 'SirisUnlocker.spec'
    if not os.path.exists(spec_path):
        print_error("SirisUnlocker.spec не найден.")
        return False

    with open(spec_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Ищем строку с datas = ... и проверяем, есть ли ('data', 'data')
    if "('data', 'data')" not in content:
        print_warning("Папка data не добавлена в datas в spec-файле. Добавляем...")
        # Ищем строку, где datas = ... и добавляем туда ('data', 'data')
        import re
        # Находим блок datas = [...]
        pattern = r'(datas\s*=\s*\[)([^\]]*?)(\])'
        def replacer(m):
            start = m.group(1)
            middle = m.group(2)
            end = m.group(3)
            if "('data'" not in middle:
                if middle.strip():
                    new_middle = middle.rstrip() + ",\n    ('data', 'data')"
                else:
                    new_middle = "    ('data', 'data')"
                return start + new_middle + end
            return m.group(0)
        new_content = re.sub(pattern, replacer, content, flags=re.DOTALL)
        if new_content != content:
            with open(spec_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print_ok("Папка data добавлена в spec-файл.")
        else:
            print_warning("Не удалось автоматически добавить data в spec. Добавьте вручную строку ('data', 'data') в список datas.")
            return False
    else:
        print_ok("Папка data уже включена в spec.")
    return True

def build():
    parser = argparse.ArgumentParser(description="Сборка SirisUnlocker с случайным именем.")
    parser.add_argument('--name', type=str, help='Желаемое имя выходного файла (без .exe)')
    parser.add_argument('--clean', action='store_true', help='Удалить временные папки build и dist перед сборкой')
    args = parser.parse_args()

    start_time = time.time()

    # Проверяем обязательные файлы
    check_required_files()

    # Убеждаемся, что data включена в spec
    if not ensure_data_in_spec():
        print_warning("Папка data может отсутствовать в сборке. Проверьте spec вручную.")

    # Проверка наличия иконки
    if not os.path.exists('icon.ico'):
        print_warning("Файл icon.ico не найден, иконка не будет добавлена.")

    # Определяем имя выходного файла
    if args.name:
        out_name = args.name + '.exe'
    else:
        out_name = random_name()

    print_info(f"Сборка {out_name}...")

    # Очистка, если запрошено
    if args.clean:
        print_info("Очистка временных папок...")
        for folder in ['build', 'dist']:
            if os.path.exists(folder):
                shutil.rmtree(folder, ignore_errors=True)
                print_ok(f"Удалена папка {folder}")

    # Команда PyInstaller
    cmd = [
        sys.executable, '-m', 'PyInstaller',
        'SirisUnlocker.spec',
        '--distpath', 'dist',
        '--workpath', 'build',
        '--clean',  # очистка кеша внутри PyInstaller
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            print_error("Сборка завершилась с ошибкой:")
            print(result.stderr)
            sys.exit(1)
        else:
            print_ok("PyInstaller отработал успешно.")
    except Exception as e:
        print_error(f"Ошибка при выполнении PyInstaller: {e}")
        sys.exit(1)

    # Проверяем созданный файл
    default_exe = os.path.join('dist', 'SirisUnlocker.exe')
    if not os.path.exists(default_exe):
        print_error("Файл SirisUnlocker.exe не найден после сборки.")
        sys.exit(1)

    # Перемещаем с учётом уникальности
    final_path = ensure_unique_path('dist', out_name)
    os.rename(default_exe, final_path)
    print_ok(f"Готово: {final_path}")

    elapsed = time.time() - start_time
    print_info(f"Время сборки: {elapsed:.2f} сек")

    # Дополнительно: предложить удалить папку build
    if os.path.exists('build'):
        if input("Удалить временную папку build? (y/N): ").strip().lower() == 'y':
            shutil.rmtree('build', ignore_errors=True)
            print_ok("Папка build удалена.")

if __name__ == '__main__':
    build()