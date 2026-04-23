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
    from colorama import init, Fore
    init()
    COLORS = True
except ImportError:
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
        'ui/styles.qss': 'Файл стилей',
        'ui/icons': 'Папка с иконками'
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
    """Проверяет, добавлены ли data и icons в spec-файл, и добавляет при необходимости."""
    spec_path = 'SirisUnlocker.spec'
    if not os.path.exists(spec_path):
        print_error("SirisUnlocker.spec не найден.")
        return False

    with open(spec_path, 'r', encoding='utf-8') as f:
        content = f.read()

    modified = False
    # Проверка папки data
    if "('data', 'data')" not in content:
        print_warning("Папка data не добавлена в datas в spec-файле. Добавляем...")
        import re
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
            # Создаём резервную копию
            backup_path = spec_path + '.bak'
            shutil.copy2(spec_path, backup_path)
            print_info(f"Создана резервная копия: {backup_path}")
            with open(spec_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print_ok("Папка data добавлена в spec-файл.")
            content = new_content
            modified = True

    # Проверка папки icons (ui/icons -> ui/icons)
    if "('ui/icons', 'ui/icons')" not in content:
        print_warning("Папка ui/icons не добавлена в datas в spec-файле. Добавляем...")
        import re
        pattern = r'(datas\s*=\s*\[)([^\]]*?)(\])'
        def replacer(m):
            start = m.group(1)
            middle = m.group(2)
            end = m.group(3)
            if "('ui/icons'" not in middle:
                if middle.strip():
                    new_middle = middle.rstrip() + ",\n    ('ui/icons', 'ui/icons')"
                else:
                    new_middle = "    ('ui/icons', 'ui/icons')"
                return start + new_middle + end
            return m.group(0)
        new_content = re.sub(pattern, replacer, content, flags=re.DOTALL)
        if new_content != content:
            if not modified:
                backup_path = spec_path + '.bak'
                shutil.copy2(spec_path, backup_path)
                print_info(f"Создана резервная копия: {backup_path}")
            with open(spec_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print_ok("Папка ui/icons добавлена в spec-файл.")
            modified = True

    if not modified:
        print_ok("Все необходимые данные уже включены в spec.")
    return True

def build():
    parser = argparse.ArgumentParser(description="Сборка SirisUnlocker с случайным именем.")
    parser.add_argument('--name', type=str, help='Желаемое имя выходного файла (без .exe)')
    parser.add_argument('--clean', action='store_true', help='Удалить временные папки build и dist перед сборкой')
    parser.add_argument('--upx', action='store_true', help='Сжать итоговый EXE с помощью UPX (должен быть в PATH)')
    args = parser.parse_args()

    start_time = time.time()

    # Проверяем обязательные файлы
    check_required_files()

    # Убеждаемся, что data и icons включены в spec
    if not ensure_data_in_spec():
        print_warning("Папки data и/или ui/icons могут отсутствовать в сборке. Проверьте spec вручную.")

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

    # Команда PyInstaller с отображением прогресса
    cmd = [
        sys.executable, '-m', 'PyInstaller',
        'SirisUnlocker.spec',
        '--distpath', 'dist',
        '--workpath', 'build',
        '--clean',
        '--noconfirm'
    ]

    try:
        # Запускаем PyInstaller с выводом в реальном времени
        print_info("Запуск PyInstaller...")
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        for line in process.stdout:
            print(line, end='')
        process.wait()
        if process.returncode != 0:
            print_error("Сборка завершилась с ошибкой.")
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

    # Опциональное сжатие UPX
    if args.upx:
        print_info("Сжатие EXE через UPX...")
        try:
            subprocess.run(['upx', '--best', '--lzma', final_path], check=True)
            size_mb = os.path.getsize(final_path) / (1024 * 1024)
            print_ok(f"EXE сжат, новый размер: {size_mb:.2f} МБ")
        except Exception as e:
            print_warning(f"Не удалось сжать через UPX: {e}")

    elapsed = time.time() - start_time
    print_info(f"Время сборки: {elapsed:.2f} сек")

    # Дополнительно: предложить удалить папку build
    if os.path.exists('build'):
        if input("Удалить временную папку build? (y/N): ").strip().lower() == 'y':
            shutil.rmtree('build', ignore_errors=True)
            print_ok("Папка build удалена.")

if __name__ == '__main__':
    build()