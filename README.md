<div align="center">

[![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=32&duration=3000&pause=1200&color=9B30FF&center=true&vCenter=true&width=700&lines=SirisUnlocker;%D0%9C%D0%BE%D1%89%D0%BD%D0%B0%D1%8F+%D1%83%D1%82%D0%B8%D0%BB%D0%B8%D1%82%D0%B0+%D0%B4%D0%BB%D1%8F+Windows;%D0%A1%D0%BD%D1%8F%D1%82%D0%B8%D0%B5+%D1%81%D0%B8%D1%81%D1%82%D0%B5%D0%BC%D0%BD%D1%8B%D1%85+%D0%BE%D0%B3%D1%80%D0%B0%D0%BD%D0%B8%D1%87%D0%B5%D0%BD%D0%B8%D0%B9;%D0%9A%D0%BE%D0%BD%D1%82%D1%80%D0%BE%D0%BB%D1%8C+%D0%B0%D0%B2%D1%82%D0%BE%D0%B7%D0%B0%D0%B3%D1%80%D1%83%D0%B7%D0%BA%D0%B8;%D0%A0%D0%B0%D1%81%D1%88%D0%B8%D1%80%D0%B5%D0%BD%D0%BD%D1%8B%D0%B9+%D0%B4%D0%B8%D1%81%D0%BF%D0%B5%D1%82%D1%87%D0%B5%D1%80+%D0%B7%D0%B0%D0%B4%D0%B0%D1%87;%D0%94%D0%BB%D1%8F+Windows+10%2F11)](https://git.io/typing-svg)

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/DiscoD3979/Siris-Unlocker?label=Релиз&style=for-the-badge&color=9B30FF)](https://github.com/DiscoD3979/Siris-Unlocker/releases/latest)
[![GitHub all releases](https://img.shields.io/github/downloads/DiscoD3979/Siris-Unlocker/total?style=for-the-badge&label=Скачиваний&color=9B30FF)](https://github.com/DiscoD3979/Siris-Unlocker/releases)
[![GitHub Repo stars](https://img.shields.io/github/stars/DiscoD3979/Siris-Unlocker?style=for-the-badge&color=9B30FF)](https://github.com/DiscoD3979/Siris-Unlocker/stargazers)
[![License](https://img.shields.io/badge/License-MIT-9B30FF?style=for-the-badge)](LICENSE)

</div>

---

## 📖 О проекте

**SirisUnlocker** — портативный инструмент для управления системой, снятия ограничений и контроля автозагрузки в Windows 10/11.

[Скачать последнюю версию](https://github.com/DiscoD3979/Siris-Unlocker/releases/latest)

---

## 🚀 Возможности

### 🖥 Диспетчер задач
- Древовидное отображение процессов с цветовой подсветкой (красный – критичные)
- Группировка по категориям: **Приложения**, **Фоновые процессы**, **Системные процессы**
- Завершение, заморозка и разморозка процессов
- Проверка файла процесса на VirusTotal
- Информация о цифровой подписи исполняемого файла
- Подтверждение при завершении критичных процессов
- Автообновление с настраиваемым интервалом (переключатель «Автообновление»)

### ⚙️ Автозагрузка
- Полный контроль над всеми точками автозапуска Windows:
  - Реестр (Run, RunOnce, Winlogon, ShellServiceObjectDelayLoad, AppInit_DLLs, KnownDLLs)
  - Папки автозагрузки (пользовательская и общая)
  - Планировщик задач (только пользовательские задачи)
  - Службы (автоматический запуск)
  - Active Setup
  - Logon Scripts
- Добавление, изменение, удаление записей
- Массовое удаление и перемещение в карантин
- Открытие папки с исполняемым файлом
- Встроенная справка для каждой вкладки

### 🔓 Снятие ограничений
- Сканирование системы на наличие десятков политик ограничений
- Автоматическая разблокировка найденных ограничений
- Ручной режим с выбором отдельных ограничений
  - Поддерживаются снятие таких ограничений на CMD, диспетчер задач, редактор реестра, панель управления, контекстные меню и многие другие

### 🛡 Карантин
- Безопасное хранение удалённых записей автозагрузки (реестр, файлы)
- Восстановление в исходное состояние
- Автоматическая очистка старых записей (настраиваемый срок)

### 🧰 Дополнительные инструменты (ExtraPage)
- Загрузка **Dr.Web CureIt!**
- Включение UAC
- Восстановление системного файла **hosts**
- Очистка временных папок (Temp, Windows\Temp, Prefetch)
- Сброс ассоциаций `.exe`
- Управление Защитником Windows (вкл/откл)
- Перезапуск Проводника
- Информация о системе (ЦП, ОЗУ, GPU, версия ОС)
- Запуск проверки системных файлов (SFC /Scannow)
- Перезагрузка в безопасный режим и обратно
- Подмена системных файлов (sethc.exe, Utilman.exe) с отложенной заменой
- Сброс оболочки Windows (Shell и Userinit)
- Добавление себя в автозагрузку (реестр, планировщик, папка, совместно с Explorer)
- Глобальные горячие клавиши: **Alt+T** (показать окно), **Alt+`** (запустить/активировать приложение)
- Режим «Поверх всех окон»
- Случайное имя окна (обфускация)

---

## 🛠 Технологический стек

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PySide6](https://img.shields.io/badge/PySide6-41CD52?style=for-the-badge&logo=qt&logoColor=white)
![Windows API](https://img.shields.io/badge/WinAPI-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Git](https://img.shields.io/badge/Git-F05032?style=for-the-badge&logo=git&logoColor=white)

---

## 📥 Быстрый старт (для разработчиков)

1. **Клонируйте репозиторий**  
   ```bash
   git clone https://github.com/DiscoD3979/Siris-Unlocker.git
   cd Siris-Unlocker
