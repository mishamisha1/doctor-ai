# Doctor AI
<img width="1871" height="991" alt="image" src="https://github.com/user-attachments/assets/b685638b-3ee2-4b1e-922f-931ed96a51d6" />

<p align="center">
  <strong>Windows security & health — scan, EDR, AI analysis, VirusTotal, one GUI</strong>
</p>

<p align="center">
  <code>Go 1.25</code> · <code>Windows</code> · <code>PowerShell</code> · <code>OpenAI</code> · <code>VirusTotal</code>
</p>

---

## Что это

**Doctor AI** — набор утилит и веб‑интерфейс для Windows: сбор телеметрии, эвристический анализ, EDR‑агент (события + реестр), корреляция инцидентов, проверка хэшей в VirusTotal, whitelist/blacklist и краткие объяснения через OpenAI. Всё можно запускать из одного exe с GUI или из консоли.

---

## Возможности

| Часть | Назначение |
|--------|------------|
| **Scan** | Сбор процессов, сети, автозапуска, Defender; сохранение в `scan_*.json` |
| **Plan / Fix** | Эвристики (неподписанное из temp/user), план действий, точечный fix (kill, карантин, отключение автозапуска) |
| **EDR Agent** | Опрос Event Log и реестра, запись событий в `edr_events.jsonl` |
| **Analyze** | Чтение последнего сканa + EDR, корреляция инцидентов, опционально AI (OpenAI) для краткого вердикта |
| **VirusTotal** | Проверка хэшей по API, автоматическое добавление в whitelist/blacklist |
| **GUI** | Один exe: сканы, анализ, защита, карантин, VT, обновления и драйверы |

---

## Структура проекта

```
doctor-ai/
├── cmd/
│   ├── doctor/      # Консольная оболочка: scan, plan, fix, agent-run, analyze и т.д.
│   ├── agent/       # EDR-агент: Event Log + реестр → edr_events.jsonl
│   ├── analyze/     # CLI-анализатор: EDR + последний scan_*.json, корреляция, AI
│   └── gui/         # Веб-GUI (один exe): все функции + встроенные configs при первом запуске
├── internal/
│   ├── agent/       # Конфиг агента, сбор событий, Sysmon, реестр, запись JSONL
│   ├── analyzer/    # Коррелятор, цепочки событий, риск, рекомендации, policy
│   ├── ai/          # Клиент OpenAI, промпты, краткие объяснения инцидентов
│   ├── collector/   # Запуск doctor.ps1 (scan/fix/update/driver-*), чтение вывода
│   ├── hashlist/    # Whitelist/blacklist хэшей (файлы в logs/)
│   ├── model/       # Модели: скан, инцидент, события
│   ├── remediation/ # Исполнение плана исправлений
│   ├── runner/      # RunAnalyze, извлечение хэшей из scan/EDR, интеграция VT+hashlist+AI
│   ├── telemetry/   # Адаптеры Event Log, реестра
│   ├── virustotal/  # Клиент VirusTotal API (проверка по хэшу)
│   └── writer/      # Запись JSONL
├── configs/
│   ├── doctor.ps1   # PowerShell: сбор телеметрии, эвристики, plan/fix, update, драйверы
│   ├── policy.json  # Политика: quarantinePaths, autoFix, allowedPackages
│   └── agent.json   # Конфиг EDR-агента (источники логов, реестр, вывод)
├── db/              # Sysmon (конфиг, путь к exe при использовании)
└── cmd/gui/embedded/configs/  # Копии doctor.ps1 и policy.json для embed в GUI-exe
```

### За что что отвечает

| Компонент | Отвечает за |
|-----------|-------------|
| **cmd/doctor** | Единая точка входа в консоли: вызов doctor.ps1 (scan/plan/fix/avscan/update/driver-install/driver-auto), запуск agent и analyze, сохранение AI-ключа. |
| **cmd/agent** | Фоновый EDR: опрос Security/System/Sysmon/PowerShell и др., слежение за Run/RunOnce, дедуп, запись в `edr_events.jsonl` и state. |
| **cmd/analyze** | Чтение `edr_events.jsonl` и последнего `scan_*.json`, корреляция, извлечение хэшей, проверка по hashlist и VirusTotal, при необходимости — краткое объяснение через OpenAI. |
| **cmd/gui** | HTTP-сервер + встроенная HTML/JS панель: Scan, Protect, Quarantine (VT, whitelist/blacklist), Update, Settings. При первом запуске создаёт `configs/` и `logs/` из встроенных файлов. |
| **internal/agent** | Конфигурация агента, сбор событий из логов и реестра, Sysmon, матчинг по policy, запись в JSONL. |
| **internal/analyzer** | Корреляция событий, цепочки, оценка риска, рекомендации, интеграция с policy. |
| **internal/ai** | Запросы к OpenAI, формирование короткого текста по инциденту (вердикт, причины, рекомендация). |
| **internal/collector** | Запуск doctor.ps1 с нужной командой и policy, получение вывода. |
| **internal/hashlist** | Хранение и проверка whitelist/blacklist хэшей (файлы в `logs/`). |
| **internal/runner** | Оркестрация Analyze: загрузка данных, хэши, VT, hashlist, вызов AI, формирование отчёта. |
| **internal/virustotal** | Запрос к VirusTotal API (отчёт по хэшу), использование в runner и GUI. |
| **configs/doctor.ps1** | Вся логика сбора телеметрии, эвристик, плана и применения fix, обновлений и установки/поиска драйверов. |

---

## Сборка

Требуется **Go 1.25+** и **Windows**.

```powershell
cd c:\GoProject\src\doctor-ai

# Консольные утилиты
go build -o doctor.exe   ./cmd/doctor
go build -o agent.exe    ./cmd/agent
go build -o analyze.exe ./cmd/analyze

# GUI (один exe, при первом запуске создаёт configs/ и logs/)
go build -o doctor-gui.exe ./cmd/gui
```

Либо используй `build.ps1`, если он настроен под твой путь.

---

## Запуск

### Один exe (рекомендуется для распространения)

1. Скопируй **только** `doctor-gui.exe` в любую папку.
2. Запусти — при первом запуске создадутся `configs/` и `logs/`, подставится встроенный `doctor.ps1` и `policy.json`.
3. Откроется браузер с панелью на `http://127.0.0.1:19527`.

В GUI: **Settings** — укажи OpenAI и VirusTotal API ключи (они сохраняются в `logs/`).

### Консоль

- **Скан и исправления:**  
  `.\doctor.exe scan` → `.\doctor.exe plan` → `.\doctor.exe fix` (или через GUI кнопки Run с командами `scan` / `fix` и т.д.)
- **EDR:**  
  `.\agent.exe` (читает `configs/agent.json`, пишет в `logs/edr_events.jsonl`).
- **Анализ с AI:**  
  `.\analyze.exe --ai --ai-max 5` или кнопка Analyze в GUI.

---

## Конфигурация

| Файл | Назначение |
|------|------------|
| **configs/policy.json** | Пути карантина (temp/user), флаги autoFix (kill, quarantine, disable autorun), разрешённые пакеты для update. |
| **configs/agent.json** | Включение Sysmon, источники Event Log, реестр, путь вывода EDR и state. |
| **logs/.openai_key** | Ключ OpenAI (GUI или `doctor ai-set-key`). |
| **logs/.vt_key** | Ключ VirusTotal (через GUI Settings). |
| **logs/whitelist_hashes.json**, **logs/blacklist_hashes.json** | Создаются автоматически при проверках VT; повторно по ним не дергаем API. |

---

## Лицензия

Проект можно использовать и модифицировать по твоему усмотрению.

---

<p align="center">
  <sub>Doctor AI — scan, EDR, correlate, VT, AI explain</sub>
</p>
