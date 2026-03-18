# Doctor AI
<img width="1871" height="991" alt="image" src="https://github.com/user-attachments/assets/b685638b-3ee2-4b1e-922f-931ed96a51d6" />

<p align="center">
  <strong>Windows security & health — Scan, EDR, AI analysis, VT, proactive protection, one GUI</strong>
</p>

<p align="center">
  <code>Go 1.25+</code> · <code>Windows</code> · <code>PowerShell</code> · <code>OpenAI (optional)</code> · <code>VirusTotal (optional)</code>
</p>

---

## Что это

**Doctor AI** — Windows security toolkit с GUI и CLI:
- сбор телеметрии и EDR-событий,
- корреляция инцидентов,
- AI-пояснения и AI-assisted авто-защита,
- работа с VirusTotal/whitelist/blacklist,
- обновления и драйверные сценарии.

Проект можно запускать как **один `doctor-gui.exe`** или как набор CLI утилит.

---

## Ключевые функции

| Блок | Что делает |
|------|------------|
| **Scan / Plan / Fix** | Телеметрия, эвристика, план и точечное исправление |
| **EDR Agent** | Читает Event Log + реестр, пишет `logs/edr_events.jsonl` |
| **Analyze** | Корреляция цепочек и риск-оценка, опционально AI-объяснения |
| **Smart Scan** | Локальный эвристический скан подозрительных файлов |
| **Knight Mode** | Проактивная защита: эвристика + AI verdict + авто-реакция + enforcement по путям из EDR корреляции |
| **Update / Drivers** | Update, driver-install/driver-auto, AI Driver Assistant |
| **VT + Hashlist** | Репутация хэшей, авто-кэширование в whitelist/blacklist |
| **Self-test** | `simulate-edr` для безопасной проверки детекта без malware |
| **Lab / Simulation (GUI)** | Генерация benign/malicious/mixed потока + Analyze + incidents timeline |
| **Quick Protect** | Пошаговый режим для обычного пользователя: Agent → Analyze → Knight Mode |
| **Startup / Portable Check** | Проверка прав, ключей и наличия Sysmon/assets при запуске |

---

## Требования и зависимости

### ОС и права
- **Windows 10/11** (основной target).
- Для полного функционала (EDR, driver flows, quarantine, process kill) запускай **от администратора**.

### Программы/компоненты
- **PowerShell 5.1+**.
- **Go 1.25+** (только если собираешь из исходников).
- **Sysmon обязателен** для полного EDR-детекта: GUI/Agent выполняет обязательную установку (если включён `autoInstall`).

### API-ключи (опционально)
- **OpenAI**: для Analyze AI, Knight Mode AI verdict, AI Driver Assistant.
- **VirusTotal**: для проверки хэшей во вкладке Quarantine.

---

## Быстрый старт (рекомендуемый сценарий)

### Один exe
1. Собери/возьми `doctor-gui.exe`.
2. Запусти **от имени администратора**.
3. В Settings укажи OpenAI и VT ключи (если нужны).

### Рекомендуемый порядок для полноценного детекта
1. **Start Agent** (сбор EDR в фоне, при этом Sysmon устанавливается/обновляется обязательно).
2. Подожди накопление событий / запусти Scan.
3. **Analyze AI** (корреляция + объяснения).
4. **Knight Mode** (проактивная реакция на подозрительные объекты).

> Если агент не запущен, детект возможен, но качество корреляции ниже (меньше EDR-контекста).

---


## Portable / 1 exe и перенос на другой ПК

- `doctor-gui.exe` можно переносить на флешке и запускать на другом Windows ПК.
- При первом запуске приложение создаёт рабочие пути: `configs/`, `logs/`, `quarantine/`, `db/sysmon/`, `db/tools/sysmon/`.
- Приложение восстанавливает встроенные конфиги и `sysmonconfig.xml`, а также подтягивает `Sysmon64.exe` в `db/tools/sysmon/` (если отсутствует); запуск Agent завершится ошибкой, если обязательная установка Sysmon не удалась.
- Для полного функционала рекомендован запуск **от администратора**.

---

## Как уменьшить риск детекта EXE как suspicious

Важно: "встроить сертификат легитимности" без внешнего доверенного УЦ нельзя.

Рекомендуется для релиза:
1. Подписывать build через **OV/EV Code Signing certificate** (лучше EV).
2. Стабилизировать publisher identity (один cert, одинаковый product name/version).
3. Делать reproducible release pipeline и публиковать checksums (SHA256).
4. Отправлять релиз на Microsoft Defender / SmartScreen reputation buildup (постепенно).

Самоподписанный сертификат подходит только для внутренних стендов и не даёт нормальной репутации SmartScreen.

---

## Публикация в GitHub (ваш репозиторий)

```powershell
# 1) добавить ваш remote
 git remote add myrepo https://github.com/<your_user>/<your_repo>.git

# 2) проверить текущую ветку
 git branch --show-current

# 3) отправить изменения
 git push -u myrepo <branch_name>
```

Если включена 2FA, используйте GitHub PAT/token или GitHub CLI auth.

---

## Быстрый старт (рекомендуемый сценарий)

### Один exe
1. Собери/возьми `doctor-gui.exe`.
2. Запусти **от имени администратора**.
3. В Settings укажи OpenAI и VT ключи (если нужны).

### Рекомендуемый порядок для полноценного детекта
1. **Start Agent** (сбор EDR в фоне, при этом Sysmon устанавливается/обновляется обязательно).
2. Подожди накопление событий / запусти Scan.
3. **Analyze AI** (корреляция + объяснения).
4. **Knight Preview** (сначала посмотреть план действий).
5. **Knight Mode** (применить действия).

> Если агент не запущен, детект возможен, но качество корреляции ниже (меньше EDR-контекста).

---


## Portable / 1 exe и перенос на другой ПК

- `doctor-gui.exe` можно переносить на флешке и запускать на другом Windows ПК.
- При первом запуске приложение создаёт рабочие пути: `configs/`, `logs/`, `quarantine/`, `db/sysmon/`, `db/tools/sysmon/`.
- Приложение восстанавливает встроенные конфиги и `sysmonconfig.xml`, а также подтягивает `Sysmon64.exe` в `db/tools/sysmon/` (если отсутствует); запуск Agent завершится ошибкой, если обязательная установка Sysmon не удалась.
- Для полного функционала рекомендован запуск **от администратора**.

---

## Как уменьшить риск детекта EXE как suspicious

Важно: "встроить сертификат легитимности" без внешнего доверенного УЦ нельзя.

Рекомендуется для релиза:
1. Подписывать build через **OV/EV Code Signing certificate** (лучше EV).
2. Стабилизировать publisher identity (один cert, одинаковый product name/version).
3. Делать reproducible release pipeline и публиковать checksums (SHA256).
4. Отправлять релиз на Microsoft Defender / SmartScreen reputation buildup (постепенно).

Самоподписанный сертификат подходит только для внутренних стендов и не даёт нормальной репутации SmartScreen.

---

### Ошибка `no such file or directory` для `edr_events.jsonl`

Если вы запускаете GUI через `go run ./cmd/gui`, бинарник работает из временной папки Go build cache, поэтому путь может выглядеть как `/root/.cache/go-build/.../logs/edr_events.jsonl`.

Решение:
- Для стабильной работы запускайте собранный `doctor-gui.exe`/`doctor-gui` из рабочей папки проекта,
- либо сначала нажмите **Lab → Generate stream**,
- либо запустите **Agent**, чтобы создать/наполнить `logs/edr_events.jsonl`.
- В текущей версии GUI стартовый layout создаётся автоматически, включая пустой `logs/edr_events.jsonl`, поэтому ошибка обычно означает запуск не из каталога проекта или старый бинарник.

---

## Публикация в GitHub (ваш репозиторий)

```powershell
# 1) добавить ваш remote
 git remote add myrepo https://github.com/<your_user>/<your_repo>.git

# 2) проверить текущую ветку
 git branch --show-current

# 3) отправить изменения
 git push -u myrepo <branch_name>
```

Если включена 2FA, используйте GitHub PAT/token или GitHub CLI auth.

---

## Сборка

```powershell
cd c:\GoProject\src\doctor-ai

# CLI
go build -o doctor.exe   ./cmd/doctor
go build -o agent.exe    ./cmd/agent
go build -o analyze.exe  ./cmd/analyze

# GUI single exe
go build -o doctor-gui.exe ./cmd/gui
```

---

## CLI команды

```powershell
# Scan/Plan/Fix
.\doctor.exe scan
.\doctor.exe plan
.\doctor.exe fix --auto

# Agent
.\agent.exe
# или
.\doctor.exe agent-run --config configs/agent.json

# Analyze
.\analyze.exe --ai --ai-max 5
# или
.\doctor.exe analyze --in logs/edr_events.jsonl --logs logs --ai

# API key
.\doctor.exe ai-set-key --logs logs
.\doctor.exe ai-test --logs logs
```

---

## Self-test: проверить корреляцию/защиту без реального вируса

```powershell
# 1) Сгенерировать синтетические EDR-события
.\doctor.exe simulate-edr --out logs\edr_events.jsonl --scenario mixed --count 30

# 2) Проверить корреляцию
.\analyze.exe

# 3) (опционально) запустить Knight Mode в GUI
```

Сценарии:
- `--scenario malicious` — злонамеренные цепочки,
- `--scenario benign` — в основном безопасный поток,
- `--scenario mixed` — смешанный поток.

### То же самое в GUI (без консоли)
Открой вкладку **Lab**:
1. **Generate stream** (выбери scenario + count),
2. **Run Analyze**,
3. **Show timeline** для просмотра инцидентов по времени.

---

## Update / Drivers (что важно знать)

- `driver-install` / `driver-auto` — **интерактивные** операции.
- Из GUI они запускаются в **отдельном терминале**, чтобы не блокировать сервер GUI.
- Во вкладке Update доступно:
  - подробный **Driver Report** (installed/problematic/downloaded),
  - **AI Driver Assistant**: пользователь описывает проблему (например, "мигает экран"), AI предлагает команду, после подтверждения выполняется установка.

---

## Конфигурация и данные

| Файл | Назначение |
|------|------------|
| `configs/doctor.ps1` | scan/plan/fix/update/driver logic |
| `configs/policy.json` | политика карантина/auto-fix |
| `configs/agent.json` | источники EDR, output/state, retention |
| `logs/edr_events.jsonl` | EDR события |
| `logs/.openai_key` | OpenAI key |
| `logs/.vt_key` | VirusTotal key |
| `logs/whitelist_hashes.json` | trusted hashes |
| `logs/blacklist_hashes.json` | malicious hashes |
| `quarantine/` | перемещённые подозрительные файлы |

---

## Примечания по безопасности

- Knight Mode и auto-remediation могут завершать процессы и перемещать файлы в карантин.
- Для production лучше сначала прогонять в режиме наблюдения (Analyze + отчёты), затем включать авто-действия.
- Всегда держи резервную копию критичных данных перед aggressive remediation.

---

## Лицензия

Проект можно использовать и модифицировать не для коммерческого использования.

---

<p align="center">
  <sub>Doctor AI — scan, EDR, correlate, VT, AI explain, proactive guard</sub>
</p>
