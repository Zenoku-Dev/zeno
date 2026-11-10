<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Zenoku-Dev/zenoku-design/main/assets/zeno/readme-banner-animated-dark.svg">
    <img src="https://raw.githubusercontent.com/Zenoku-Dev/zenoku-design/main/assets/zeno/readme-banner-animated.svg" alt="zeno" width="440">
  </picture>
</p>

# zenо

[![ci](https://github.com/Zenoku-Dev/zeno/actions/workflows/ci.yml/badge.svg)](https://github.com/Zenoku-Dev/zeno/actions/workflows/ci.yml)
[![release](https://github.com/Zenoku-Dev/zeno/actions/workflows/release.yml/badge.svg)](https://github.com/Zenoku-Dev/zeno/actions/workflows/release.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**zeno** — локальный аналог VirusTotal с открытым кодом, работающий только на открытых движках и открытых базах.

## Что умеет

- **Хэши файла**: MD5, SHA-1, SHA-256
- **Архивы**: `.zip`, `.tar`, `.tar.gz`/`.tgz` — файлы внутри сканируются как обычные (хэши + базы + движки), в выводе путь вида `archive.zip!inner/path`; сетевые lookups выполняются и для содержимого; `zeno scan x.zip --no-archives` — сканировать архив как непрозрачный файл
- **Папки**: рекурсивно (`ignore_dirs` в конфиге)
- **Открытые базы (без ключей):**
  - [CIRCL HashLookup](https://www.circl.lu/services/hashlookup/) — поиск SHA-256 среди известных вредоносных файлов
  - [MalwareBazaar (abuse.ch)](https://bazaar.abuse.ch/) — поиск известных сэмплов (нужен бесплатный Auth-Key, без него запрос пропускается)
- **Открытые AV/YARA-движки:**
  - **ClamAV** — через `clamd` (TCP INSTREAM, порт 3310 по умолчанию) и через `clamscan` CLI
  - **YARA-X** — через CLI `yarax`/`yara-x` (движок разработки VirusTotal, сам открыт: github.com/VirusTotal/yara-x)
  - любые другие движки настраиваются в `zeno.toml` (например `esets_cli`, `sophos-savdi`, custom)
- **Динамический запуск** (`zeno run`, docs/emulation.md): РЕАЛЬНОЕ выполнение файла в изоляции — Linux ELF в Docker+alpine (`--network=none`), Windows PE через Cuckoo3, проверка macOS-окружения через OSX-KVM

## Установка

`zeno` ставит **готовый бинарник из Releases** (сборку делают GitHub Actions):

Linux / macOS (одной командой):

```bash
curl -fsSL https://raw.githubusercontent.com/Zenoku-Dev/zeno/main/install.sh | sh
```

Windows (одной командой):

```powershell
powershell -c "irm https://raw.githubusercontent.com/Zenoku-Dev/zeno/main/install.ps1 | iex"
```

Бинарник для Windows устанавливается в `%LOCALAPPDATA%\Programs\zeno` и добавляется в user PATH.
Бинарник для Linux/macOS — в `~/.local/bin`.

Вручную:

```bash
git clone https://github.com/Zenoku-Dev/zeno && \
cargo install --path zeno    # сборка из исходников, если релизов нет
```

### Как публикуется релиз

Релизы делаются автоматически GitHub Actions (`.github/workflows/release.yml`): Windows x64, Linux x86_64 (musl, static), Linux ARM64 (glibc ≥ 2.35), macOS Apple Silicon + macOS Intel. Чтобы выпустить новую версию после фиксов:

```bash
git tag v0.4.0 && git push origin v0.4.0
```


## Использование

```bash
zeno scan файл.exe
zeno scan архив.zip            # файлы внутри архива тоже проверяются
zeno scan архив.tar.gz --offline
zeno scan C:\Users\me\Downloads --json
zeno check     # проверить доступность баз
zeno engines   # показать настроенные движки
zeno run sample.elf --target alpine --yes   # РЕАЛЬНЫЙ запуск в контейнере (см. docs/emulation.md)
```

## Конфигурация `~/.zeno/config.toml` (или `./zeno.toml`)

```toml
clamd_host = "127.0.0.1"   # если отсутствует — не сканировать через clamd
clamd_port = 3310
malwarebazaar_auth_key = "" # требуется бесплатный Auth-Key с bazaar.abuse.ch; без него MalwareBazaar пропускается
max_file_size_mb = 200      # лимит размера файла для хэширования
ignore_dirs = [".git", "node_modules", "target"]  # директории, пропускаемые при сканировании папки

[engine.clamscan]
cmd = "clamscan"
args = ["--no-summary", "{path}"]

[engine.yarax]
cmd = "yarax"
args = ["--rules", "C:/yara-rules/index.yar", "{path}"]
```

## Что это НЕ

- Не замена антивирусу. zeno — инструмент проверки по хэшам и движкам, в основном **оффлайн-friendly** и непрозрачный, полностью open-source.
- Не отправляет ваши файлы никуда. На удалённые базы уходят **только SHA-256 хэши** (как у VirusTotal web-lookup), сами файлы никогда не покидают ПК.

## Права и лицензия

MIT — см. LICENSE.
