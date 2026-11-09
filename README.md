<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/rival-afk/zenoku-design/main/assets/zeno/png/readme-banner-dark.png">
    <img src="https://raw.githubusercontent.com/rival-afk/zenoku-design/main/assets/zeno/png/readme-banner.png" alt="zeno" width="440">
  </picture>
</p>

# zenо

[![ci](https://github.com/rival-afk/zeno/actions/workflows/ci.yml/badge.svg)](https://github.com/rival-afk/zeno/actions/workflows/ci.yml)
[![release](https://github.com/rival-afk/zeno/actions/workflows/release.yml/badge.svg)](https://github.com/rival-afk/zeno/actions/workflows/release.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**zeno** — локальный аналог VirusTotal с открытым кодом, работающий только на открытых движках и открытых базах.

## Что умеет

- **Хэши файла**: MD5, SHA-1, SHA-256
- **Открытые базы (без ключей):**
  - [CIRCL HashLookup](https://www.circl.lu/services/hashlookup/) — поиск SHA-256 среди известных вредоносных файлов
  - [MalwareBazaar (abuse.ch)](https://bazaar.abuse.ch/) — поиск известных сэмплов (нужен бесплатный Auth-Key, без него запрос пропускается)
- **Открытые AV/YARA-движки:**
  - **ClamAV** — через `clamd` (TCP INSTREAM, порт 3310 по умолчанию) и через `clamscan` CLI
  - **YARA-X** — через CLI `yarax`/`yara-x` (движок разработки VirusTotal, сам открыт: github.com/VirusTotal/yara-x)
  - любые другие движки настраиваются в `zeno.toml` (например `esets_cli`, `sophos-savdi`, custom)

## Установка

`zeno` ставит **готовый бинарник из Releases** (сборку делают GitHub Actions):

Linux / macOS (одной командой):

```bash
curl -fsSL https://raw.githubusercontent.com/rival-afk/zeno/main/install.sh | sh
```

Windows (одной командой):

```powershell
powershell -c "irm https://raw.githubusercontent.com/rival-afk/zeno/main/install.ps1 | iex"
```

Бинарник для Windows устанавливается в `%LOCALAPPDATA%\Programs\zeno` и добавляется в user PATH.
Бинарник для Linux/macOS — в `~/.local/bin`.

Вручную:

```bash
git clone https://github.com/rival-afk/zeno && \
cargo install --path zeno    # сборка из исходников, если релизов нет
```

### Как публикуется релиз

Релизы делаются автоматически GitHub Actions (`.github/workflows/release.yml`): Windows x64, Linux amd64 (musl, static), macOS aarch64. Чтобы выпустить новую версию после фиксов:

```bash
git tag v0.2.1 && git push origin v0.2.1
```


## Использование

```bash
zeno scan файл.exe
zeno scan C:\Users\me\Downloads --json
zeno check     # проверить доступность баз
zeno engines   # показать настроенные движки
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
