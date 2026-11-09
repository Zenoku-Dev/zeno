# zenо

**zeno** — локальный аналог VirusTotal с открытым кодом, работающий только на открытых движках и открытых базах.

## Что умеет

- **Хэши файла**: MD5, SHA-1, SHA-256
- **Открытые базы (без ключей):**
  - [CIRCL HashLookup](https://www.circl.lu/services/hashlookup/) — поиск SHA-256 среди известных вредоносных файлов
  - [MalwareBazaar (abuse.ch)](https://bazaar.abuse.ch/) — поиск известных сэмплов (опционально с Auth-Key)
- **Открытые AV/YARA-движки:**
  - **ClamAV** — через `clamd` (TCP INSTREAM, порт 3310 по умолчанию) и через `clamscan` CLI
  - **YARA-X** — через CLI `yarax`/`yara-x` (движок разработки VirusTotal, сам открыт: github.com/VirusTotal/yara-x)
  - любые другие движки настраиваются в `zeno.toml` (например `esets_cli`, `sophos-savdi`, custom)

## Установка

```
cargo install --path .
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
malwarebazaar_auth_key = "" # необязательно; бесплатно выдается на abuse.ch

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

## Лицензия

MIT
