# Динамический анализ (`zeno run`) в изоляции

`zeno run` — это **реальное выполнение** файла (или его отправка на выполнение) в изолированной среде. Это не магический «проверяльщик», это управляемый запуск с наблюдением. Всегда понимайте, где именно выполнится код:

| target   | Что происходит                                   | Изоляция              | ОС/формат          | Нужно заранее |
|----------|--------------------------------------------------|-----------------------|--------------------|---------------|
| `alpine` | ELF запускается в контейнере alpine (Docker)     | container, `--network=none`, caps dropped | Linux ELF | Docker демон, образ (по умолчанию `alpine:latest`) |
| `windows`| Файл отправляется в локальный **Cuckoo3** (Windows-гости на KVM), zeno ждёт отчёт | полноценная VM | Windows PE/scripts | установленный Cuckoo3 + API-токен + готовые Windows-VM |
| `macos`  | **Только проверка готовности** окружения через OSX-KVM | полноценная VM (если вы её создали) | macOS Mach-O | Linux+KVM, QEMU, клон OSX-KVM, созданный диск macOS |

> ⚠️ Никогда не запускайте образец на обычной рабочей машине. Контейнер — это не то же самое, что VM: у ядра Linux общий, теоретически возможны побеги через уязвимости. Для неизвестных прод-образцов используйте выделенную машину с KVM (Cuckoo3 или отдельную VM).

## Общие правила

- `zeno run <file> --target <target> --yes` — флаг `--yes` обязателен: без него zeno только печатает предупреждение и выходит с кодом 2.
- `--timeout N` — секунд (по умолчанию 60).
- `--json` — машиночитаемый отчёт (поля `executed`, `exit_code`, `stdout`, `stderr`, `created_files`, `strace_tail`, `notes`).
- Код выхода: 0 — успешно, 1 — образец завершился с ненулевым кодом (alpine), 2 — ошибка/неизвестный target.

## target = alpine (Linux ELF через Docker)

Запуск максимально изолированного контейнера:

- `--network=none` — нет сети;
- `--cap-drop=ALL`, `--security-opt=no-new-privileges` — нет capabilities;
- `--pids-limit=64`, `--memory=256m` — потолок по ресурсам;
- файл монтируется/копируется в рабочий каталог, коммиты в образ не сохраняются (`--rm`).

zno собирает: код выхода, stdout/stderr (хвосты), список созданных файлов (с SHA-256), `strace` tail (если strace есть в образе).

```toml
# zeno.toml / ~/.zeno/config.toml
zeno_alpine_image = "alpine:latest"   # по умолчанию alpine:latest
```

Если хотите `strace` (а он не входит в базовый образ), соберите свой:

```dockerfile
FROM alpine:latest
RUN apk add --no-cache strace
```

```bash
docker build -t zeno-alpine-strace .
```
```toml
zeno_alpine_image = "zeno-alpine-strace"
```

Пример:

```bash
zeno run sample.elf --target alpine --timeout 30 --yes
```

Ограничения: только Linux/ELF (и shebang-скрипты); PE-файлы не запустятся; `.exe` → используйте `--target windows`.

## target = windows (Cuckoo3)

[Cuckoo3](https://github.com/cert-ee/cuckoo3) (cert-ee, EUPL-1.2) — открытая система динамического анализа: прогоняет исполняемый файл в изолированной Windows-VM, снимает поведение (процессы, файлы, реестр, сеть) и собирает отчёт.

Установка (Ubuntu-хост, Python 3.10+): следуйте `INSTALL/QUICKSTART.md` в репозитории Cuckoo3. Итог: веб-интерфейс на `:8080`/иногда `:8090`, KVM-машины win10x64.

Настройка zeno:

```toml
cuckoo_url = "http://127.0.0.1:8090"   # адрес веб-API Cuckoo3
cuckoo_token = "cb60aa0d689d7f..."     # cuckoo api token --list
```

Токен появится после `cuckoo api token --list` на машине с Cuckoo. Пример:

```bash
zeno run sample.exe --target windows --timeout 120 --yes
```

zeno: отправляет файл (`POST /submit/file`, `Authorization: token <key>`), ждёт до таймаута+10 минут, печатает `analysis_id`, финальный `state` и `score`, даёт ссылку на полный веб-отчёт (`<cuckoo_url>/analysis/<id>`). Полные детали (что делал образец) — в веб-отчёте и в разделе API-docs Cuckoo3.

## target = macos (OSX-KVM)

Динамический мониторинг в macOS невозможен без агента внутри гостевой ОС; Cuckoo3 поддерживает только Windows-гостей. Что zeno может:

- проверить готовность: `/dev/kvm`, `qemu-system-x86_64`, клон [kholia/OSX-KVM](https://github.com/kholia/OSX-KVM), диск `mac_hdd_ng.img`, `boot-macOS-headless.sh`;
- напечатать, чего не хватает и как достроить.

```toml
osx_kvm_path = "/home/me/OSX-KVM"   # по умолчанию ~/OSX-KVM
```

```bash
zeno run sample.macho --target macos --yes
```

Дальше — вручную: загрузить VM headless-скриптом, зайти по VNC (`:5901`), прогнать файл, следить через Activity Monitor / `fs_usage`. Лицензия macOS в неродном железе — на вашей совести.

## Почему не «одна кнопка» вместо всего этого

Полноценная кроссплатформенная песочница = оркестрация VM + агенты + захват I/O + сигнатуры поведения (это и есть Cuckoo/CAPE/DRAKVUF). zeno не пытается переизобрести их, а интегрируется: хэши/базы/статика — внутри zeno, динамика — через открытые движки и системы.
