# GophKeeper — менеджер паролей

![Go](https://img.shields.io/badge/Go-1.25-blue?logo=go)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-17-orange?logo=postgresql)
![Docker](https://img.shields.io/badge/Docker-Compose-blue?logo=docker)
![JWT](https://img.shields.io/badge/JWT-authentication-yellow?logo=jsonwebtokens)
![AES-GCM](https://img.shields.io/badge/encryption-AES_GCM-purple)

## 📚 Описание

GophKeeper — клиент-серверная система для надёжного и безопасного хранения логинов, паролей, текстовых и бинарных данных, данных банковских карт и произвольной текстовой метаинформации. Поддерживает синхронизацию данных между несколькими авторизованными клиентами одного пользователя.

## 🧩 Основные функции

**Сервер (`gophkeeper-server`):**
- регистрация, аутентификация и авторизация пользователей (JWT + bcrypt);
- хранение приватных данных в PostgreSQL с шифрованием at-rest (AES-GCM);
- CRUD секретов и передача данных по запросу;
- синхронизация изменений (`GET /api/sync?since=`).

**Клиент (`gophkeeper-client`, CLI):**
- аутентификация на удалённом сервере;
- добавление, чтение, обновление и удаление секретов;
- локальный кэш и синхронизация с сервером;
- кроссплатформенный CLI (Windows, Linux, macOS);
- отображение версии и даты сборки бинарного файла.

**Типы хранимых данных:**
- пары логин/пароль;
- произвольный текст;
- произвольные бинарные данные;
- данные банковских карт;
- текстовая метаинформация для любого типа (сайт, личность, банк, OTP и т.д.).

## 🛠 Технологический стек

- **Go** — сервер и CLI-клиент.
- **PostgreSQL** — персистентное хранение пользователей и секретов.
- **net/http ServeMux** — HTTP router (Go 1.22+, method-based routing).
- **golang-migrate** — миграции схемы БД.
- **JWT** — аутентификация API-запросов.
- **bcrypt** — хеширование паролей.
- **AES-GCM** — шифрование payload в БД.
- **RSA + AES** — опциональное шифрование тела запросов (transport).
- **zap** — структурированное логирование.
- **Docker Compose** — локальный PostgreSQL для разработки.

## Принцип работы

### Регистрация и первичная настройка

1. Пользователь запускает CLI-клиент на нужной платформе.
2. Выполняет `register` — сервер создаёт учётную запись и возвращает JWT.
3. Токен сохраняется в локальный файл (`TOKEN_FILE`).

### Работа с секретами

1. Клиент отправляет REST-запросы с заголовком `Authorization: Bearer <token>`.
2. Сервер проверяет JWT, выполняет операцию в PostgreSQL.
3. Payload секрета шифруется перед записью в БД.
4. Клиент отображает данные через команды `list`, `get`.

### Синхронизация между клиентами

1. Клиент вызывает `sync` — запрос `GET /api/sync?since=<RFC3339>`.
2. Сервер возвращает секреты, изменённые после указанного времени (включая soft-delete).
3. Клиент объединяет ответ с локальным кэшем (`CACHE_FILE`, стратегия last-write-wins по `updated_at`).
4. Второй клиент того же пользователя после `login` + `sync` получает актуальные данные.

## Требования

- Go 1.25+
- Docker и Docker Compose
- PostgreSQL 13+ (через Docker или внешний инстанс)

## 🧰 Инструкция по запуску

### 1. Подготовка

1. Склонируйте репозиторий:

```bash
git clone https://github.com/GagarinRu/gophkeeper.git
cd gophkeeper
```

2. Создайте `.env` для Docker PostgreSQL:

```bash
cp .env.example .env
```

Файл `.env` нужен для `docker compose` (учётные данные БД). Go-приложения **не читают `.env` автоматически** — сервер запускается flags (`-d`, `-jwt-secret`, `-data-key`), клиент работает **без `.env`** (дефолты: `http://localhost:8080`, token/cache в `%USERPROFILE%\.gophkeeper\`).

### 2. Запуск PostgreSQL

```bash
docker compose up -d
```

Убедитесь, что контейнер `gophkeeper.db` в статусе `healthy`.

### 3. Запуск сервера

```bash
go run ./cmd/server \
  -a :8080 \
  -d "postgres://gophkeeper:gophkeeper@localhost:5432/gophkeeper?sslmode=disable" \
  -jwt-secret "change-me-in-production" \
  -data-key "change-me-data-key"
```

Параметры сервера:

| Env | Flag | Описание |
|-----|------|----------|
| `ADDRESS` | `-a` | Адрес HTTP-сервера |
| `DATABASE_DSN` | `-d` | DSN PostgreSQL (обязательный) |
| `JWT_SECRET` | `-jwt-secret` | Секрет для JWT |
| `DATA_ENCRYPTION_KEY` | `-data-key` | Ключ шифрования payload (обязательный, отдельно от JWT) |
| `TOKEN_TTL` | — | Время жизни JWT (`24h`, `3600s` и т.д., по умолчанию 24h) |
| `LOG_LEVEL` | `-l` | Уровень логирования |
| `CRYPTO_KEY` | `-crypto-key` | Путь к приватному RSA-ключу (transport) |

Проверка:

```bash
curl http://localhost:8080/ping
```

Ожидаемый ответ: `ok`.

### 4. Работа с клиентом

Клиент не требует `.env`: по умолчанию `http://localhost:8080`, токен и кэш в `%USERPROFILE%\.gophkeeper\` (Linux/macOS: `~/.gophkeeper/`).

```bash
go run ./cmd/client version

go run ./cmd/client register --email user@example.com --password secret

go run ./cmd/client login --email user@example.com --password secret

go run ./cmd/client add login --name github --login user --password pass --url https://github.com

go run ./cmd/client list
go run ./cmd/client sync
```

Флаг `-a` нужен только если сервер не на `localhost:8080`.

**Конфигурация клиента:** JSON (`CONFIG`) → flags → env (env перекрывает flags). Все параметры опциональны — есть дефолты в коде.

| Env | Flag | Дефолт | Описание |
|-----|------|--------|----------|
| `SERVER_URL` / `ADDRESS` | `-a` | `http://localhost:8080` | URL сервера |
| `LOG_LEVEL` | `-l` | `info` | Уровень логирования |
| `TOKEN_FILE` | `-token-file` | `%USERPROFILE%\.gophkeeper\token` | Файл с JWT-токеном |
| `CACHE_FILE` | `-cache-file` | `%USERPROFILE%\.gophkeeper\cache.json` | Локальный кэш sync |
| `CRYPTO_KEY` | `-crypto-key` | — | Публичный RSA-ключ (transport) |

Пример override через env (PowerShell):

```powershell
$env:SERVER_URL = "http://localhost:8080"
go run ./cmd/client list
```

### CLI команды

| Команда | Описание |
|---------|----------|
| `version` | Версия, дата и commit сборки |
| `register --email --password` | Регистрация |
| `login --email --password` | Вход, сохранение token |
| `logout` | Выход: отзыв token на сервере, удаление token и кэша |
| `add login` | Логин/пароль (`--name`, `--login`, `--password`, `--url`, `--metadata`) |
| `add text` | Текст (`--name`, `--content`, `--metadata`) |
| `add binary` | Бинарные данные (`--name`, `--file`, `--metadata`) |
| `add card` | Карта (`--name`, `--number`, `--holder`, `--expiry`, `--cvv`, `--metadata`) |
| `list [--type]` | Список секретов |
| `get <id>` | Получить секрет |
| `update <id>` | Обновить секрет |
| `delete <id>` | Удалить секрет |
| `sync` | Синхронизация с сервером в локальный кэш |

## API

| Метод | Путь | Auth | Описание |
|-------|------|------|----------|
| POST | `/api/register` | нет | Регистрация `{"email","password"}` → `{"token"}` |
| POST | `/api/login` | нет | Вход → `{"token"}` |
| POST | `/api/logout` | Bearer | Отзыв текущего token |
| POST | `/api/secrets` | Bearer | Создать секрет |
| GET | `/api/secrets?type=` | Bearer | Список секретов |
| GET | `/api/secrets/{id}` | Bearer | Один секрет |
| PUT | `/api/secrets/{id}` | Bearer | Обновить секрет |
| DELETE | `/api/secrets/{id}` | Bearer | Удалить секрет (soft delete) |
| GET | `/api/sync?since=` | Bearer | Изменения с момента RFC3339 |
| GET | `/health` | нет | Проверка доступности сервера |
| GET | `/ping` | нет | Проверка доступности БД |

## Пример использования

Регистрация и создание текстового секрета:

```bash
go run ./cmd/client -a http://localhost:8080 \
  register --email demo@example.com --password demo123

go run ./cmd/client -a http://localhost:8080 \
  add text --name "note" --content "private note" --metadata "personal"
```

Пример ответа `get <id>`:

```json
{
  "id": "dc6d62ac-6c1a-4edf-afaf-4023f728d5d7",
  "user_id": "b2f9b9da-a3d9-4263-958a-788b0517433c",
  "type": "text",
  "name": "note",
  "metadata": "personal",
  "payload": {
    "content": "private note"
  },
  "version": 1,
  "created_at": "2026-08-16T10:49:33.501341Z",
  "updated_at": "2026-08-16T10:49:33.501341Z"
}
```

Синхронизация второго клиента (тот же пользователь):

```bash
go run ./cmd/client -a http://localhost:8080 \
  -token-file ~/.gophkeeper/token2 \
  -cache-file ~/.gophkeeper/cache2.json \
  login --email demo@example.com --password demo123

go run ./cmd/client -a http://localhost:8080 \
  -token-file ~/.gophkeeper/token2 \
  -cache-file ~/.gophkeeper/cache2.json \
  sync
```

## Сборка

```bash
make build      # bin/gophkeeper-server, bin/gophkeeper-client
make build-all  # кроссплатформенные бинарии в bin/
```

С версией и метаданными сборки:

```bash
VERSION=0.1.0
DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

go build -ldflags "-X main.buildVersion=$VERSION -X main.buildDate=$DATE -X main.buildCommit=$COMMIT" \
  -o bin/gophkeeper-server ./cmd/server
go build -ldflags "-X main.buildVersion=$VERSION -X main.buildDate=$DATE -X main.buildCommit=$COMMIT" \
  -o bin/gophkeeper-client ./cmd/client
```

## Тестирование

```bash
go test ./...
```

## Структура проекта

```
cmd/server/     — HTTP-сервер
cmd/client/     — CLI-клиент
internal/
  config/       — конфигурация (flags, env, JSON)
  logger/       — логирование
  models/       — доменные модели
  storage/      — PostgreSQL + MemStorage для тестов
  auth/         — JWT, bcrypt, middleware
  handler/      — HTTP handlers
  crypto/       — шифрование at-rest и transport
  client/       — HTTP-клиент API и локальный кэш sync
migrations/     — SQL-миграции
```

## 📢 Автор

[Evgeny Kudryashov](https://github.com/GagarinRu)
