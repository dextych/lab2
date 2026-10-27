# Vault — OAuth2/OIDC Provider

Учебный backend-сервис, превращенный в полноценный провайдер авторизации: FastAPI, SQLAlchemy 2.x, Alembic, Ariadne (GraphQL), RS256, PKCE, Redis и Demo-RP.

## Стек

- **FastAPI** — REST API и веб-сервер
- **Ariadne** — GraphQL (schema-first)
- **SQLAlchemy 2.x** — ORM
- **Alembic** — миграции БД
- **PostgreSQL** — основная СУБД
- **Redis** — blacklist токенов (TTL) и временное хранилище
- **JWT (RS256)** — асимметричная подпись токенов (python-jose + cryptography)
- **Argon2id + pepper** — хэширование паролей и `client_secret`
- **zxcvbn** — оценка стойкости паролей

## Возможности OAuth2/OIDC

- **Grant Types:** `password`, `authorization_code` (с PKCE), `refresh_token` (с rotation), `client_credentials`.
- **OIDC:** `id_token`, эндпоинт `/oauth/userinfo`, Discovery-документ (`/.well-known/openid-configuration`).
- **JWKS:** публикация публичного ключа по адресу `/.well-known/jwks.json`.
- **Безопасность:** Blacklist отозванных токенов в Redis, детекция повторного использования Refresh Token (отзыв семейства).
- **GraphQL:** Расширенная админка (просмотр сессий, отзыв сессий, ротация секретов клиентов).
- **Demo-RP:** Отдельное приложение, демонстрирующее вход через Vault как через настоящий OIDC-провайдер.

## Установка и запуск

### 1. Клонировать репозиторий

```bash
git clone https://github.com/ТВО_ИМЯ/vault-oauth2.git
cd vault-oauth2
```

### 2. Создать виртуальное окружение и установить зависимости

```bash
python -m venv .venv
```

Активировать:
- Windows: `.venv\Scripts\Activate.ps1`
- Linux/macOS: `source .venv/bin/activate`

Установить зависимости:
```bash
pip install -r requirements.txt
```

### 3. Поднять Redis

Убедитесь, что Docker запущен:
```bash
docker run -d --name vault-redis -p 6379:6379 redis:7-alpine
```

### 4. Сгенерировать RSA-ключи

Создайте папку `keys/` и сгенерируйте пару ключей:
```bash
python scripts/gen_keys.py
```
*(Приватный ключ `rsa_private.pem` попадает в `keys/`, которая добавлена в `.gitignore`)*.

### 5. Настроить `.env`

Скопируйте пример и заполните своими значениями:
```bash
cp .env.example .env
```

### 6. Создать БД и применить миграции

```bash
psql -U postgres -c "CREATE DATABASE authDb;"
alembic upgrade head
```

### 7. Запустить Vault

```bash
uvicorn app.main:app --reload --port 8080
```

### 8. Запустить Demo-RP (в отдельном терминале)

```bash
uvicorn demo_rp.main:app --port 8001
```

## Точки входа

| URL | Что там |
|---|---|
| `http://127.0.0.1:8080/docs` | Swagger UI (REST) |
| `http://127.0.0.1:8080/graphql` | GraphQL Playground |
| `http://127.0.0.1:8080/admin/` | Админ-панель (Vanilla JS) |
| `http://127.0.0.1:8080/.well-known/openid-configuration` | OIDC Discovery |
| `http://127.0.0.1:8080/.well-known/jwks.json` | JWKS (Публичный ключ) |
| `http://127.0.0.1:8001` | Demo-RP (Стороннее приложение) |

## Переменные окружения (`.env`)

```env
# База данных
DATABASE_URL=postgresql+psycopg2://postgres:postgres@localhost:5432/authDb

# Redis
REDIS_URL=redis://localhost:6379/0

# JWT / OIDC
ISSUER=http://127.0.0.1:8080
RSA_KEY_PATH=./keys/rsa_private.pem
RSA_KEY_ID=vault-key-1
ACCESS_TOKEN_TTL_SEC=900
REFRESH_TOKEN_TTL_DAYS=30
AUTH_CODE_TTL_SEC=60
PKCE_REQUIRED_FOR_PUBLIC=true

# Пароли
ARGON2_PEPPER=change-me-to-a-long-random-pepper-string
PASSWORD_MIN_LENGTH=12

# Приложение
APP_NAME=Vault OAuth2 Provider
DEBUG=false
```

## Пример обмена кода на токен (cURL)

```bash
curl -X POST http://127.0.0.1:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "client_id=vault" \
  -d "code=<authorization_code>" \
  -d "redirect_uri=http://127.0.0.1:8001/callback" \
  -d "code_verifier=<pkce_verifier>"
```

## Тесты

```bash
python -m pytest tests/ -v
```

## Структура проекта

```text
vault-oauth2/
├── app/
│   ├── audit/              # сервис аудита
│   ├── auth/               # REST /auth/* (осталось с лабы 2)
│   ├── core/
│   │   └── security/       # passwords.py, jwt_rsa.py, tokens.py, pkce.py
│   ├── graphql/            # Ariadne: SDL, resolvers, directives, context
│   ├── models/             # SQLAlchemy модели (включая RefreshToken, AuthCode, UserSession)
│   ├── oauth/
│   │   ├── grants/         # password.py, authorization_code.py, refresh_token.py, client_credentials.py
│   │   ├── authorize.py    # /oauth/authorize
│   │   ├── token.py        # /oauth/token
│   │   ├── revoke.py       # /oauth/revoke
│   │   ├── introspect.py   # /oauth/introspect
│   │   ├── userinfo.py     # /oauth/userinfo
│   │   ├── discovery.py    # /.well-known/openid-configuration
│   │   └── jwks.py         # /.well-known/jwks.json
│   ├── static/             # админка (HTML + JS)
│   ├── config.py
│   ├── db.py
│   ├── redis_client.py
│   └── main.py
├── demo_rp/                # Demo-RP (FastAPI + Jinja2)
├── alembic/                # миграции
├── keys/                   # RSA ключи (.gitignore'd)
├── scripts/
│   ├── gen_keys.py         # генерация RSA ключей
│   └── make_admin.py       # выдача прав админа
└── tests/                  # pytest (test_jwks.py, test_pkce.py, test_refresh_rotation.py и др.)
```