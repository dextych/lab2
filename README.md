# GraphQL Auth Service

Учебный backend-сервис с базовой аутентификацией: FastAPI, SQLAlchemy 2.x, Alembic, Ariadne (GraphQL), JWT (HS256), Argon2id, аудит и минимальная админ-панель.

## Стек

- **FastAPI** — REST API
- **Ariadne** — GraphQL (schema-first)
- **SQLAlchemy 2.x** — ORM
- **Alembic** — миграции БД
- **PostgreSQL** — СУБД
- **Argon2id + pepper** — хэширование паролей
- **zxcvbn** — оценка стойкости паролей
- **JWT (HS256)** — токены аутентификации

## Возможности

- Регистрация и логин через REST (`/auth/*`)
- GraphQL API для админки (`/graphql`)
- Аудит действий (`audit_events`)
- Мини-админка на vanilla JS (`/admin`)
- Директивы `@isAuthenticated`, `@isAdmin` в GraphQL

## Установка

### 1. Клонировать репозиторий

```bash
git clone https://github.com/ТВО_ИМЯ/graphql-auth-service.git
cd graphql-auth-service
```

### 2. Создать виртуальное окружение

```bash
python -m venv .venv
```

Активировать:

- Windows: `.venv\Scripts\Activate.ps1`
- Linux/macOS: `source .venv/bin/activate`

### 3. Установить зависимости

```bash
pip install -r requirements.txt
```

### 4. Настроить `.env`

Скопировать пример и заполнить своими значениями:

```bash
cp .env.example .env
```

Содержимое `.env` — см. раздел «Переменные окружения».

### 5. Создать БД в PostgreSQL

```bash
psql -U postgres -c "CREATE DATABASE authDb;"
```

### 6. Применить миграции

```bash
alembic upgrade head
```

### 7. Запустить сервер

```bash
uvicorn app.main:app --reload --port 8080
```

## Точки входа

| URL | Что там |
|---|---|
| `http://127.0.0.1:8080/docs` | Swagger UI (REST) |
| `http://127.0.0.1:8080/redoc` | ReDoc (REST) |
| `http://127.0.0.1:8080/graphql` | GraphQL Playground |
| `http://127.0.0.1:8080/admin/` | Мини-админка |
| `http://127.0.0.1:8080/health` | Health-check |

## Переменные окружения

Пример `.env` (замени на свои значения):

```env
DATABASE_URL=postgresql+psycopg2://postgres:postgres@localhost:5432/authDb

JWT_SECRET_KEY=change-me-to-a-long-random-string-at-least-32-chars
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30

ARGON2_PEPPER=change-me-to-a-long-random-pepper-string

PASSWORD_MIN_LENGTH=12

APP_NAME=GraphQL Auth Service
DEBUG=false
```

## Зависимости

Полный список — в `requirements.txt`:

```
fastapi==0.115.0
uvicorn[standard]==0.30.6
ariadne==0.23.0
graphql-core==3.2.3
sqlalchemy==2.0.35
alembic==1.13.3
psycopg2-binary==2.9.9
pydantic==2.9.2
pydantic-settings==2.5.2
argon2-cffi==23.1.0
zxcvbn==4.4.28
python-jose[cryptography]==3.3.0
python-multipart==0.0.12
email-validator==2.2.0
pytest==8.3.3
httpx==0.27.2
```

## Тесты

```bash
python -m pytest tests/ -v
```

## Структура проекта

```
app/
├── audit/          # сервис аудита
├── auth/           # REST /auth/*
├── core/           # passwords, jwt, deps, audit
├── graphql/        # Ariadne: SDL, resolvers, directives, context
├── models/         # SQLAlchemy модели
├── static/         # админка (HTML + JS)
├── config.py
├── db.py
└── main.py
alembic/            # миграции
tests/              # pytest
```