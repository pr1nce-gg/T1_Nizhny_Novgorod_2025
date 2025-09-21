# Телеграм-алерты и фиксы аптайма

## Что сделано
- Исправлен расчет аптайма и логика статуса: домены без валидного FQDN (например, `https://nerabotaet/`) больше **не** считаются доступными. Они помечаются как DOWN с `status_code=0` и `error=invalid_hostname`.
- Уточнена функция `uptime_percent`: аптайм считается только по успешным ответам **2xx–3xx** без ошибок.
- Добавлен минимальный Телеграм-бот (`bot/telegram_bot.py`), который:
  - Реагирует на `/start` и подписывает чат на алерты.
  - Реагирует на `/stop` и отписывает.
  - Получает алерты из Redis-канала `alerts` (их публикует воркер при падениях).

## Быстрый старт
1. Заполните `.env` или `.env.example` скопируйте в `.env`:
   ```env
   TELEGRAM_BOT_TOKEN=123456:ABC...   # токен вашего бота @BotFather
   REDIS_URL=redis://redis:6379/0
   ```
2. Убедитесь, что `docker-compose.yml` поднимает redis и веб/воркер (если используете docker).
3. Запустите воркер:
   ```bash
   python -m worker.runner
   ```
4. Запустите бота:
   ```bash
   python -m bot.telegram_bot
   ```
5. В Телеграме напишите боту `/start` из чата, куда хотите получать алерты.

## Как генерируется алерт
- Воркер при неуспешной проверке публикует JSON в Redis pub/sub канал `alerts`.
- Бот слушает этот канал и рассылает сообщение во все чаты, которые прописаны командой `/start`.

## Примечания
- Проверка URL теперь принудительно добавляет протокол `https://` если его нет.
- Валидация хоста простая: допускает `localhost`, IPv4, либо FQDN с точкой. Всё остальное — `invalid_hostname`.
- Если хотите дополнительно проверять public suffix (например, через `tldextract`), добавьте пакет и усложните `is_valid_hostname`.


## Docker Compose
```bash
docker compose up --build
```
Сервисы:
- web: FastAPI на :8000
- worker: фоновые проверки сайтов + публикация алёртов
- bot: телеграм-бот, слушает Redis pub/sub и шлёт уведомления
- postgres, redis

Требуется `.env` с:
```
POSTGRES_USER=wm_user
POSTGRES_PASSWORD=wm_password
POSTGRES_DB=wm_db
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
REDIS_URL=redis://redis:6379/0
TELEGRAM_BOT_TOKEN=ваш_токен
```
