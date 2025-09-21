import os
import asyncio
import json
import time
import logging
from typing import Dict, Any, List

import redis
from aiogram import Bot, Dispatcher, types
from aiogram.filters import CommandStart, Command

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("alertbot")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
if not BOT_TOKEN:
    raise RuntimeError("TELEGRAM_BOT_TOKEN is not set")

rds = redis.Redis.from_url(REDIS_URL, decode_responses=True)
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

DEST_CHAT_KEY = "alerts:dest_chat_id"
ALERTS_STREAM_KEY = os.getenv("ALERTS_STREAM_KEY", "alerts")
BUFFER_LIST_KEY = os.getenv("ALERTS_BUFFER_LIST_KEY", "alerts:buffer")
STATE_LAST_FLUSH_AT = os.getenv("ALERTS_STATE_LAST_FLUSH_AT", "alerts:last_flush_at")

def _cfg_int(name: str, default: int) -> int:
    v = rds.get(name) or os.getenv(name)
    try: return int(v) if v is not None else default
    except: return default

def _cfg_bool(name: str, default: bool) -> bool:
    v = rds.get(name) or os.getenv(name)
    return default if v is None else str(v).lower() in {"1","true","yes","y","on"}

def _cfg_str(name: str, default: str) -> str:
    v = rds.get(name) or os.getenv(name)
    return v if v is not None else default

def _period() -> int: return _cfg_int("ALERT_THROTTLE_SECONDS", 1800)
def _only_imp() -> bool: return _cfg_bool("ALERTS_BATCH_ONLY_IMPORTANT", True)
def _max_per() -> int: return _cfg_int("ALERTS_BATCH_MAX_PER_PERIOD", 0)
def _hdr() -> str: return _cfg_str("ALERTS_BATCH_HEADER", "⚠️ Еженятный алёрт-дайджест ({count} шт.)")
def _ftr() -> str: return _cfg_str("ALERTS_BATCH_FOOTER", "— конец партии —")

TG_MAX_LEN = 4096

def _fmt_alert(entry: Dict[str, Any]) -> str:
    kind = entry.get("kind") or entry.get("type") or "alert"
    prio = entry.get("priority") or entry.get("severity") or ""
    title = entry.get("title") or entry.get("message") or entry.get("msg") or json.dumps(entry, ensure_ascii=False)
    src = entry.get("source") or entry.get("site") or ""
    ts  = entry.get("ts") or entry.get("timestamp") or int(time.time())
    dt_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(int(ts)))
    parts = ["•", f"[{kind}]", f"{title}"]
    if src: parts.append(f"(src: {src})")
    if prio: parts.append(f"[{prio}]")
    parts.append(f"@{dt_str}Z")
    return " ".join(parts)

def _should_include(entry: Dict[str, Any]) -> bool:
    if not _only_imp():
        return True
    if entry.get("important") in (True, "true", 1, "1"):
        return True
    sev = (entry.get("severity") or entry.get("priority") or "").lower()
    return sev in {"high", "critical", "urgent", "p1", "p0"}

def _buffer_len() -> int:
    return rds.llen(BUFFER_LIST_KEY)

def _flush_due(now: float) -> bool:
    last = rds.get(STATE_LAST_FLUSH_AT)
    try: last = float(last) if last is not None else 0.0
    except: last = 0.0
    return (now - last) >= _period()

def _chunk_message(header: str, items: List[str], footer: str) -> List[str]:
    chunks, cur = [], header.strip() + "\n"
    for it in items:
        line = f"{it}\n"
        if len(cur) + len(line) > TG_MAX_LEN:
            chunks.append(cur.rstrip()); cur = ""
        cur += line
    cur = cur.rstrip()
    if footer:
        if len(cur) + len("\n" + footer) > TG_MAX_LEN:
            chunks.append(cur); cur = footer
        else:
            cur += "\n" + footer
    if cur: chunks.append(cur)
    return chunks

async def _send(text: str):
    dest = rds.get(DEST_CHAT_KEY)
    if not dest: return
    try: await bot.send_message(int(dest), text)
    except Exception as e: logger.warning("send failed: %s", e)

async def alerts_forwarder():
    rds.setnx(STATE_LAST_FLUSH_AT, "0")
    logger.info("Alerts forwarder is running; period=%s sec", _period())
    while True:
        drained = 0
        while True:
            raw = rds.rpop(ALERTS_STREAM_KEY)
            if raw is None: break
            drained += 1
            try: entry = json.loads(raw)
            except Exception: entry = {"message": str(raw)}
            if _should_include(entry):
                rds.lpush(BUFFER_LIST_KEY, json.dumps(entry, ensure_ascii=False))
        if drained:
            logger.info("Drained %s alerts into buffer (len=%s)", drained, _buffer_len())

        now = time.time()
        if _flush_due(now):
            to_send = min(_buffer_len(), 10**9 if _max_per() <= 0 else _max_per())
            logger.info("Flushing %s buffered alerts", to_send)
            items = []
            for _ in range(to_send):
                raw = rds.rpop(BUFFER_LIST_KEY)
                if raw is None: break
                try: entry = json.loads(raw)
                except Exception: entry = {"message": str(raw)}
                items.append(_fmt_alert(entry))
            if items:
                header = _hdr().format(count=len(items))
                chunks = _chunk_message(header, list(reversed(items)), _ftr().strip())
                sent = 0
                for ch in chunks:
                    await _send(ch); await asyncio.sleep(0.2); sent += 1
                logger.info("Flush complete: sent %s chunk(s)", sent)
            rds.set(STATE_LAST_FLUSH_AT, str(now))
        await asyncio.sleep(0.5)

@dp.message(CommandStart())
async def on_start(m: types.Message):
    rds.set(DEST_CHAT_KEY, str(m.chat.id))
    await m.answer("Готово: буду слать алёрты в этот чат. Настройки — /settings в веб-UI.")
    logger.info("Chat set via /start: %s", m.chat.id)

@dp.message(Command("status"))
async def on_status(m: types.Message):
    await m.answer(f"Назначение: {rds.get(DEST_CHAT_KEY) or '—'}\nПериод: {_period()}s\nФильтр: {_only_imp()}\nБуфер: {_buffer_len()}\nОчередь: {rds.llen(ALERTS_STREAM_KEY)}")
    logger.info("/status from chat %s", m.chat.id)

@dp.message()
async def on_any(m: types.Message):
    prev = rds.get(DEST_CHAT_KEY)
    if prev != str(m.chat.id):
        rds.set(DEST_CHAT_KEY, str(m.chat.id))
        await m.answer("Ок, чат назначения переключён. Параметры — /status, настройки — /settings.")
        logger.info("Destination chat changed: %s -> %s", prev, m.chat.id)

async def main():
    logger.info("Starting Telegram bot polling + alerts forwarder...")
    fwd = asyncio.create_task(alerts_forwarder())
    try:
        await dp.start_polling(bot)
    finally:
        fwd.cancel()
        logger.info("Bot stopped")

if __name__ == "__main__":
    asyncio.run(main())
