import os
import time
import traceback
import socket
import hashlib
import json
from datetime import datetime, timedelta
from urllib.parse import urlparse

import httpx
import redis
from sqlalchemy.orm import Session

from app.db import SessionLocal, init_db
from app.models import Site, CheckResult
from app.ssl_utils import scan_ssl_for_site

# ────────────────────────── настройки ──────────────────────────
redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
rds = redis.Redis.from_url(redis_url, decode_responses=True)

ALERT_THROTTLE_SECONDS = int(os.getenv("ALERT_THROTTLE_SECONDS", "1800"))
CHECK_TICK_SECONDS = int(os.getenv("CHECK_TICK_SECONDS", "5"))

# куда продюсер кладёт алёрты; бот забирает из этого списка (LPUSH/RPOP)
ALERTS_STREAM_KEY = os.getenv("ALERTS_STREAM_KEY", "alerts")

# периодичность SSL-скана для https-сайтов (в секундах)
SSL_CHECK_INTERVAL_SECONDS = int(os.getenv("SSL_CHECK_INTERVAL_SECONDS", "1800"))
SSL_TIMEOUT_SECONDS = int(os.getenv("SSL_TIMEOUT_SECONDS", "10"))

# ────────────────────────── утилиты ──────────────────────────
def normalize_url(raw: str) -> str:
    u = (raw or "").strip()
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u

def is_valid_hostname(hostname: str) -> bool:
    if not hostname or " " in hostname:
        return False
    if hostname.endswith("/"):
        hostname = hostname[:-1]
    if hostname == "localhost":
        return True
    try:
        socket.inet_aton(hostname)  # IPv4
        return True
    except OSError:
        pass
    return "." in hostname and not hostname.startswith(".") and not hostname.endswith(".")

def request_site(url: str, timeout: int) -> tuple[int, float, str]:
    start = time.perf_counter()
    try:
        with httpx.Client(follow_redirects=True, timeout=timeout, verify=True) as client:
            resp = client.get(url, headers={"User-Agent": "wm-monitor/1.0"})
            elapsed = time.perf_counter() - start
            return resp.status_code, elapsed, ""
    except Exception as e:
        elapsed = time.perf_counter() - start
        return 0, elapsed, str(e)[:500]

def _hash_msg(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()

def should_alert(site: Site, message: str, delay_sec: int = ALERT_THROTTLE_SECONDS) -> bool:
    """
    Лёгкая дедупликация: за один период отправляем не больше одного одинакового сообщения.
    Если Redis недоступен — возвращаем True (лучше заспамить, чем промолчать).
    """
    key = f"alert_throttle:{site.id}:{_hash_msg(message)}"
    try:
        if rds.exists(key):
            rds.expire(key, delay_sec)
            return False
        rds.set(key, "1", ex=delay_sec)
        return True
    except Exception:
        return True

def publish_alert(site: Site, message: str, severity: str = "high"):
    payload = {
        "type": "check",
        "site_id": site.id,
        "site_name": site.name,
        "url": site.url,
        "message": message,
        "severity": severity,          # бот умеет фильтровать по severity
        "ts": int(time.time()),
    }
    # ВАЖНО: кладём в список, т.к. бот читает RPOP из ALERTS_STREAM_KEY
    rds.lpush(ALERTS_STREAM_KEY, json.dumps(payload, ensure_ascii=False))

def _ssl_due_key(site_id: int) -> str:
    return f"ssl:scan:lock:{site_id}"

def ssl_scan_if_needed(site: Site, db: Session):
    """
    Запускаем SSL-скан не чаще, чем раз в SSL_CHECK_INTERVAL_SECONDS.
    Используем redis-lock с TTL, чтобы не городить счётчики в БД.
    """
    if not (site.url or "").lower().startswith("https://"):
        return
    key = _ssl_due_key(site.id)
    try:
        if rds.set(key, "1", ex=SSL_CHECK_INTERVAL_SECONDS, nx=True):
            # lock установлен — можно сканировать
            scan_ssl_for_site(site, db, timeout=SSL_TIMEOUT_SECONDS)
    except Exception:
        # никогда не мешаем основному воркфлоу
        pass

# ────────────────────────── основная логика ──────────────────────────
def check_site(site: Site, db: Session):
    url = normalize_url(site.url)
    host = urlparse(url).hostname

    # 1) HTTP-проверка
    if not is_valid_hostname(host):
        status_code, elapsed, err = 0, 0.0, "invalid_hostname"
    else:
        status_code, elapsed, err = request_site(url, timeout=site.timeout_seconds)

    ok = (err == "") and (200 <= status_code < 400)

    rec = CheckResult(
        site_id=site.id,
        status_code=status_code,
        response_time=elapsed,
        error=("" if ok else (err or f"Unexpected status: {status_code}")),
    )
    db.add(rec)

    # расписание следующей проверки сайта
    now = datetime.utcnow()
    site.last_check_at = now
    site.next_check_at = now + timedelta(seconds=site.interval_seconds)
    db.commit()

    # 2) SSL-скан по расписанию (только для https)
    ssl_scan_if_needed(site, db)

    # 3) Алёртинг по факту ошибки
    if not ok:
        msg = f"DOWN: {url} ({rec.error})"
        if should_alert(site, msg, ALERT_THROTTLE_SECONDS):
            publish_alert(site, msg, severity="high")

def loop():
    init_db()
    while True:
        db = SessionLocal()
        try:
            now = datetime.utcnow()
            sites = (
                db.query(Site)
                .filter(Site.is_active == True)
                .filter((Site.next_check_at == None) | (Site.next_check_at <= now))
                .all()
            )
            for s in sites:
                check_site(s, db)
        except Exception as e:
            print("Worker error:", e)
            traceback.print_exc()
        finally:
            db.close()
        time.sleep(CHECK_TICK_SECONDS)

if __name__ == "__main__":
    loop()
