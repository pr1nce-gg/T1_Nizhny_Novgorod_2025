# app/utils.py
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Tuple

from sqlalchemy.orm import Session
from sqlalchemy import func
import re
from typing import Optional
from .models import CheckResult
import re
from typing import Optional

def uptime_percent(db: Session, site_id: int, period_hours: int = 24) -> Tuple[float, int, float]:
    """
    Возвращает:
      - аптайм в процентах за последние `period_hours` часов,
      - кол-во неуспешных проверок (fails) в периоде,
      - среднее время ответа (сек) в периоде.

    Успешной считаем проверку с 200 <= status_code < 400 и пустой error.
    Если в периоде записей нет — считаем 100% (ничего не падало) и 0, 0.0.
    """
    since = datetime.utcnow() - timedelta(hours=period_hours)

    # всего записей
    total = (
        db.query(func.count(CheckResult.id))
        .filter(CheckResult.site_id == site_id, CheckResult.checked_at >= since)
        .scalar()
        or 0
    )

    if total == 0:
        return 100.0, 0, 0.0

    # успешные
    ok = (
        db.query(func.count(CheckResult.id))
        .filter(
            CheckResult.site_id == site_id,
            CheckResult.checked_at >= since,
            CheckResult.status_code >= 200,
            CheckResult.status_code < 400,
            (CheckResult.error == "") | (CheckResult.error.is_(None)),
        )
        .scalar()
        or 0
    )

    # среднее время ответа
    avg_resp = (
        db.query(func.avg(CheckResult.response_time))
        .filter(CheckResult.site_id == site_id, CheckResult.checked_at >= since)
        .scalar()
    )
    avg_resp = float(avg_resp or 0.0)

    fails = total - ok
    pct = round(ok * 100.0 / total, 2)
    return pct, fails, avg_resp

def issuer_short(issuer: Optional[str]) -> Optional[str]:
    """
    Возвращает только название компании-издателя из длинной DN-строки.
    Ищем O/organizationName, затем CN/commonName.
    """
    if not issuer:
        return issuer
    m = re.search(r"(?:organizationName|O)\s*=\s*([^,]+)", issuer)
    if not m:
        m = re.search(r"(?:commonName|CN)\s*=\s*([^,]+)", issuer)
    if m:
        return m.group(1).strip()
    return issuer.strip()