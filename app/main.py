import os
from datetime import datetime
import redis
import io
from openpyxl import Workbook
from sqlalchemy import desc, and_
from .models import Site, CheckResult, SSLResult


from datetime import datetime, timedelta
from fastapi import FastAPI, Request, Depends, Form, APIRouter, Body, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from pydantic import BaseModel
from sqlalchemy import desc, func, and_

from .db import SessionLocal, init_db
from .models import Site, CheckResult, SSLResult
from .models import User, Site, CheckResult, SSLResult
from .security import get_password_hash, verify_password, create_access_token, decode_token
from .utils import uptime_percent


# -----------------------------------------------------------------------------
# App & templates
# -----------------------------------------------------------------------------
app = FastAPI()

# ========== Alerts UI settings ==========
ALERTS_UI_SETTINGS_KEYS = {
    "ALERT_THROTTLE_SECONDS": ("1800", "Период отправки (сек)"),
    "ALERTS_BATCH_ONLY_IMPORTANT": ("true", "Только важные"),
    "ALERTS_BATCH_MAX_PER_PERIOD": ("0", "Лимит алёртов за период (0 = без лимита)"),
    "ALERTS_BATCH_HEADER": ("⚠️ Еженятный алёрт-дайджест ({count} шт.)", "Заголовок"),
    "ALERTS_BATCH_FOOTER": ("— конец партии —", "Футер"),
}
ALERTS_DEST_CHAT_KEY = "alerts:dest_chat_id"

templates = Jinja2Templates(directory="app/templates")
from .utils import issuer_short
templates.env.filters["issuer_short"] = issuer_short

# Redis (необязательно для веба, но пусть будет готов)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
try:
    rds = redis.Redis.from_url(REDIS_URL, decode_responses=True)
except Exception:
    rds = None  # веб-часть работает и без redis


# -----------------------------------------------------------------------------
# DB dependency
# -----------------------------------------------------------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# -----------------------------------------------------------------------------
# Auth helpers
# -----------------------------------------------------------------------------
COOKIE_NAME = "access_token"


def _get_token_from_request(request: Request) -> str | None:
    tok = request.cookies.get(COOKIE_NAME)
    if tok:
        return tok
    # fallback на header, если кто-то дергает API
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return None


@app.middleware("http")
async def add_user_to_request(request: Request, call_next):
    request.state.user = None
    token = _get_token_from_request(request)
    if token:
        try:
            payload = decode_token(token)
            email = payload.get("sub")
            if email:
                with SessionLocal() as db:
                    user = db.query(User).filter(User.email == email).first()
                    if user:
                        request.state.user = user
        except Exception:
            # не валидный токен — просто игнорируем
            pass
    response = await call_next(request)
    return response


def current_user(request: Request, db: Session = Depends(get_db)) -> User | None:
    return request.state.user


# -----------------------------------------------------------------------------
# Startup
# -----------------------------------------------------------------------------
@app.on_event("startup")
def startup():
    # создаем таблицы (в т.ч. ssl_results) если их нет
    init_db()


# -----------------------------------------------------------------------------
# Root
# -----------------------------------------------------------------------------
@app.get("/")
def root(request: Request):
    if request.state.user:
        return RedirectResponse("/sites", status_code=302)
    return RedirectResponse("/login", status_code=302)


# -----------------------------------------------------------------------------
# Auth: Register / Login / Logout
# -----------------------------------------------------------------------------
@app.get("/register", response_class=HTMLResponse)
def register_get(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
def register_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    email = (email or "").strip().lower()
    if not email or not password:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Укажите email и пароль"},
            status_code=400,
        )
    if db.query(User).filter(User.email == email).first():
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Пользователь уже существует"},
            status_code=400,
        )
    user = User(email=email, password_hash=get_password_hash(password))
    db.add(user)
    db.commit()
    token = create_access_token(subject=email)
    resp = RedirectResponse(url="/sites", status_code=302)
    resp.set_cookie(COOKIE_NAME, token, httponly=True, samesite="lax")
    return resp


@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
def login_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    email = (email or "").strip().lower()
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Неверный email или пароль"}, status_code=400
        )

    token = create_access_token(subject=email)
    resp = RedirectResponse(url="/sites", status_code=302)
    resp.set_cookie(COOKIE_NAME, token, httponly=True, samesite="lax")
    return resp


@app.get("/logout")
def logout():
    resp = RedirectResponse(url="/login", status_code=302)
    resp.delete_cookie(COOKIE_NAME)
    return resp


# -----------------------------------------------------------------------------
# Sites: list / create / edit / delete / stats
# -----------------------------------------------------------------------------
@app.get("/sites", response_class=HTMLResponse)
def sites_list(request: Request, db: Session = Depends(get_db), user=Depends(current_user)):
    if not user:
        return RedirectResponse("/login", status_code=302)

    sites = (
        db.query(Site)
        .filter(Site.user_id == user.id)
        .order_by(Site.name.asc())
        .all()
    )

    # ---- последний SSL-результат по каждому сайту (как было) ----
    subq_ssl = (
        db.query(SSLResult.site_id, func.max(SSLResult.checked_at).label("mx"))
        .group_by(SSLResult.site_id)
        .subquery()
    )
    ssl_map = {
        site_id: rec
        for site_id, rec in db.query(SSLResult.site_id, SSLResult)
        .join(subq_ssl, (SSLResult.site_id == subq_ssl.c.site_id) & (SSLResult.checked_at == subq_ssl.c.mx))
    }

    # ---- НОВОЕ: статус по последней HTTP-проверке для каждой записи ----
    status_ok_map: dict[int, bool] = {}
    site_ids = [s.id for s in sites]
    if site_ids:
        subq_http = (
            db.query(CheckResult.site_id, func.max(CheckResult.checked_at).label("mx"))
            .filter(CheckResult.site_id.in_(site_ids))
            .group_by(CheckResult.site_id)
            .subquery()
        )
        last_checks = (
            db.query(CheckResult)
            .join(subq_http, and_(CheckResult.site_id == subq_http.c.site_id,
                                  CheckResult.checked_at == subq_http.c.mx))
            .all()
        )
        for r in last_checks:
            ok = (r.error == "") and (200 <= (r.status_code or 0) < 400)
            status_ok_map[r.site_id] = ok

    return templates.TemplateResponse(
        "sites.html",
        {
            "request": request,
            "user": user,
            "sites": sites,
            "ssl_map": ssl_map,
            "status_ok_map": status_ok_map,
        },
    )


@app.get("/sites/new", response_class=HTMLResponse)
def site_new_get(request: Request, user=Depends(current_user)):
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("site_form.html", {"request": request, "user": user, "mode": "new"})


@app.post("/sites/new")
def site_new_post(
    request: Request,
    name: str = Form(...),
    url: str = Form(...),
    description: str = Form(""),
    interval_seconds: int = Form(...),
    timeout_seconds: int = Form(...),
    expected_status: int = Form(...),
    db: Session = Depends(get_db),
    user=Depends(current_user),
):
    if not user:
        return RedirectResponse("/login", status_code=302)
    site = Site(
        user_id=user.id,
        name=name.strip(),
        url=url.strip(),
        description=(description or "").strip(),
        interval_seconds=int(interval_seconds),
        timeout_seconds=int(timeout_seconds),
        expected_status=int(expected_status),
        is_active=True,
    )
    db.add(site)
    db.commit()
    return RedirectResponse("/sites", status_code=302)


@app.get("/sites/{site_id}/edit", response_class=HTMLResponse)
def site_edit_get(site_id: int, request: Request, db: Session = Depends(get_db), user=Depends(current_user)):
    if not user:
        return RedirectResponse("/login", status_code=302)
    site = db.query(Site).filter(Site.id == site_id, Site.user_id == user.id).first()
    if not site:
        return RedirectResponse("/sites", status_code=302)
    return templates.TemplateResponse("site_form.html", {"request": request, "user": user, "mode": "edit", "site": site})


@app.post("/sites/{site_id}/edit")
def site_edit_post(
    site_id: int,
    request: Request,
    name: str = Form(...),
    url: str = Form(...),
    description: str = Form(""),
    interval_seconds: int = Form(...),
    timeout_seconds: int = Form(...),
    expected_status: int = Form(...),
    is_active: int = Form(1),
    db: Session = Depends(get_db),
    user=Depends(current_user),
):
    if not user:
        return RedirectResponse("/login", status_code=302)
    site = db.query(Site).filter(Site.id == site_id, Site.user_id == user.id).first()
    if not site:
        return RedirectResponse("/sites", status_code=302)

    site.name = name.strip()
    site.url = url.strip()
    site.description = (description or "").strip()
    site.interval_seconds = int(interval_seconds)
    site.timeout_seconds = int(timeout_seconds)
    site.expected_status = int(expected_status)
    site.is_active = bool(int(is_active))
    db.commit()
    return RedirectResponse("/sites", status_code=302)


@app.get("/sites/{site_id}/delete")
def site_delete(site_id: int, db: Session = Depends(get_db), user=Depends(current_user)):
    if not user:
        return RedirectResponse("/login", status_code=302)
    site = db.query(Site).filter(Site.id == site_id, Site.user_id == user.id).first()
    if site:
        db.delete(site)
        db.commit()
    return RedirectResponse(url="/sites", status_code=302)


@app.get("/sites/{site_id}/stats", response_class=HTMLResponse)
def site_stats(site_id: int, request: Request, db: Session = Depends(get_db), user=Depends(current_user)):
    if not user:
        return RedirectResponse("/login", status_code=302)

    site = db.query(Site).filter(Site.id == site_id, Site.user_id == user.id).first()
    if not site:
        return RedirectResponse("/sites", status_code=302)

    # ---- чтение диапазона (GET ?from=...&to=...) ----
    q_from = request.query_params.get("from")
    q_to   = request.query_params.get("to")

    def parse_dt_local(s: str | None):
        if not s:
            return None
        # ожидаем формат input[type=datetime-local]: 'YYYY-MM-DDTHH:MM'
        try:
            return datetime.fromisoformat(s)
        except Exception:
            return None

    dt_to = parse_dt_local(q_to) or datetime.utcnow()
    dt_from = parse_dt_local(q_from) or (dt_to - timedelta(days=1))  # по умолчанию последние 24 часа

    # строки для заполнения инпутов (datetime-local требует 'YYYY-MM-DDTHH:MM')
    def to_input(dt: datetime): return dt.strftime("%Y-%m-%dT%H:%M")

    from_str = to_input(dt_from)
    to_str   = to_input(dt_to)

    # ---- данные HTTP по диапазону ----
    checks_desc = (
        db.query(CheckResult)
          .filter(
              CheckResult.site_id == site.id,
              CheckResult.checked_at >= dt_from,
              CheckResult.checked_at <= dt_to,
          )
          .order_by(CheckResult.checked_at.desc())
          .limit(2000)
          .all()
    )
    checks_for_chart = list(reversed(checks_desc))

    # ---- SSL история (таблица) — также отфильтруем по диапазону ----
    ssl_history = (
        db.query(SSLResult)
          .filter(
              SSLResult.site_id == site.id,
              SSLResult.checked_at >= dt_from,
              SSLResult.checked_at <= dt_to,
          )
          .order_by(SSLResult.checked_at.asc())
          .all()
    )
    ssl_last = ssl_history[-1] if ssl_history else None

    # ---- массивы для графиков ----
    http_labels = [c.checked_at.strftime("%Y-%m-%d %H:%M:%S") for c in checks_for_chart]
    http_resp   = [float(c.response_time or 0.0) for c in checks_for_chart]
    http_status = [int(c.status_code or 0) for c in checks_for_chart]

    # аптайм за выбранный период (если нужно – можно оставить 24h)
    try:
        hours = max(1, int((dt_to - dt_from).total_seconds() // 3600))
        up_24h, fails_24h, avg_resp_24h = uptime_percent(db, site.id, period_hours=hours)
    except Exception:
        up_24h, fails_24h, avg_resp_24h = (100.0, 0, 0.0)

    return templates.TemplateResponse(
        "site_stats.html",
        {
            "request": request,
            "user": user,
            "site": site,

            # таблицы
            "checks": checks_desc,
            "ssl_history": ssl_history,
            "ssl_last": ssl_last,

            # графики
            "http_labels": http_labels,
            "http_resp": http_resp,
            "http_status": http_status,

            # диапазон для формы
            "from_str": from_str,
            "to_str": to_str,
        },
    )
@app.get("/sites/{site_id}/stats/export")
def site_stats_export(
    site_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(current_user),
):
    if not user:
        return RedirectResponse("/login", status_code=302)

    site = db.query(Site).filter(Site.id == site_id, Site.user_id == user.id).first()
    if not site:
        return RedirectResponse("/sites", status_code=302)

    # --- читаем диапазон из query (?from=...&to=...) как на странице статистики ---
    q_from = request.query_params.get("from")
    q_to   = request.query_params.get("to")

    def parse_dt_local(s: str | None):
        if not s:
            return None
        try:
            return datetime.fromisoformat(s)  # 'YYYY-MM-DDTHH:MM'
        except Exception:
            return None

    dt_to   = parse_dt_local(q_to) or datetime.utcnow()
    dt_from = parse_dt_local(q_from) or (dt_to - timedelta(days=1))

    # --- собираем данные как в site_stats ---
    checks = (
        db.query(CheckResult)
          .filter(
              CheckResult.site_id == site.id,
              CheckResult.checked_at >= dt_from,
              CheckResult.checked_at <= dt_to,
          )
          .order_by(CheckResult.checked_at.asc())
          .all()
    )

    ssl_history = (
        db.query(SSLResult)
          .filter(
              SSLResult.site_id == site.id,
              SSLResult.checked_at >= dt_from,
              SSLResult.checked_at <= dt_to,
          )
          .order_by(SSLResult.checked_at.asc())
          .all()
    )

    # --- формируем Excel ---
    wb = Workbook()

    # Лист 1: HTTP checks
    ws1 = wb.active
    ws1.title = "HTTP checks"
    ws1.append(["#",
                "Checked At (UTC)",
                "Status Code",
                "Response Time (s)",
                "Error"])
    for i, c in enumerate(checks, start=1):
        ws1.append([
            i,
            c.checked_at.strftime("%Y-%m-%d %H:%M:%S"),
            int(c.status_code or 0),
            float(c.response_time or 0.0),
            c.error or "",
        ])

    # Лист 2: SSL
    ws2 = wb.create_sheet("SSL")
    ws2.append(["#",
                "Checked At (UTC)",
                "Has SSL",
                "Issuer",
                "Subject CN",
                "Not Before (UTC)",
                "Not After (UTC)",
                "Days to Expiry",
                "Hostname OK",
                "Time Valid Now",
                "Chain OK",
                "Error"])
    for i, sres in enumerate(ssl_history, start=1):
        ws2.append([
            i,
            sres.checked_at.strftime("%Y-%m-%d %H:%M:%S"),
            bool(sres.has_ssl),
            sres.issuer or "",
            sres.subject_cn or "",
            sres.not_before.strftime("%Y-%m-%d %H:%M:%S") if sres.not_before else "",
            sres.not_after.strftime("%Y-%m-%d %H:%M:%S")  if sres.not_after  else "",
            sres.days_to_expiry if sres.days_to_expiry is not None else "",
            "" if sres.hostname_ok is None else bool(sres.hostname_ok),
            "" if sres.time_valid_now is None else bool(sres.time_valid_now),
            "" if sres.chain_ok is None else bool(sres.chain_ok),
            sres.error or "",
        ])

    # (необязательно) автоширина — простая эвристика
    for ws in (ws1, ws2):
        for col_cells in ws.columns:
            try:
                max_len = max(len(str(c.value)) if c.value is not None else 0 for c in col_cells)
                ws.column_dimensions[col_cells[0].column_letter].width = min(max(10, max_len + 2), 60)
            except Exception:
                pass

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)

    # имя файла
    fname = f"site_{site.id}_stats_{dt_from.strftime('%Y%m%d_%H%M')}_{dt_to.strftime('%Y%m%d_%H%M')}.xlsx"

    return Response(
        content=buf.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'}
    )


# -----------------------------------------------------------------------------
# Debug
# -----------------------------------------------------------------------------
@app.get("/__routes")
def _routes():
    return sorted([r.path for r in app.routes])


from fastapi import APIRouter
from fastapi import Body
from fastapi import status
from pydantic import BaseModel
from sqlalchemy import desc

@app.get("/settings", response_class=HTMLResponse)
def settings_get(request: Request):
    vals = {}
    for k, (default, label) in ALERTS_UI_SETTINGS_KEYS.items():
        vals[k] = rds.get(k) or os.getenv(k, default)
    dest = rds.get(ALERTS_DEST_CHAT_KEY) or ""
    return templates.TemplateResponse("settings.html", {"request": request, "vals": vals, "labels": {k:v[1] for k,v in ALERTS_UI_SETTINGS_KEYS.items()}, "dest": dest})

@app.post("/settings")
def settings_post(request: Request,
                  ALERT_THROTTLE_SECONDS: str = Form(...),
                  ALERTS_BATCH_ONLY_IMPORTANT: str = Form("true"),
                  ALERTS_BATCH_MAX_PER_PERIOD: str = Form("0"),
                  ALERTS_BATCH_HEADER: str = Form(""),
                  ALERTS_BATCH_FOOTER: str = Form(""),
                  db: Session = Depends(get_db)):
    rds.set("ALERT_THROTTLE_SECONDS", (ALERT_THROTTLE_SECONDS or "").strip())
    rds.set("ALERTS_BATCH_ONLY_IMPORTANT", (ALERTS_BATCH_ONLY_IMPORTANT or "").strip())
    rds.set("ALERTS_BATCH_MAX_PER_PERIOD", (ALERTS_BATCH_MAX_PER_PERIOD or "").strip())
    rds.set("ALERTS_BATCH_HEADER", (ALERTS_BATCH_HEADER or "").strip())
    rds.set("ALERTS_BATCH_FOOTER", (ALERTS_BATCH_FOOTER or "").strip())
    return RedirectResponse("/settings", status_code=302)

# ---------------- REST API ----------------
api = APIRouter(prefix="/api", tags=["api"])

class SiteIn(BaseModel):
    name: str
    url: str
    interval_seconds: int = 60
    timeout_seconds: int = 10

class SiteOut(BaseModel):
    id: int
    name: str
    url: str
    interval_seconds: int
    timeout_seconds: int
    class Config:
        orm_mode = True

class CheckOut(BaseModel):
    checked_at: datetime
    status_code: int
    response_time: float
    error: str

class SSLOut(BaseModel):
    checked_at: datetime
    issuer: str | None
    subject_cn: str | None
    not_before: datetime | None
    not_after: datetime | None
    days_to_expiry: int | None
    hostname_ok: bool | None
    time_valid_now: bool | None
    chain_ok: bool | None
    error: str

# ==== Сайты ====
@api.get("/sites", response_model=list[SiteOut])
def api_sites(db: Session = Depends(get_db)):
    return db.query(Site).order_by(Site.id.asc()).all()

@api.post("/sites", response_model=SiteOut, status_code=status.HTTP_201_CREATED)
def api_sites_create(payload: SiteIn, db: Session = Depends(get_db)):
    s = Site(
        name=payload.name.strip(),
        url=payload.url.strip(),
        interval_seconds=payload.interval_seconds,
        timeout_seconds=payload.timeout_seconds,
    )
    db.add(s); db.commit(); db.refresh(s)
    return s

@api.get("/sites/{site_id}", response_model=SiteOut)
def api_site_get(site_id: int, db: Session = Depends(get_db)):
    s = db.query(Site).get(site_id)
    if not s:
        return Response(status_code=404)
    return s

@api.put("/sites/{site_id}", response_model=SiteOut)
def api_site_update(site_id: int, payload: SiteIn, db: Session = Depends(get_db)):
    s = db.query(Site).get(site_id)
    if not s:
        return Response(status_code=404)
    s.name = payload.name.strip()
    s.url = payload.url.strip()
    s.interval_seconds = payload.interval_seconds
    s.timeout_seconds = payload.timeout_seconds
    db.commit(); db.refresh(s)
    return s

@api.delete("/sites/{site_id}", status_code=status.HTTP_204_NO_CONTENT)
def api_site_delete(site_id: int, db: Session = Depends(get_db)):
    s = db.query(Site).get(site_id)
    if not s:
        return Response(status_code=404)
    db.delete(s); db.commit()
    return Response(status_code=204)

# ==== Результаты проверок ====
@api.get("/sites/{site_id}/checks", response_model=list[CheckOut])
def api_site_checks(site_id: int, limit: int = 100, db: Session = Depends(get_db)):
    qs = (
        db.query(CheckResult)
        .filter(CheckResult.site_id == site_id)
        .order_by(desc(CheckResult.checked_at))
        .limit(max(1, min(1000, limit)))
        .all()
    )
    return qs

# ==== SSL ====
@api.get("/sites/{site_id}/ssl", response_model=SSLOut)
def api_site_ssl(site_id: int, db: Session = Depends(get_db)):
    row = (
        db.query(SSLResult)
        .filter(SSLResult.site_id == site_id)
        .order_by(desc(SSLResult.checked_at))
        .first()
    )
    if not row:
        return Response(status_code=404)
    return row

# ==== Настройки алёртов ====
@api.get("/settings/alerts")
def api_get_alert_settings():
    keys = [
        "ALERT_THROTTLE_SECONDS",
        "ALERTS_BATCH_ONLY_IMPORTANT",
        "ALERTS_BATCH_MAX_PER_PERIOD",
        "ALERTS_BATCH_HEADER",
        "ALERTS_BATCH_FOOTER",
    ]
    return {k: (rds.get(k) or os.getenv(k)) for k in keys}

@api.put("/settings/alerts")
def api_put_alert_settings(payload: dict = Body(...)):
    for k, v in payload.items():
        if k.startswith("ALERT"):
            rds.set(k, str(v))
    return {"ok": True}

# ==== Алёрты ====
@api.get("/alerts")
def api_get_alerts(limit: int = 50):
    items = []
    for raw in rds.lrange(os.getenv("ALERTS_BUFFER_LIST_KEY","alerts:buffer"), 0, limit-1):
        try:
            items.append(json.loads(raw))
        except Exception:
            items.append({"raw": raw})
    return items

@api.post("/alerts/test", status_code=202)
def api_post_alert_test(payload: dict = Body(...)):
    rds.lpush(os.getenv("ALERTS_STREAM_KEY","alerts"), json.dumps(payload, ensure_ascii=False))
    return {"queued": True}

# подключаем роутер
app.include_router(api)