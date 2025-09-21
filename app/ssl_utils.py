import socket
import ssl
import datetime
import re
from urllib.parse import urlparse
from typing import Optional, Tuple, Dict, Any

from sqlalchemy.orm import Session
from .models import Site, SSLResult


def _hostname_from_url(url: str) -> str:
    u = urlparse(url if re.match(r"^https?://", url) else "https://" + url)
    return u.hostname or ""


def _fetch_peer_cert(hostname: str, port: int = 443, timeout: int = 10) -> Dict[str, Any]:
    """
    Возвращает декодированный сертификат (dict) с проверкой цепочки.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            return ssock.getpeercert()


def _parse_cert_dates(cert: Dict[str, Any]) -> Tuple[Optional[datetime.datetime], Optional[datetime.datetime]]:
    fmt = "%b %d %H:%M:%S %Y %Z"   # например: 'Jun  1 12:00:00 2025 GMT'

    def _parse(s: Optional[str]) -> Optional[datetime.datetime]:
        if not s:
            return None
        try:
            return datetime.datetime.strptime(s, fmt)
        except Exception:
            return None

    return _parse(cert.get("notBefore")), _parse(cert.get("notAfter"))


def _get_subject_cn(cert: Dict[str, Any]) -> Optional[str]:
    for tup in cert.get("subject", ()):
        for k, v in tup:
            if k == "commonName":
                return v
    return None


def _issuer_company(cert: Dict[str, Any]) -> Optional[str]:
    """
    Достаём только компанию-издателя.
    Берём organizationName (O), если нет — commonName (CN).
    """
    for tup in cert.get("issuer", ()):
        d = dict(tup)
        if "organizationName" in d:
            return str(d["organizationName"])
        if "O" in d:
            return str(d["O"])
        if "commonName" in d:
            return str(d["commonName"])
        if "CN" in d:
            return str(d["CN"])
    return None


def _hostname_matches(cert: Dict[str, Any], hostname: str) -> bool:
    try:
        ssl.match_hostname(cert, hostname)
        return True
    except Exception:
        return False


def scan_ssl_for_site(site: Site, db: Session, timeout: int = 10) -> SSLResult:
    """
    Выполняет TLS-соединение, парсит сертификат и записывает строку в ssl_results.
    """
    res = SSLResult(site_id=site.id, has_ssl=False)
    try:
        hostname = _hostname_from_url(site.url or "")
        if not hostname:
            raise ValueError("Не удалось распарсить hostname")

        cert = _fetch_peer_cert(hostname, timeout=timeout)
        res.has_ssl = True

        # issuer — только название компании
        res.issuer = _issuer_company(cert)

        # subject CN
        res.subject_cn = (_get_subject_cn(cert) or "")[:255] or None

        # validity
        nb, na = _parse_cert_dates(cert)
        res.not_before = nb
        res.not_after = na
        res.days_to_expiry = int((na - datetime.datetime.utcnow()).days) if na else None

        # validations
        res.hostname_ok = _hostname_matches(cert, hostname)
        now = datetime.datetime.utcnow()
        res.time_valid_now = (nb is None or nb <= now) and (na is None or now <= na)
        res.chain_ok = True  # цепочка верифицирована

        res.error = ""
    except Exception as e:
        res.error = str(e)[:500]
        res.chain_ok = False
        res.hostname_ok = False
        res.time_valid_now = False
        res.has_ssl = False
    finally:
        db.add(res)
        db.commit()
        db.refresh(res)
        return res
