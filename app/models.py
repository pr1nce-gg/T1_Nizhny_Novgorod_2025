from datetime import datetime, timedelta
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import Integer, String, DateTime, ForeignKey, Boolean, Float, Text


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Site(Base):
    __tablename__ = "sites"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    url: Mapped[str] = mapped_column(String(1024))
    description: Mapped[str | None] = mapped_column(String(1024), default="")
    interval_seconds: Mapped[int] = mapped_column(Integer, default=60)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=30)
    expected_status: Mapped[int] = mapped_column(Integer, default=200)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_check_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class CheckResult(Base):
    __tablename__ = "check_results"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    status_code: Mapped[int] = mapped_column(Integer)
    response_time: Mapped[float] = mapped_column(Float)  # seconds
    error: Mapped[str] = mapped_column(Text, default="")


# ─────────────────────────────  NEW: SSL results  ─────────────────────────────

class SSLResult(Base):
    __tablename__ = "ssl_results"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    has_ssl: Mapped[bool] = mapped_column(Boolean, default=False)
    issuer: Mapped[str | None] = mapped_column(String(255), nullable=True)
    subject_cn: Mapped[str | None] = mapped_column(String(255), nullable=True)
    not_before: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    not_after: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    days_to_expiry: Mapped[int | None] = mapped_column(Integer, nullable=True)

    hostname_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    time_valid_now: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    chain_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    error: Mapped[str] = mapped_column(Text, default="")
