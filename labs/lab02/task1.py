"""Завдання 1: модель користувача, сеансу та журналу аудиту (ООП)."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import ClassVar

PBKDF2_ITERATIONS = 200_000
SALT_SIZE = 16
SESSION_TIMEOUT_SEC = 900

ACTION_LOGIN_SUCCESS = "login_success"
ACTION_LOGIN_FAILURE = "login_failure"
ACTION_LOGOUT = "logout"

# Локальна частина: літера + 2..63 символи (разом 3-64), далі @ і домен з крапкою.
EMAIL_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{2,63}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")


def _utcnow() -> datetime:
    return datetime.now(UTC)


class User:
    """Користувач з безпечним зберіганням пароля (PBKDF2-HMAC-SHA256 + сіль)."""

    def __init__(
        self,
        username: str,
        email: str,
        role: str,
        password: str,
        active: bool = True,
    ) -> None:
        if not isinstance(username, str) or not username.strip():
            raise ValueError("Ім'я користувача не може бути порожнім")
        self.username = username
        self.email = email  # проходить через setter з валідацією
        self.role = role
        self.active = active
        self.__password_hash = b""
        self.__password_salt = b""
        self.set_password(password)

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not isinstance(value, str) or not EMAIL_RE.fullmatch(value):
            raise ValueError(f"Некоректний email: {value!r}")
        self._email = value

    @staticmethod
    def _derive(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
        )

    def set_password(self, password: str) -> None:
        """Зберігає лише сіль і хеш; відкритий пароль ніде не залишається."""
        if not isinstance(password, str) or not password:
            raise ValueError("Пароль не може бути порожнім")
        self.__password_salt = os.urandom(SALT_SIZE)
        self.__password_hash = self._derive(password, self.__password_salt)

    def check_password(self, password: str) -> bool:
        if not isinstance(password, str):
            return False
        candidate = self._derive(password, self.__password_salt)
        return hmac.compare_digest(candidate, self.__password_hash)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        state = "active" if self.active else "inactive"
        return f"User({self.username}, {self.email}, role={self.role}, {state})"


class Admin(User):
    """Адміністратор: User + набір дозволів (наслідування, відношення Is-A)."""

    def __init__(
        self,
        username: str,
        email: str,
        password: str,
        permissions: set[str] | None = None,
        active: bool = True,
    ) -> None:
        super().__init__(username, email, "admin", password, active)
        # Нова множина для кожного об'єкта: без змінюваного типового аргументу.
        self.permissions: set[str] = set(permissions) if permissions else set()

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        perms = ", ".join(sorted(self.permissions)) or "-"
        return f"{super().__str__()} permissions=[{perms}]"


class Session:
    """Сеанс користувача (час тільки UTC з часовим поясом)."""

    def __init__(
        self,
        ip: str,
        login_time: datetime | None = None,
        last_activity: datetime | None = None,
    ) -> None:
        self.ip = ip
        self.login_time = login_time or _utcnow()
        self.last_activity = last_activity or self.login_time

    def touch(self) -> None:
        self.last_activity = _utcnow()

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("timeout_sec має бути додатним")
        return _utcnow() - self.last_activity <= timedelta(seconds=timeout_sec)


@dataclass(frozen=True)
class LogEntry:
    """Один запис аудиту. @dataclass дає __init__, __repr__, __eq__ безкоштовно."""

    username: str
    action: str
    timestamp: datetime = field(default_factory=_utcnow)


class AuditLog:
    """Журнал аудиту. Паролі в нього ніколи не потрапляють."""

    def __init__(self) -> None:
        self.entries: list[LogEntry] = []

    def add_log(self, username: str, action: str) -> None:
        self.entries.append(LogEntry(username, action))

    def show_all(self) -> None:
        for e in self.entries:
            print(f"{e.timestamp:%Y-%m-%d %H:%M:%S} UTC | {e.username} | {e.action}")


class UserAccount:
    """Композиція (Has-A): User + Session + AuditLog."""

    # Лише ці ключі доступні через account[...]; хеш і сіль пароля не доступні.
    _ALLOWED: ClassVar[dict[str, type | tuple[type, ...]]] = {
        "user": User,
        "session": (Session, type(None)),
        "audit": AuditLog,
    }

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self.user = user
        self.session = session
        self.audit = audit if audit is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        ok = (
            self.user.active
            and username == self.user.username
            and self.user.check_password(password)
        )
        if not ok:
            self.audit.add_log(username, ACTION_LOGIN_FAILURE)
            return False
        self.session = Session(ip)
        self.session.touch()
        self.audit.add_log(username, ACTION_LOGIN_SUCCESS)
        return True

    def is_authenticated(self) -> bool:
        # Перевірка нічого не оновлює: невдала перевірка не подовжує сеанс.
        return (
            self.user.active
            and self.session is not None
            and self.session.is_active(SESSION_TIMEOUT_SEC)
        )

    def logout(self) -> None:
        if self.session is None:
            return
        self.session = None
        self.audit.add_log(self.user.username, ACTION_LOGOUT)

    def __getitem__(self, key: str) -> object:
        if key not in self._ALLOWED:
            raise KeyError(key)
        return getattr(self, key)

    def __setitem__(self, key: str, value: object) -> None:
        if key not in self._ALLOWED:
            raise KeyError(key)
        if not isinstance(value, self._ALLOWED[key]):
            raise TypeError(f"Невірний тип для {key!r}: {type(value).__name__}")
        setattr(self, key, value)


def run_demo() -> None:
    """Сценарій демонстрації: python -m labs.lab02.main demo."""
    # Навчальний пароль лише для демонстрації.
    admin = Admin("alice_adm", "alice_adm@example.com", "S3cret!pass", {"read_logs"})
    account = UserAccount(admin)

    print("--- Вхід ---")
    print("Невдалий вхід:", account.login("alice_adm", "wrong", "10.0.0.5"))
    print("Успішний вхід:", account.login("alice_adm", "S3cret!pass", "10.0.0.5"))
    print("Автентифікований:", account.is_authenticated())

    print("\n--- Зміна email ---")
    admin.email = "alice_new@example.com"
    print("Новий email:", admin.email)
    for bad in ("1bad@@example", "ab@example.com", "alice@localhost"):
        try:
            admin.email = bad
        except ValueError as exc:
            print("Помилка валідації:", exc)

    print("\n--- Права адміністратора ---")
    admin.grant_permission("manage_users")
    admin.revoke_permission("read_logs")
    print(admin)
    print("manage_users:", admin.has_permission("manage_users"))
    print("read_logs:", admin.has_permission("read_logs"))

    print("\n--- Доступ через ключі ---")
    print("account['user'] ->", account["user"])
    for key, value in (("password", 1), ("user", "not a user")):
        try:
            account[key] = value
        except (KeyError, TypeError) as exc:
            print(f"{type(exc).__name__}: {exc}")

    print("\n--- Таймаут сеансу ---")
    old = _utcnow() - timedelta(seconds=SESSION_TIMEOUT_SEC + 60)
    account["session"] = Session("10.0.0.5", old, old)
    print("Автентифікований після таймауту:", account.is_authenticated())

    print("\n--- Вихід ---")
    account.login("alice_adm", "S3cret!pass", "10.0.0.5")
    account.logout()
    print("Автентифікований:", account.is_authenticated())

    print("\n--- AuditLog ---")
    account.audit.show_all()
