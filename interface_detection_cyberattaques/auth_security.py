from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
import threading
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


APP_DIR = Path(__file__).resolve().parent
try:
    from dotenv import load_dotenv

    load_dotenv(APP_DIR / ".env", override=False)
except ImportError:
    pass

AUTH_DB_FILE = Path(
    os.getenv("AUTH_DB_FILE", str(APP_DIR / "security" / "authentication.db"))
).expanduser()
if not AUTH_DB_FILE.is_absolute():
    AUTH_DB_FILE = (APP_DIR / AUTH_DB_FILE).resolve()

SESSION_DURATION_HOURS = max(1, min(int(os.getenv("AUTH_SESSION_HOURS", "12")), 168))
CODE_DURATION_MINUTES = max(
    3,
    min(int(os.getenv("EMAIL_CODE_DURATION_MINUTES", "10")), 30),
)
CODE_RESEND_SECONDS = max(
    30,
    min(int(os.getenv("EMAIL_CODE_RESEND_SECONDS", "60")), 300),
)
MAX_CODE_ATTEMPTS = 5
PASSWORD_ITERATIONS = 390_000

EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{3,32}$")

PUBLIC_PATHS = {
    "/",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/health/ready",
    "/auth/status",
    "/auth/login",
    "/auth/register/request-code",
    "/auth/register/verify",
    "/auth/register/resend",
    "/auth/password-reset/request-code",
    "/auth/password-reset/verify",
}

router = APIRouter()
_DATABASE_LOCK = threading.RLock()
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_FAILURES = 5
LOGIN_MAX_FAILURES_PER_CLIENT = 20


class LoginRequest(BaseModel):
    identifier: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)


class RegistrationRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=80)
    username: str = Field(min_length=3, max_length=32)
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=10, max_length=256)


class RegistrationVerifyRequest(BaseModel):
    registration_id: str = Field(min_length=20, max_length=200)
    code: str = Field(min_length=6, max_length=6)


class RegistrationResendRequest(BaseModel):
    registration_id: str = Field(min_length=20, max_length=200)


class EmailCodeRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254)


class EmailCodeVerifyRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    code: str = Field(min_length=6, max_length=6)


class PasswordResetRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254)


class PasswordResetVerifyRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    code: str = Field(min_length=6, max_length=6)
    new_password: str = Field(min_length=10, max_length=256)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=10, max_length=256)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_datetime(value: datetime | None = None) -> str:
    return (value or utc_now()).isoformat(timespec="seconds")


def parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "oui", "on"}


def normalize_email(value: str) -> str:
    return value.strip().lower()


def valid_email(value: str) -> bool:
    return len(value) <= 254 and bool(EMAIL_PATTERN.fullmatch(value))


def mask_email(value: str) -> str:
    value = value.strip()
    if not value or "@" not in value:
        return ""
    local, domain = value.split("@", 1)
    visible = local[:2] if len(local) > 1 else local[:1]
    return f"{visible}***@{domain}"


def validate_identity(full_name: str, username: str, email: str) -> tuple[str, str, str]:
    clean_name = " ".join(full_name.strip().split())
    clean_username = username.strip().lower()
    clean_email = normalize_email(email)

    if len(clean_name) < 2:
        raise HTTPException(status_code=422, detail="Le nom complet est obligatoire.")
    if not USERNAME_PATTERN.fullmatch(clean_username):
        raise HTTPException(
            status_code=422,
            detail=(
                "L'identifiant doit contenir 3 a 32 caracteres : lettres, chiffres, "
                "point, tiret ou tiret bas."
            ),
        )
    if not valid_email(clean_email):
        raise HTTPException(status_code=422, detail="Adresse e-mail invalide.")
    return clean_name, clean_username, clean_email


def validate_password(password: str) -> None:
    if len(password) < 10:
        raise HTTPException(
            status_code=422,
            detail="Le mot de passe doit contenir au moins 10 caracteres.",
        )
    if not re.search(r"[a-z]", password):
        raise HTTPException(status_code=422, detail="Ajoutez une lettre minuscule.")
    if not re.search(r"[A-Z]", password):
        raise HTTPException(status_code=422, detail="Ajoutez une lettre majuscule.")
    if not re.search(r"[0-9]", password):
        raise HTTPException(status_code=422, detail="Ajoutez un chiffre.")


def database_connection() -> sqlite3.Connection:
    AUTH_DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(AUTH_DB_FILE, timeout=20)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 20000")
    return connection


def ensure_column(
    connection: sqlite3.Connection,
    table: str,
    column: str,
    declaration: str,
) -> None:
    existing = {
        str(row["name"])
        for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
    }
    if column not in existing:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")


def initialize_auth_database() -> None:
    with _DATABASE_LOCK, database_connection() as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                full_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'analyst',
                alert_email TEXT UNIQUE COLLATE NOCASE,
                alert_email_verified_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS registration_requests (
                registration_hash TEXT PRIMARY KEY,
                full_name TEXT NOT NULL,
                username TEXT NOT NULL COLLATE NOCASE,
                email TEXT NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                code_salt TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                last_sent_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS email_verifications (
                user_id TEXT PRIMARY KEY,
                email TEXT NOT NULL COLLATE NOCASE,
                code_hash TEXT NOT NULL,
                code_salt TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                last_sent_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS password_resets (
                user_id TEXT PRIMARY KEY,
                code_hash TEXT NOT NULL,
                code_salt TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                last_sent_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS login_failures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identifier_hash TEXT NOT NULL,
                client_hash TEXT NOT NULL,
                attempted_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                event_type TEXT NOT NULL,
                result TEXT NOT NULL,
                client_hash TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_expiry
                ON sessions(expires_at);
            CREATE INDEX IF NOT EXISTS idx_registration_email
                ON registration_requests(email);
            CREATE INDEX IF NOT EXISTS idx_registration_username
                ON registration_requests(username);
            CREATE INDEX IF NOT EXISTS idx_login_failures_lookup
                ON login_failures(identifier_hash, client_hash, attempted_at);
            CREATE INDEX IF NOT EXISTS idx_login_failures_client
                ON login_failures(client_hash, attempted_at);
            CREATE INDEX IF NOT EXISTS idx_security_events_user
                ON security_events(user_id, created_at);
            """
        )
        ensure_column(
            connection,
            "users",
            "alert_enabled",
            "INTEGER NOT NULL DEFAULT 1",
        )

        # Migration sûre de la v9 : le premier compte existant devient
        # l'administrateur principal et propriétaire des alertes automatiques.
        admin_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM users WHERE role = 'admin'"
            ).fetchone()[0]
        )
        if admin_count == 0:
            first_user = connection.execute(
                "SELECT id FROM users ORDER BY created_at ASC LIMIT 1"
            ).fetchone()
            if first_user:
                connection.execute(
                    "UPDATE users SET role = 'admin' WHERE id = ?",
                    (str(first_user["id"]),),
                )


def hash_secret(value: str, salt: bytes | None = None) -> tuple[str, str]:
    actual_salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        value.encode("utf-8"),
        actual_salt,
        PASSWORD_ITERATIONS,
    )
    return digest.hex(), actual_salt.hex()


def verify_secret(value: str, expected_hash: str, salt_hex: str) -> bool:
    actual_hash, _ = hash_secret(value, bytes.fromhex(salt_hex))
    return hmac.compare_digest(actual_hash, expected_hash)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def make_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def smtp_configuration() -> dict[str, Any]:
    sender = os.getenv("GMAIL_SENDER", "").strip()
    password = os.getenv("GMAIL_APP_PASSWORD", "").replace(" ", "").strip()
    enabled = env_bool("GMAIL_ENABLED", True)
    return {
        "enabled": enabled,
        "configured": bool(enabled and sender and password),
        "host": os.getenv("GMAIL_SMTP_HOST", "smtp.gmail.com").strip(),
        "port": int(os.getenv("GMAIL_SMTP_PORT", "587")),
        "sender": sender,
        "password": password,
    }


def send_smtp_message(recipient: str, subject: str, body: str) -> tuple[bool, str]:
    config = smtp_configuration()
    if not config["enabled"]:
        return False, "La messagerie est desactivee."
    if not config["configured"]:
        return False, "Les identifiants SMTP Gmail ne sont pas configures dans .env."

    message = EmailMessage()
    message["From"] = config["sender"]
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)

    try:
        context = ssl.create_default_context()
        if config["port"] == 465:
            with smtplib.SMTP_SSL(
                config["host"],
                config["port"],
                context=context,
                timeout=20,
            ) as smtp:
                smtp.login(config["sender"], config["password"])
                smtp.send_message(message)
        else:
            with smtplib.SMTP(config["host"], config["port"], timeout=20) as smtp:
                smtp.ehlo()
                smtp.starttls(context=context)
                smtp.ehlo()
                smtp.login(config["sender"], config["password"])
                smtp.send_message(message)
        return True, ""
    except Exception as exc:  # noqa: BLE001
        return False, f"{exc.__class__.__name__}: {exc}"


def verification_message(code: str, purpose: str) -> tuple[str, str]:
    subject = f"[SOC] Code de verification - {purpose}"
    body = "\n".join(
        [
            "Verification de votre adresse e-mail SOC",
            "",
            f"Votre code de verification est : {code}",
            f"Ce code expire dans {CODE_DURATION_MINUTES} minutes.",
            "",
            "Si vous n'etes pas a l'origine de cette demande, ignorez ce message.",
            "Ne communiquez jamais ce code a une autre personne.",
        ]
    )
    return subject, body


def cleanup_expired(connection: sqlite3.Connection) -> None:
    now = iso_datetime()
    login_threshold = iso_datetime(
        utc_now() - timedelta(seconds=LOGIN_WINDOW_SECONDS)
    )
    audit_threshold = iso_datetime(utc_now() - timedelta(days=90))
    connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
    connection.execute(
        "DELETE FROM registration_requests WHERE expires_at <= ?",
        (now,),
    )
    connection.execute(
        "DELETE FROM email_verifications WHERE expires_at <= ?",
        (now,),
    )
    connection.execute("DELETE FROM password_resets WHERE expires_at <= ?", (now,))
    connection.execute(
        "DELETE FROM login_failures WHERE attempted_at <= ?",
        (login_threshold,),
    )
    connection.execute(
        "DELETE FROM security_events WHERE created_at <= ?",
        (audit_threshold,),
    )


def user_payload(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    email = str(row["alert_email"] or "")
    verified_at = str(row["alert_email_verified_at"] or "")
    return {
        "id": str(row["id"]),
        "username": str(row["username"]),
        "full_name": str(row["full_name"]),
        "role": str(row["role"]),
        "email": email,
        "email_masked": mask_email(email),
        "email_verified": bool(email and verified_at),
        "email_verified_at": verified_at,
        "alert_enabled": bool(int(row["alert_enabled"] or 0)),
    }


def client_address(request: Request) -> str:
    # L'API est liée à 127.0.0.1 et n'accorde aucune confiance implicite aux
    # en-têtes X-Forwarded-For fournis par le client.
    return request.client.host if request.client else "unknown"


def privacy_digest(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()


def record_security_event(
    event_type: str,
    result: str,
    *,
    user_id: str | None = None,
    request: Request | None = None,
) -> None:
    client_hash = privacy_digest(client_address(request)) if request else ""
    with _DATABASE_LOCK, database_connection() as connection:
        connection.execute(
            """
            INSERT INTO security_events(user_id, event_type, result, client_hash, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, event_type[:80], result[:40], client_hash, iso_datetime()),
        )


def create_session(user_id: str) -> tuple[str, str]:
    raw_token = secrets.token_urlsafe(48)
    created_at = utc_now()
    expires_at = created_at + timedelta(hours=SESSION_DURATION_HOURS)
    with _DATABASE_LOCK, database_connection() as connection:
        cleanup_expired(connection)
        existing_sessions = connection.execute(
            """
            SELECT token_hash FROM sessions
            WHERE user_id = ?
            ORDER BY created_at DESC
            """,
            (user_id,),
        ).fetchall()
        for old_session in existing_sessions[4:]:
            connection.execute(
                "DELETE FROM sessions WHERE token_hash = ?",
                (str(old_session["token_hash"]),),
            )
        connection.execute(
            """
            INSERT INTO sessions(token_hash, user_id, created_at, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                token_digest(raw_token),
                user_id,
                iso_datetime(created_at),
                iso_datetime(expires_at),
            ),
        )
    return raw_token, iso_datetime(expires_at)


def get_user_from_token(token: str) -> dict[str, Any] | None:
    if not token:
        return None
    with _DATABASE_LOCK, database_connection() as connection:
        cleanup_expired(connection)
        row = connection.execute(
            """
            SELECT u.*
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ? AND s.expires_at > ?
            """,
            (token_digest(token), iso_datetime()),
        ).fetchone()
    return user_payload(row) if row else None


def bearer_token(request: Request) -> str:
    authorization = request.headers.get("Authorization", "").strip()
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return ""
    return token.strip()


async def authentication_middleware(request: Request, call_next):
    path = request.url.path.rstrip("/") or "/"
    if request.method == "OPTIONS" or path in PUBLIC_PATHS:
        return await call_next(request)

    token = bearer_token(request)
    user = get_user_from_token(token)
    if user is None:
        return JSONResponse(
            status_code=401,
            content={"detail": "Authentification requise ou session expiree."},
            headers={"WWW-Authenticate": "Bearer"},
        )
    request.state.auth_user = user
    return await call_next(request)


def request_user(request: Request) -> dict[str, Any]:
    user = getattr(request.state, "auth_user", None)
    if not user:
        raise HTTPException(status_code=401, detail="Authentification requise.")
    return user


def auth_response(user: dict[str, Any], token: str, expires_at: str) -> dict[str, Any]:
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires_at,
        "user": user,
    }


def get_user_recipient(user_id: str) -> str:
    initialize_auth_database()
    with _DATABASE_LOCK, database_connection() as connection:
        row = connection.execute(
            """
            SELECT alert_email
            FROM users
            WHERE id = ?
              AND alert_enabled = 1
              AND alert_email IS NOT NULL
              AND alert_email != ''
              AND alert_email_verified_at IS NOT NULL
            LIMIT 1
            """
            ,
            (user_id,),
        ).fetchone()
    return str(row["alert_email"]) if row else ""


def get_primary_alert_user() -> dict[str, Any] | None:
    """Retourne l'unique propriétaire des alertes Suricata automatiques."""
    initialize_auth_database()
    with _DATABASE_LOCK, database_connection() as connection:
        row = connection.execute(
            """
            SELECT * FROM users
            WHERE role = 'admin'
              AND alert_enabled = 1
              AND alert_email_verified_at IS NOT NULL
            ORDER BY created_at ASC
            LIMIT 1
            """
        ).fetchone()
    return user_payload(row) if row else None


def registration_allowed(connection: sqlite3.Connection | None = None) -> bool:
    if env_bool("AUTH_ALLOW_ADDITIONAL_REGISTRATION", False):
        return True
    if connection is not None:
        return int(connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]) == 0
    with _DATABASE_LOCK, database_connection() as local_connection:
        return int(local_connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]) == 0


def login_failure_keys(identifier: str, request: Request) -> tuple[str, str]:
    return privacy_digest(identifier), privacy_digest(client_address(request))


def check_login_throttle(identifier: str, request: Request) -> None:
    identifier_hash, client_hash = login_failure_keys(identifier, request)
    threshold = utc_now() - timedelta(seconds=LOGIN_WINDOW_SECONDS)
    with _DATABASE_LOCK, database_connection() as connection:
        cleanup_expired(connection)
        combined = connection.execute(
            """
            SELECT COUNT(*) AS attempts, MIN(attempted_at) AS first_attempt
            FROM login_failures
            WHERE identifier_hash = ? AND client_hash = ? AND attempted_at > ?
            """,
            (identifier_hash, client_hash, iso_datetime(threshold)),
        ).fetchone()
        client_total = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM login_failures
                WHERE client_hash = ? AND attempted_at > ?
                """,
                (client_hash, iso_datetime(threshold)),
            ).fetchone()[0]
        )

    attempts = int(combined["attempts"] or 0)
    if attempts >= LOGIN_MAX_FAILURES or client_total >= LOGIN_MAX_FAILURES_PER_CLIENT:
        first_attempt = parse_datetime(str(combined["first_attempt"])) if combined["first_attempt"] else threshold
        remaining = int(
            LOGIN_WINDOW_SECONDS - (utc_now() - first_attempt).total_seconds()
        ) + 1
        raise HTTPException(
            status_code=429,
            detail=f"Trop de tentatives. Reessayez dans {max(1, remaining)} secondes.",
        )


def record_login_failure(identifier: str, request: Request) -> None:
    identifier_hash, client_hash = login_failure_keys(identifier, request)
    with _DATABASE_LOCK, database_connection() as connection:
        connection.execute(
            """
            INSERT INTO login_failures(identifier_hash, client_hash, attempted_at)
            VALUES (?, ?, ?)
            """,
            (identifier_hash, client_hash, iso_datetime()),
        )


def clear_login_failures(identifier: str, request: Request) -> None:
    identifier_hash, client_hash = login_failure_keys(identifier, request)
    with _DATABASE_LOCK, database_connection() as connection:
        connection.execute(
            "DELETE FROM login_failures WHERE identifier_hash = ? AND client_hash = ?",
            (identifier_hash, client_hash),
        )


@router.get("/auth/status")
def auth_status() -> dict[str, Any]:
    initialize_auth_database()
    with _DATABASE_LOCK, database_connection() as connection:
        users_count = int(connection.execute("SELECT COUNT(*) FROM users").fetchone()[0])
    smtp = smtp_configuration()
    return {
        "authentication_enabled": True,
        "registration_enabled": registration_allowed(),
        "account_initialized": users_count > 0,
        "email_verification_available": smtp["configured"],
        "code_expiration_minutes": CODE_DURATION_MINUTES,
        "resend_delay_seconds": CODE_RESEND_SECONDS,
    }


@router.post("/auth/register/request-code")
def register_request_code(payload: RegistrationRequest, request: Request) -> dict[str, Any]:
    initialize_auth_database()
    full_name, username, email = validate_identity(
        payload.full_name,
        payload.username,
        payload.email,
    )
    validate_password(payload.password)
    smtp = smtp_configuration()
    if not smtp["configured"]:
        raise HTTPException(
            status_code=503,
            detail=(
                "L'envoi du code est indisponible. Configurez GMAIL_SENDER et "
                "GMAIL_APP_PASSWORD dans le fichier .env."
            ),
        )

    now = utc_now()
    with _DATABASE_LOCK, database_connection() as connection:
        cleanup_expired(connection)
        if not registration_allowed(connection):
            raise HTTPException(
                status_code=403,
                detail="L'inscription publique est fermee apres la creation du compte principal.",
            )
        duplicate = connection.execute(
            """
            SELECT username, alert_email
            FROM users
            WHERE username = ? COLLATE NOCASE OR alert_email = ? COLLATE NOCASE
            """,
            (username, email),
        ).fetchone()
        if duplicate:
            if str(duplicate["username"]).lower() == username:
                detail = "Cet identifiant est deja utilise."
            else:
                detail = "Cette adresse e-mail est deja associee a un compte."
            raise HTTPException(status_code=409, detail=detail)

        recent = connection.execute(
            """
            SELECT last_sent_at
            FROM registration_requests
            WHERE email = ? COLLATE NOCASE OR username = ? COLLATE NOCASE
            ORDER BY last_sent_at DESC
            LIMIT 1
            """,
            (email, username),
        ).fetchone()
        if recent:
            elapsed = (now - parse_datetime(str(recent["last_sent_at"]))).total_seconds()
            if elapsed < CODE_RESEND_SECONDS:
                wait_seconds = int(CODE_RESEND_SECONDS - elapsed) + 1
                raise HTTPException(
                    status_code=429,
                    detail=f"Attendez {wait_seconds} secondes avant un nouvel envoi.",
                )

    registration_id = secrets.token_urlsafe(32)
    code = make_code()
    password_hash, password_salt = hash_secret(payload.password)
    code_hash, code_salt = hash_secret(code)
    expires_at = now + timedelta(minutes=CODE_DURATION_MINUTES)

    subject, body = verification_message(code, "creation du compte")
    sent, error = send_smtp_message(email, subject, body)
    if not sent:
        raise HTTPException(
            status_code=502,
            detail=f"Le code n'a pas pu etre envoye : {error}",
        )

    with _DATABASE_LOCK, database_connection() as connection:
        connection.execute(
            "DELETE FROM registration_requests WHERE email = ? OR username = ?",
            (email, username),
        )
        connection.execute(
            """
            INSERT INTO registration_requests(
                registration_hash, full_name, username, email,
                password_hash, password_salt, code_hash, code_salt,
                attempts, created_at, last_sent_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
            """,
            (
                token_digest(registration_id),
                full_name,
                username,
                email,
                password_hash,
                password_salt,
                code_hash,
                code_salt,
                iso_datetime(now),
                iso_datetime(now),
                iso_datetime(expires_at),
            ),
        )

    record_security_event("registration_code", "sent", request=request)

    return {
        "message": "Code de verification envoye.",
        "registration_id": registration_id,
        "email_masked": mask_email(email),
        "expires_in_minutes": CODE_DURATION_MINUTES,
        "resend_after_seconds": CODE_RESEND_SECONDS,
    }


@router.post("/auth/register/resend")
def register_resend(payload: RegistrationResendRequest) -> dict[str, Any]:
    initialize_auth_database()
    registration_hash = token_digest(payload.registration_id)
    now = utc_now()

    with _DATABASE_LOCK, database_connection() as connection:
        row = connection.execute(
            "SELECT * FROM registration_requests WHERE registration_hash = ?",
            (registration_hash,),
        ).fetchone()
    if not row:
        raise HTTPException(
            status_code=404,
            detail="Demande d'inscription introuvable ou expiree. Recommencez l'inscription.",
        )

    elapsed = (now - parse_datetime(str(row["last_sent_at"]))).total_seconds()
    if elapsed < CODE_RESEND_SECONDS:
        wait_seconds = int(CODE_RESEND_SECONDS - elapsed) + 1
        raise HTTPException(
            status_code=429,
            detail=f"Attendez {wait_seconds} secondes avant de renvoyer le code.",
        )

    code = make_code()
    code_hash, code_salt = hash_secret(code)
    expires_at = now + timedelta(minutes=CODE_DURATION_MINUTES)
    subject, body = verification_message(code, "creation du compte")
    sent, error = send_smtp_message(str(row["email"]), subject, body)
    if not sent:
        raise HTTPException(status_code=502, detail=f"Echec de l'envoi : {error}")

    with _DATABASE_LOCK, database_connection() as connection:
        connection.execute(
            """
            UPDATE registration_requests
            SET code_hash = ?, code_salt = ?, attempts = 0,
                last_sent_at = ?, expires_at = ?
            WHERE registration_hash = ?
            """,
            (
                code_hash,
                code_salt,
                iso_datetime(now),
                iso_datetime(expires_at),
                registration_hash,
            ),
        )
    return {
        "message": "Un nouveau code a ete envoye.",
        "email_masked": mask_email(str(row["email"])),
        "expires_in_minutes": CODE_DURATION_MINUTES,
    }


@router.post("/auth/register/verify")
def register_verify(payload: RegistrationVerifyRequest, request: Request) -> dict[str, Any]:
    initialize_auth_database()
    if not payload.code.isdigit():
        raise HTTPException(status_code=422, detail="Le code doit contenir 6 chiffres.")

    registration_hash = token_digest(payload.registration_id)
    with _DATABASE_LOCK, database_connection() as connection:
        row = connection.execute(
            "SELECT * FROM registration_requests WHERE registration_hash = ?",
            (registration_hash,),
        ).fetchone()
        if not row:
            raise HTTPException(
                status_code=404,
                detail="Demande d'inscription introuvable ou expiree.",
            )
        if parse_datetime(str(row["expires_at"])) <= utc_now():
            connection.execute(
                "DELETE FROM registration_requests WHERE registration_hash = ?",
                (registration_hash,),
            )
            connection.commit()
            raise HTTPException(status_code=410, detail="Le code a expire.")
        if int(row["attempts"]) >= MAX_CODE_ATTEMPTS:
            connection.execute(
                "DELETE FROM registration_requests WHERE registration_hash = ?",
                (registration_hash,),
            )
            connection.commit()
            raise HTTPException(
                status_code=429,
                detail="Nombre maximal d'essais atteint. Recommencez l'inscription.",
            )
        if not verify_secret(payload.code, str(row["code_hash"]), str(row["code_salt"])):
            attempts = int(row["attempts"]) + 1
            connection.execute(
                "UPDATE registration_requests SET attempts = ? WHERE registration_hash = ?",
                (attempts, registration_hash),
            )
            connection.commit()
            remaining = MAX_CODE_ATTEMPTS - attempts
            raise HTTPException(
                status_code=422,
                detail=f"Code incorrect. {remaining} essai(s) restant(s).",
            )

        users_count = int(connection.execute("SELECT COUNT(*) FROM users").fetchone()[0])
        if users_count > 0 and not env_bool("AUTH_ALLOW_ADDITIONAL_REGISTRATION", False):
            connection.execute(
                "DELETE FROM registration_requests WHERE registration_hash = ?",
                (registration_hash,),
            )
            raise HTTPException(status_code=403, detail="L'inscription publique est fermee.")

        user_id = secrets.token_hex(16)
        role = "admin" if users_count == 0 else "analyst"
        try:
            connection.execute(
                """
                INSERT INTO users(
                    id, username, full_name, password_hash, password_salt,
                    role, alert_email, alert_email_verified_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    str(row["username"]),
                    str(row["full_name"]),
                    str(row["password_hash"]),
                    str(row["password_salt"]),
                    role,
                    str(row["email"]),
                    iso_datetime(),
                    iso_datetime(),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(
                status_code=409,
                detail="L'identifiant ou l'adresse e-mail est deja utilise.",
            ) from exc
        connection.execute(
            "DELETE FROM registration_requests WHERE registration_hash = ?",
            (registration_hash,),
        )
        user_row = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    user = user_payload(user_row)
    token, expires_at = create_session(user_id)
    record_security_event("registration", "success", user_id=user_id, request=request)
    return auth_response(user, token, expires_at)


@router.post("/auth/login")
def login(payload: LoginRequest, request: Request) -> dict[str, Any]:
    initialize_auth_database()
    identifier = payload.identifier.strip().lower()
    check_login_throttle(identifier, request)
    with _DATABASE_LOCK, database_connection() as connection:
        cleanup_expired(connection)
        row = connection.execute(
            """
            SELECT * FROM users
            WHERE username = ? COLLATE NOCASE OR alert_email = ? COLLATE NOCASE
            LIMIT 1
            """,
            (identifier, identifier),
        ).fetchone()

    if not row or not verify_secret(
        payload.password,
        str(row["password_hash"]) if row else "00",
        str(row["password_salt"]) if row else "00" * 16,
    ):
        record_login_failure(identifier, request)
        record_security_event("login", "failure", request=request)
        raise HTTPException(status_code=401, detail="Identifiant ou mot de passe incorrect.")

    clear_login_failures(identifier, request)
    user = user_payload(row)
    token, expires_at = create_session(str(row["id"]))
    record_security_event("login", "success", user_id=user["id"], request=request)
    return auth_response(user, token, expires_at)


@router.get("/auth/me")
def auth_me(request: Request) -> dict[str, Any]:
    return {"user": request_user(request)}


@router.post("/auth/logout")
def logout(request: Request) -> dict[str, str]:
    user = request_user(request)
    token = bearer_token(request)
    with _DATABASE_LOCK, database_connection() as connection:
        connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_digest(token),))
    record_security_event("logout", "success", user_id=user["id"], request=request)
    return {"message": "Deconnexion effectuee."}


@router.post("/auth/password-reset/request-code")
def password_reset_request(
    payload: PasswordResetRequest,
    request: Request,
) -> dict[str, Any]:
    initialize_auth_database()
    email = normalize_email(payload.email)
    generic_response = {
        "message": (
            "Si cette adresse correspond a un compte verifie, un code de "
            "reinitialisation vient d'etre envoye."
        ),
        "expires_in_minutes": CODE_DURATION_MINUTES,
    }
    if not valid_email(email):
        return generic_response

    now = utc_now()
    with _DATABASE_LOCK, database_connection() as connection:
        cleanup_expired(connection)
        row = connection.execute(
            """
            SELECT * FROM users
            WHERE alert_email = ? COLLATE NOCASE
              AND alert_email_verified_at IS NOT NULL
            LIMIT 1
            """,
            (email,),
        ).fetchone()
        previous = None
        if row:
            previous = connection.execute(
                "SELECT * FROM password_resets WHERE user_id = ?",
                (str(row["id"]),),
            ).fetchone()

    if not row:
        record_security_event("password_reset_request", "accepted", request=request)
        return generic_response
    if previous:
        elapsed = (now - parse_datetime(str(previous["last_sent_at"]))).total_seconds()
        if elapsed < CODE_RESEND_SECONDS:
            return generic_response

    code = make_code()
    code_hash, code_salt = hash_secret(code)
    expires_at = now + timedelta(minutes=CODE_DURATION_MINUTES)
    subject, body = verification_message(code, "reinitialisation du mot de passe")
    sent, _ = send_smtp_message(email, subject, body)
    if sent:
        with _DATABASE_LOCK, database_connection() as connection:
            connection.execute(
                """
                INSERT INTO password_resets(
                    user_id, code_hash, code_salt, attempts,
                    created_at, last_sent_at, expires_at
                ) VALUES (?, ?, ?, 0, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    code_hash = excluded.code_hash,
                    code_salt = excluded.code_salt,
                    attempts = 0,
                    created_at = excluded.created_at,
                    last_sent_at = excluded.last_sent_at,
                    expires_at = excluded.expires_at
                """,
                (
                    str(row["id"]),
                    code_hash,
                    code_salt,
                    iso_datetime(now),
                    iso_datetime(now),
                    iso_datetime(expires_at),
                ),
            )
    record_security_event(
        "password_reset_request",
        "sent" if sent else "delivery_failure",
        user_id=str(row["id"]),
        request=request,
    )
    return generic_response


@router.post("/auth/password-reset/verify")
def password_reset_verify(
    payload: PasswordResetVerifyRequest,
    request: Request,
) -> dict[str, str]:
    initialize_auth_database()
    email = normalize_email(payload.email)
    validate_password(payload.new_password)
    if not valid_email(email) or not payload.code.isdigit():
        raise HTTPException(status_code=422, detail="Code ou demande de reinitialisation invalide.")

    with _DATABASE_LOCK, database_connection() as connection:
        cleanup_expired(connection)
        user_row = connection.execute(
            "SELECT * FROM users WHERE alert_email = ? COLLATE NOCASE LIMIT 1",
            (email,),
        ).fetchone()
        reset_row = None
        if user_row:
            reset_row = connection.execute(
                "SELECT * FROM password_resets WHERE user_id = ?",
                (str(user_row["id"]),),
            ).fetchone()
        if not user_row or not reset_row:
            raise HTTPException(status_code=422, detail="Code ou demande de reinitialisation invalide.")
        if int(reset_row["attempts"]) >= MAX_CODE_ATTEMPTS:
            connection.execute(
                "DELETE FROM password_resets WHERE user_id = ?",
                (str(user_row["id"]),),
            )
            raise HTTPException(status_code=429, detail="Nombre maximal d'essais atteint.")
        if not verify_secret(
            payload.code,
            str(reset_row["code_hash"]),
            str(reset_row["code_salt"]),
        ):
            attempts = int(reset_row["attempts"]) + 1
            connection.execute(
                "UPDATE password_resets SET attempts = ? WHERE user_id = ?",
                (attempts, str(user_row["id"])),
            )
            raise HTTPException(status_code=422, detail="Code ou demande de reinitialisation invalide.")

        if verify_secret(
            payload.new_password,
            str(user_row["password_hash"]),
            str(user_row["password_salt"]),
        ):
            raise HTTPException(
                status_code=422,
                detail="Le nouveau mot de passe doit etre different de l'ancien.",
            )
        password_hash, password_salt = hash_secret(payload.new_password)
        user_id = str(user_row["id"])
        connection.execute(
            "UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?",
            (password_hash, password_salt, user_id),
        )
        connection.execute("DELETE FROM password_resets WHERE user_id = ?", (user_id,))
        connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))

    record_security_event("password_reset", "success", user_id=user_id, request=request)
    return {"message": "Mot de passe reinitialise. Connectez-vous avec le nouveau mot de passe."}


@router.get("/profile")
def get_profile(request: Request) -> dict[str, Any]:
    return request_user(request)


@router.post("/profile/password/change")
def change_password(
    payload: PasswordChangeRequest,
    request: Request,
) -> dict[str, Any]:
    user = request_user(request)
    validate_password(payload.new_password)
    with _DATABASE_LOCK, database_connection() as connection:
        row = connection.execute(
            "SELECT * FROM users WHERE id = ?",
            (user["id"],),
        ).fetchone()
        if not row or not verify_secret(
            payload.current_password,
            str(row["password_hash"]) if row else "00",
            str(row["password_salt"]) if row else "00" * 16,
        ):
            record_security_event(
                "password_change",
                "failure",
                user_id=user["id"],
                request=request,
            )
            raise HTTPException(status_code=401, detail="Mot de passe actuel incorrect.")
        if verify_secret(
            payload.new_password,
            str(row["password_hash"]),
            str(row["password_salt"]),
        ):
            raise HTTPException(
                status_code=422,
                detail="Le nouveau mot de passe doit etre different de l'ancien.",
            )
        password_hash, password_salt = hash_secret(payload.new_password)
        connection.execute(
            "UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?",
            (password_hash, password_salt, user["id"]),
        )
        connection.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))

    record_security_event(
        "password_change",
        "success",
        user_id=user["id"],
        request=request,
    )
    return {
        "message": "Mot de passe modifie. Toutes les sessions ont ete fermees.",
        "reauthentication_required": True,
    }


@router.get("/profile/security-events")
def get_security_events(request: Request) -> dict[str, Any]:
    user = request_user(request)
    with _DATABASE_LOCK, database_connection() as connection:
        rows = connection.execute(
            """
            SELECT event_type, result, created_at
            FROM security_events
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 50
            """,
            (user["id"],),
        ).fetchall()
    return {"events": [dict(row) for row in rows]}


@router.post("/profile/email/request-code")
def profile_request_code(payload: EmailCodeRequest, request: Request) -> dict[str, Any]:
    user = request_user(request)
    email = normalize_email(payload.email)
    if not valid_email(email):
        raise HTTPException(status_code=422, detail="Adresse e-mail invalide.")
    if user["email_verified"] and email == user["email"]:
        raise HTTPException(status_code=409, detail="Cette adresse est deja verifiee.")
    if not smtp_configuration()["configured"]:
        raise HTTPException(status_code=503, detail="La passerelle Gmail n'est pas configuree.")

    now = utc_now()
    with _DATABASE_LOCK, database_connection() as connection:
        duplicate = connection.execute(
            "SELECT id FROM users WHERE alert_email = ? COLLATE NOCASE AND id != ?",
            (email, user["id"]),
        ).fetchone()
        if duplicate:
            raise HTTPException(
                status_code=409,
                detail="Cette adresse e-mail est deja associee a un autre compte.",
            )
        previous = connection.execute(
            "SELECT * FROM email_verifications WHERE user_id = ?",
            (user["id"],),
        ).fetchone()
        if previous:
            elapsed = (now - parse_datetime(str(previous["last_sent_at"]))).total_seconds()
            if elapsed < CODE_RESEND_SECONDS:
                wait_seconds = int(CODE_RESEND_SECONDS - elapsed) + 1
                raise HTTPException(
                    status_code=429,
                    detail=f"Attendez {wait_seconds} secondes avant de renvoyer le code.",
                )

    code = make_code()
    code_hash, code_salt = hash_secret(code)
    expires_at = now + timedelta(minutes=CODE_DURATION_MINUTES)
    subject, body = verification_message(code, "adresse de reception des alertes")
    sent, error = send_smtp_message(email, subject, body)
    if not sent:
        raise HTTPException(status_code=502, detail=f"Le code n'a pas pu etre envoye : {error}")

    with _DATABASE_LOCK, database_connection() as connection:
        connection.execute(
            """
            INSERT INTO email_verifications(
                user_id, email, code_hash, code_salt, attempts,
                created_at, last_sent_at, expires_at
            ) VALUES (?, ?, ?, ?, 0, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                email = excluded.email,
                code_hash = excluded.code_hash,
                code_salt = excluded.code_salt,
                attempts = 0,
                created_at = excluded.created_at,
                last_sent_at = excluded.last_sent_at,
                expires_at = excluded.expires_at
            """,
            (
                user["id"],
                email,
                code_hash,
                code_salt,
                iso_datetime(now),
                iso_datetime(now),
                iso_datetime(expires_at),
            ),
        )
    record_security_event(
        "profile_email_code",
        "sent",
        user_id=user["id"],
        request=request,
    )
    return {
        "message": "Code de verification envoye.",
        "email_masked": mask_email(email),
        "expires_in_minutes": CODE_DURATION_MINUTES,
        "resend_after_seconds": CODE_RESEND_SECONDS,
    }


@router.post("/profile/email/verify")
def profile_verify_code(payload: EmailCodeVerifyRequest, request: Request) -> dict[str, Any]:
    user = request_user(request)
    email = normalize_email(payload.email)
    if not payload.code.isdigit():
        raise HTTPException(status_code=422, detail="Le code doit contenir 6 chiffres.")

    with _DATABASE_LOCK, database_connection() as connection:
        row = connection.execute(
            "SELECT * FROM email_verifications WHERE user_id = ?",
            (user["id"],),
        ).fetchone()
        if not row or str(row["email"]).lower() != email:
            raise HTTPException(status_code=404, detail="Aucune verification active pour cet e-mail.")
        if parse_datetime(str(row["expires_at"])) <= utc_now():
            connection.execute("DELETE FROM email_verifications WHERE user_id = ?", (user["id"],))
            connection.commit()
            raise HTTPException(status_code=410, detail="Le code a expire. Demandez un nouveau code.")
        if int(row["attempts"]) >= MAX_CODE_ATTEMPTS:
            connection.execute("DELETE FROM email_verifications WHERE user_id = ?", (user["id"],))
            connection.commit()
            raise HTTPException(status_code=429, detail="Nombre maximal d'essais atteint.")
        if not verify_secret(payload.code, str(row["code_hash"]), str(row["code_salt"])):
            attempts = int(row["attempts"]) + 1
            connection.execute(
                "UPDATE email_verifications SET attempts = ? WHERE user_id = ?",
                (attempts, user["id"]),
            )
            connection.commit()
            remaining = MAX_CODE_ATTEMPTS - attempts
            raise HTTPException(
                status_code=422,
                detail=f"Code incorrect. {remaining} essai(s) restant(s).",
            )

        try:
            connection.execute(
                """
                UPDATE users
                SET alert_email = ?, alert_email_verified_at = ?
                WHERE id = ?
                """,
                (email, iso_datetime(), user["id"]),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(
                status_code=409,
                detail="Cette adresse e-mail est deja associee a un autre compte.",
            ) from exc
        connection.execute("DELETE FROM email_verifications WHERE user_id = ?", (user["id"],))
        updated = connection.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()

    record_security_event(
        "profile_email_change",
        "success",
        user_id=user["id"],
        request=request,
    )
    return {
        "message": "Adresse e-mail verifiee et activee pour les alertes.",
        "user": user_payload(updated),
    }
