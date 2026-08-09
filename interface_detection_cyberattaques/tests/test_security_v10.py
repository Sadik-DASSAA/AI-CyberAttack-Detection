from __future__ import annotations

import os
import re
import sqlite3
import sys
import tempfile
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
TEST_ROOT = Path(tempfile.mkdtemp(prefix="soc-v10-security-"))
os.chdir(TEST_ROOT)
sys.path.insert(0, str(PROJECT_DIR))

os.environ.update(
    {
        "AUTH_DB_FILE": str(TEST_ROOT / "authentication.db"),
        "SURICATA_MONITOR_ENABLED": "false",
        "GMAIL_ENABLED": "true",
        "GMAIL_SENDER": "soc-test@example.com",
        "GMAIL_APP_PASSWORD": "test-only",
        "API_ALLOWED_HOSTS": "testserver,api,localhost,127.0.0.1",
        "API_ALLOWED_ORIGINS": "https://localhost",
        "AUTH_ALLOW_ADDITIONAL_REGISTRATION": "false",
        "MAX_CSV_UPLOAD_MB": "1",
        "MAX_EVE_UPLOAD_MB": "1",
    }
)

from fastapi.testclient import TestClient  # noqa: E402

import api  # noqa: E402
import auth_security  # noqa: E402


MAILS: list[tuple[str, str, str]] = []


def fake_mail(recipient: str, subject: str, body: str) -> tuple[bool, str]:
    MAILS.append((recipient, subject, body))
    return True, ""


auth_security.send_smtp_message = fake_mail
api.send_smtp_message = fake_mail


def latest_code(recipient: str) -> str:
    for mail_recipient, _, body in reversed(MAILS):
        if mail_recipient == recipient and "Votre code de verification" in body:
            match = re.search(r"\b(\d{6})\b", body)
            if match:
                return match.group(1)
    raise AssertionError(f"Aucun code trouve pour {recipient}")


def register(
    client: TestClient,
    *,
    full_name: str,
    username: str,
    email: str,
    password: str,
) -> dict:
    requested = client.post(
        "/auth/register/request-code",
        json={
            "full_name": full_name,
            "username": username,
            "email": email,
            "password": password,
        },
    )
    assert requested.status_code == 200, requested.text
    verified = client.post(
        "/auth/register/verify",
        json={
            "registration_id": requested.json()["registration_id"],
            "code": latest_code(email),
        },
    )
    assert verified.status_code == 200, verified.text
    return verified.json()


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def run() -> None:
    with TestClient(api.app) as client:
        status = client.get("/auth/status")
        assert status.status_code == 200
        assert status.json()["registration_enabled"] is True
        assert status.headers["cache-control"] == "no-store"
        assert client.get("/docs").status_code == 404

        allowed_preflight = client.options(
            "/auth/status",
            headers={
                "Origin": "https://localhost",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert allowed_preflight.headers.get("access-control-allow-origin") == (
            "https://localhost"
        )
        denied_preflight = client.options(
            "/auth/status",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert "access-control-allow-origin" not in denied_preflight.headers
        assert client.get("/", headers={"Host": "evil.example"}).status_code == 400
        assert client.get("/history").status_code == 401

        first = register(
            client,
            full_name="Sadik DASSAA",
            username="sadik",
            email="sadik@example.com",
            password="Solide12345",
        )
        token_one = first["access_token"]
        user_one = first["user"]
        assert user_one["role"] == "admin"
        assert client.get("/auth/status").json()["registration_enabled"] is False

        closed_registration = client.post(
            "/auth/register/request-code",
            json={
                "full_name": "Compte refuse",
                "username": "refuse",
                "email": "refuse@example.com",
                "password": "Solide12345",
            },
        )
        assert closed_registration.status_code == 403

        upload_one = client.post(
            "/analyze",
            headers=bearer(token_one),
            files={
                "file": (
                    "analyse.csv",
                    b"Label,Flow Duration\nDDoS,12\n",
                    "text/csv",
                )
            },
        )
        assert upload_one.status_code == 200, upload_one.text
        history_one = client.get("/history", headers=bearer(token_one)).json()["history"]
        assert len(history_one) == 1
        assert "user_id" not in history_one[0]
        history_id_one = history_one[0]["historique_id"]

        rejected_extension = client.post(
            "/analyze",
            headers=bearer(token_one),
            files={"file": ("payload.exe", b"not a csv", "application/octet-stream")},
        )
        assert rejected_extension.status_code == 415
        oversized = client.post(
            "/analyze",
            headers=bearer(token_one),
            files={"file": ("large.csv", b"x" * (1024 * 1024 + 1), "text/csv")},
        )
        assert oversized.status_code == 413

        os.environ["AUTH_ALLOW_ADDITIONAL_REGISTRATION"] = "true"
        second = register(
            client,
            full_name="Analyste Deux",
            username="analyste2",
            email="analyste2@example.com",
            password="Autre12345",
        )
        token_two = second["access_token"]
        assert second["user"]["role"] == "analyst"
        assert client.get("/history", headers=bearer(token_two)).json()["history"] == []
        cross_update = client.post(
            "/update-status",
            headers=bearer(token_two),
            json={"historique_id": history_id_one, "statut": "Traitee"},
        )
        assert cross_update.status_code == 404

        upload_two = client.post(
            "/analyze",
            headers=bearer(token_two),
            files={"file": ("deux.csv", b"Label\nPortScan\n", "text/csv")},
        )
        assert upload_two.status_code == 200, upload_two.text
        assert len(client.get("/history", headers=bearer(token_two)).json()["history"]) == 1
        assert len(client.get("/history", headers=bearer(token_one)).json()["history"]) == 1

        assert client.post("/metrics/traffic/reset").status_code == 401
        assert (
            client.get("/stats", headers=bearer(token_one)).json()[
                "flux_reseau_analyses"
            ]
            == 1
        )
        assert (
            client.get("/stats", headers=bearer(token_two)).json()[
                "flux_reseau_analyses"
            ]
            == 1
        )
        traffic_reset = client.post(
            "/metrics/traffic/reset",
            headers=bearer(token_one),
        )
        assert traffic_reset.status_code == 200, traffic_reset.text
        assert traffic_reset.json() == {
            "ancien_volume": 1,
            "nouveau_volume": 0,
            "message": "Le volume de trafic analyse a ete remis a zero.",
        }
        assert (
            client.get("/stats", headers=bearer(token_one)).json()[
                "flux_reseau_analyses"
            ]
            == 0
        )
        assert (
            client.get("/stats", headers=bearer(token_two)).json()[
                "flux_reseau_analyses"
            ]
            == 1
        )
        assert len(client.get("/history", headers=bearer(token_one)).json()["history"]) == 1

        changed = client.post(
            "/profile/password/change",
            headers=bearer(token_one),
            json={
                "current_password": "Solide12345",
                "new_password": "Nouveau12345",
            },
        )
        assert changed.status_code == 200, changed.text
        assert client.get("/auth/me", headers=bearer(token_one)).status_code == 401
        assert client.post(
            "/auth/login",
            json={"identifier": "sadik", "password": "Solide12345"},
        ).status_code == 401
        login_new = client.post(
            "/auth/login",
            json={"identifier": "sadik", "password": "Nouveau12345"},
        )
        assert login_new.status_code == 200, login_new.text
        token_one = login_new.json()["access_token"]

        reset_request = client.post(
            "/auth/password-reset/request-code",
            json={"email": "sadik@example.com"},
        )
        assert reset_request.status_code == 200
        reset = client.post(
            "/auth/password-reset/verify",
            json={
                "email": "sadik@example.com",
                "code": latest_code("sadik@example.com"),
                "new_password": "Final123456",
            },
        )
        assert reset.status_code == 200, reset.text
        assert client.get("/auth/me", headers=bearer(token_one)).status_code == 401
        final_login = client.post(
            "/auth/login",
            json={"identifier": "sadik", "password": "Final123456"},
        )
        assert final_login.status_code == 200, final_login.text
        final_token = final_login.json()["access_token"]

        events = client.get(
            "/profile/security-events",
            headers=bearer(final_token),
        )
        assert events.status_code == 200
        event_types = {item["event_type"] for item in events.json()["events"]}
        assert {
            "registration",
            "login",
            "password_change",
            "password_reset",
            "traffic_volume_reset",
        } <= event_types

        for _ in range(auth_security.LOGIN_MAX_FAILURES):
            failed = client.post(
                "/auth/login",
                json={"identifier": "intrus", "password": "Incorrect123"},
            )
            assert failed.status_code == 401
        blocked = client.post(
            "/auth/login",
            json={"identifier": "intrus", "password": "Incorrect123"},
        )
        assert blocked.status_code == 429

    with sqlite3.connect(os.environ["AUTH_DB_FILE"]) as connection:
        persisted_failures = int(
            connection.execute("SELECT COUNT(*) FROM login_failures").fetchone()[0]
        )
        assert persisted_failures >= auth_security.LOGIN_MAX_FAILURES

    print("SECURITY TESTS PASSED")
    print("- Authentification et inscription initiale securisee")
    print("- CORS, TrustedHost et en-tetes de securite")
    print("- Limites et formats d'upload")
    print("- Isolation des historiques entre utilisateurs")
    print("- Remise a zero isolee du volume de trafic")
    print("- Changement et reinitialisation du mot de passe")
    print("- Limitation persistante et journal d'audit")


if __name__ == "__main__":
    run()
