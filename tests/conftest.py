"""A minimal FastAPI app protected by predik_auth (the same wiring every Predik app uses)."""
from __future__ import annotations

import secrets
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from predik_auth import AuthConfig, current_user, install, login_redirect, sign_token

ROOT = Path(__file__).resolve().parents[1]
APP_ID = "demoapp"
BROKER_SECRET = "b" * 40
SESSION_SECRET = "s" * 40
ENV = {"AUTH_APP_ID": APP_ID, "AUTH_BROKER_URL": "https://reports.example.test/saml2/broker.php",
       "AUTH_BROKER_SECRET": BROKER_SECRET, "AUTH_SESSION_SECRET": SESSION_SECRET}


def make_app(env: dict | None = None) -> FastAPI:
    app = FastAPI()
    install(app, AuthConfig.from_env(env or ENV))

    @app.get("/")
    def index(request: Request):
        user = current_user(request)
        return login_redirect(request) if not user else {"user": user}

    @app.get("/api/me")
    def me(request: Request):
        user = current_user(request)
        if not user:
            raise HTTPException(401, "login_required")
        return {"user": user}

    return app


@pytest.fixture
def client():
    return TestClient(make_app(), base_url="https://testserver")  # https: the session cookie is Secure


def broker_token(state: str, email: str = "ana@predikdata.com", secret: str = BROKER_SECRET, **over) -> str:
    """What the PHP broker sends back (claims can be overridden to forge bad tokens)."""
    now = int(time.time())
    claims = {"typ": "broker", "sub": email, "aud": APP_ID, "state": state, "iat": now, "exp": now + 60, **over}
    return sign_token(secret, claims)


def start_login(client, next_url: str = "/") -> str:
    r = client.get("/auth/login", params={"next": next_url}, follow_redirects=False)
    assert r.status_code == 302
    return parse_qs(urlparse(r.headers["location"]).query)["state"][0]


def login(client, email: str = "ana@predikdata.com") -> None:
    state = start_login(client)
    r = client.get("/auth/callback", params={"token": broker_token(state, email), "next": "/"},
                   follow_redirects=False)
    assert r.status_code == 302, r.text


def random_state() -> str:
    return secrets.token_urlsafe(24)
