"""Login flow, tampered tokens, open redirect and configuration."""
import time
from dataclasses import replace
from urllib.parse import parse_qs, urlparse

import pytest

from conftest import APP_ID, BROKER_SECRET, broker_token, login, random_state, start_login
from predik_auth import AuthConfig, AuthConfigError, AuthError, safe_next, sign_link, sign_token, verify_link, verify_token


# ---------- gate ----------
def test_page_requires_login(client):
    r = client.get("/?REPORT_ID=a", follow_redirects=False)
    loc = urlparse(r.headers["location"])
    assert r.status_code == 302 and loc.path == "/auth/login" and parse_qs(loc.query)["next"] == ["/?REPORT_ID=a"]


def test_api_requires_login(client):
    assert client.get("/api/me").status_code == 401
    login(client)
    assert client.get("/api/me").json() == {"user": "ana@predikdata.com"}


# ---------- login flow ----------
def test_login_redirects_to_broker_with_state_cookie(client):
    r = client.get("/auth/login", params={"next": "/?REPORT_ID=x"}, follow_redirects=False)
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert urlparse(r.headers["location"]).netloc == "reports.example.test"
    assert q["app"] == [APP_ID] and q["next"] == ["/?REPORT_ID=x"] and len(q["state"][0]) >= 16
    assert "pa_state" in r.headers["set-cookie"] and "HttpOnly" in r.headers["set-cookie"]


def test_callback_sets_session_and_returns_to_next(client):
    state = start_login(client, "/?REPORT_ID=x")
    r = client.get("/auth/callback", params={"token": broker_token(state), "next": "/?REPORT_ID=x"},
                   follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/?REPORT_ID=x"
    assert any(c.startswith("pa_session=") and "Secure" in c and "HttpOnly" in c and "samesite=lax" in c.lower()
               for c in r.headers.get_list("set-cookie"))


@pytest.mark.parametrize("bad", ["state", "aud", "typ", "expired", "secret", "garbage"])
def test_callback_rejects_bad_tokens(client, bad):
    state = start_login(client)
    tok = {
        "state": lambda: broker_token(random_state()),               # minted for another browser
        "aud": lambda: broker_token(state, aud="otra-app"),          # token for another app
        "typ": lambda: broker_token(state, typ="session"),
        "expired": lambda: broker_token(state, exp=int(time.time()) - 120),
        "secret": lambda: broker_token(state, secret="z" * 40),      # not signed by the broker
        "garbage": lambda: "v1.garbage.garbage",
    }[bad]()
    r = client.get("/auth/callback", params={"token": tok}, follow_redirects=False)
    assert r.status_code == 403 and "pa_session" not in r.headers.get("set-cookie", "")
    assert client.get("/", follow_redirects=False).status_code == 302


def test_callback_without_state_cookie_is_rejected(client):
    r = client.get("/auth/callback", params={"token": broker_token(random_state())}, follow_redirects=False)
    assert r.status_code == 403


@pytest.mark.parametrize("nxt", ["//evil.com/x", "https://evil.com", "/\\evil.com", "javascript:alert(1)"])
def test_no_open_redirect(client, nxt):
    state = start_login(client)
    r = client.get("/auth/callback", params={"token": broker_token(state), "next": nxt}, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/"


def test_logout(client):
    login(client)
    client.get("/auth/logout")
    assert client.get("/", follow_redirects=False).status_code == 302


def test_forged_session_cookie_is_ignored(client):
    now = int(time.time())
    forged = sign_token(BROKER_SECRET, {"typ": "session", "sub": "x@y.com", "aud": APP_ID, "iat": now, "exp": now + 99})
    client.cookies.set("pa_session", forged)
    assert client.get("/", follow_redirects=False).status_code == 302


def test_allowed_domains(client):
    client.app.state.predik_auth = replace(client.app.state.predik_auth, allowed_domains=("predikdata.com",))
    state = start_login(client)
    r = client.get("/auth/callback", params={"token": broker_token(state, "intruso@gmail.com")},
                   follow_redirects=False)
    assert r.status_code == 403


# ---------- config: login can't be switched off in production ----------
GOOD = {"AUTH_APP_ID": "a", "AUTH_BROKER_SECRET": "b" * 32, "AUTH_SESSION_SECRET": "s" * 32}


def test_config_requires_secrets():
    with pytest.raises(AuthConfigError):
        AuthConfig.from_env({})
    with pytest.raises(AuthConfigError):
        AuthConfig.from_env({**GOOD, "AUTH_BROKER_SECRET": "short"})
    assert AuthConfig.from_env(GOOD).mode == "sso"


def test_dev_mode_forbidden_in_production():
    assert AuthConfig.from_env({"AUTH_MODE": "dev"}).mode == "dev"
    with pytest.raises(AuthConfigError):
        AuthConfig.from_env({"AUTH_MODE": "dev", "APP_ENV": "production"})
    with pytest.raises(AuthConfigError):
        AuthConfig.from_env({**GOOD, "APP_ENV": "production", "AUTH_COOKIE_SECURE": "false"})


# ---------- primitives ----------
def test_token_roundtrip_and_tamper():
    tok = sign_token("k" * 32, {"typ": "t", "sub": "a@b.c", "aud": "x", "iat": 1, "exp": 4e9})
    assert verify_token("k" * 32, tok, typ="t", aud="x")["sub"] == "a@b.c"
    v, p, s = tok.split(".")
    for bad in (f"{v}.{p}x.{s}", f"{v}.{p}.{s[:-2]}AA", "v2." + p + "." + s, ""):
        with pytest.raises(AuthError):
            verify_token("k" * 32, bad, typ="t", aud="x")


def test_safe_next():
    assert safe_next("/a?b=1#c") == "/a?b=1#c"
    for bad in ("", "a", "//x", "/\\x", "http://x", "/a\r\nSet-Cookie: x"):
        assert safe_next(bad) == "/"


def test_signed_links():
    exp = int(time.time()) + 60
    sig = sign_link("k" * 32, ["r", "c", "1"], exp)
    assert verify_link("k" * 32, sig, ["r", "c", "1"], exp)
    assert not verify_link("k" * 32, sig, ["r", "otro", "1"], exp)
    assert not verify_link("k" * 32, sign_link("k" * 32, ["r"], 1), ["r"], 1)  # expired
    assert verify_link(None, sig, ["r"]) is False
