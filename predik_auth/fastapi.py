"""FastAPI / Starlette integration: /auth/login, /auth/callback, /auth/logout and helpers.

    from predik_auth import AuthConfig, install, current_user, login_redirect
    auth = install(app, AuthConfig.from_env())

    @app.get("/")
    def index(request: Request):
        if not current_user(request):
            return login_redirect(request)
        ...
"""
from __future__ import annotations

import html
import secrets
import time
from urllib.parse import urlencode

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .core import AuthConfig, AuthError, safe_next, sign_token, verify_token

STATE_COOKIE = "pa_state"
STATE_TTL = 600


def _page(title: str, msg: str, status: int, link: tuple[str, str] | None = None) -> HTMLResponse:
    a = f'<p style="margin:16px 0 0"><a href="{html.escape(link[0])}">{html.escape(link[1])}</a></p>' if link else ""
    body = f"""<!doctype html><meta charset="utf-8"><title>{html.escape(title)}</title>
<body style="font-family:Poppins,system-ui,sans-serif;background:#f4f4f4;margin:0;display:grid;place-items:center;min-height:100vh">
<div style="background:#fff;border:1px solid #e2e2e2;border-top:3px solid #C8102E;border-radius:6px;padding:28px 32px;max-width:520px">
<h2 style="margin:0 0 8px">{html.escape(title)}</h2><p style="margin:0;color:#555">{html.escape(msg)}</p>{a}</div></body>"""
    return HTMLResponse(body, status_code=status, headers={"Cache-Control": "no-store"})


def current_user(request: Request) -> str | None:
    """Email of the logged-in user, or None."""
    cfg: AuthConfig = request.app.state.predik_auth
    if cfg.mode == "dev":
        return cfg.dev_user
    raw = request.cookies.get(cfg.cookie_name)
    if not raw:
        return None
    try:
        return verify_token(cfg.session_secret, raw, typ="session", aud=cfg.app_id)["sub"]
    except AuthError:
        return None


def login_redirect(request: Request) -> RedirectResponse:
    """Send the browser to the login, coming back to the current URL afterwards."""
    here = request.url.path + (f"?{request.url.query}" if request.url.query else "")
    return RedirectResponse("/auth/login?" + urlencode({"next": here}), status_code=302)


def install(app: FastAPI, cfg: AuthConfig, prefix: str = "/auth") -> AuthConfig:
    app.state.predik_auth = cfg  # single source of truth, read on every request

    @app.get(f"{prefix}/login", include_in_schema=False)
    def auth_login(request: Request, next: str = "/"):
        cfg: AuthConfig = request.app.state.predik_auth
        nxt = safe_next(next)
        if cfg.mode == "dev":
            return RedirectResponse(nxt, status_code=302)
        state = secrets.token_urlsafe(24)
        url = cfg.broker_url + "?" + urlencode({"app": cfg.app_id, "state": state, "next": nxt})
        resp = RedirectResponse(url, status_code=302, headers={"Cache-Control": "no-store"})
        resp.set_cookie(STATE_COOKIE, state, max_age=STATE_TTL, path=prefix, httponly=True,
                        secure=cfg.cookie_secure, samesite="lax")
        return resp

    @app.get(f"{prefix}/callback", include_in_schema=False)
    def auth_callback(request: Request, token: str = "", next: str = "/"):
        cfg: AuthConfig = request.app.state.predik_auth
        retry = (f"{prefix}/login?" + urlencode({"next": safe_next(next)}), "Intentar de nuevo")
        if cfg.mode == "dev":
            return RedirectResponse(safe_next(next), status_code=302)
        try:
            claims = verify_token(cfg.broker_secret, token, typ="broker", aud=cfg.app_id)
        except AuthError:
            return _page("No se pudo iniciar sesión", "El inicio de sesión no es válido o expiró.", 403, retry)
        state = request.cookies.get(STATE_COOKIE) or ""
        if not state or not secrets.compare_digest(str(claims.get("state", "")), state):
            return _page("No se pudo iniciar sesión", "El inicio de sesión no corresponde a este navegador.", 403, retry)
        email = claims["sub"].strip().lower()
        if not cfg.email_allowed(email):
            return _page("Acceso denegado", f"El usuario {email} no tiene acceso a esta aplicación.", 403)
        now = int(time.time())
        session = sign_token(cfg.session_secret, {"typ": "session", "sub": email, "aud": cfg.app_id,
                                                  "iat": now, "exp": now + cfg.session_ttl})
        resp = RedirectResponse(safe_next(next), status_code=302, headers={"Cache-Control": "no-store"})
        resp.set_cookie(cfg.cookie_name, session, max_age=cfg.session_ttl, path="/", httponly=True,
                        secure=cfg.cookie_secure, samesite="lax")
        resp.delete_cookie(STATE_COOKIE, path=prefix)
        return resp

    @app.get(f"{prefix}/logout", include_in_schema=False)
    def auth_logout(request: Request):
        cfg: AuthConfig = request.app.state.predik_auth
        resp = _page("Sesión cerrada", "Cerraste sesión en esta aplicación.", 200, (f"{prefix}/login", "Entrar de nuevo"))
        resp.delete_cookie(cfg.cookie_name, path="/")
        return resp

    return cfg
