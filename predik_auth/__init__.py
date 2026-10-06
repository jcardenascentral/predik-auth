"""predik_auth: mandatory login for Predik web apps, reusing the SAML (AWS IAM Identity Center)
session of reports.predikdata.com through a small PHP broker. See README.md.

Install:  pip install "predik-auth @ git+https://github.com/jcardenascentral/predik-auth@v1.0.0"
Only depends on fastapi.
"""
from .core import (
    AuthConfig,
    AuthConfigError,
    AuthError,
    safe_next,
    sign_link,
    sign_token,
    verify_link,
    verify_token,
)
from .fastapi import current_user, install, login_redirect

__version__ = "1.0.0"

__all__ = ["AuthConfig", "AuthConfigError", "AuthError", "current_user", "install", "login_redirect",
           "safe_next", "sign_link", "sign_token", "verify_link", "verify_token"]
