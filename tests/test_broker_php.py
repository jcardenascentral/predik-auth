"""End-to-end: the real predik_auth/broker/broker.php (served by `php -S`) logs a user into the app.

login.php is replaced by a stub that plays the SAML ACS: it fills $_SESSION['saml_user'] and goes
back to $_SESSION['redirect_uri'], exactly like the existing saml2 flow does after Identity Center.
"""
import os
import shutil
import socket
import subprocess
import time
from dataclasses import replace
from urllib.parse import urlparse

import httpx
import pytest

from conftest import APP_ID, BROKER_SECRET, ROOT

pytestmark = [pytest.mark.skipif(not shutil.which("php"), reason="php not installed")]

LOGIN_STUB = """<?php
session_start(['cookie_lifetime' => 86400]);
$_SESSION['saml_user'] = ['attributes' => ['email' => ['Ana.Perez@PredikData.com']]];
header('Location: ' . $_SESSION['redirect_uri']);
"""
APPS = """<?php
return [
    'demoapp' => ['callback' => 'https://testserver/auth/callback', 'secret' => getenv('BROKER_SECRET_DEMOAPP')],
    'weak' => ['callback' => 'https://testserver/auth/callback', 'secret' => 'short'],
];
"""


@pytest.fixture(scope="module")
def broker(tmp_path_factory):
    root = tmp_path_factory.mktemp("php")
    saml2 = root / "saml2"
    (saml2 / "settings").mkdir(parents=True)
    shutil.copy(ROOT / "broker" / "broker.php", saml2 / "broker.php")
    (saml2 / "login.php").write_text(LOGIN_STUB)
    (saml2 / "settings" / "broker_apps.php").write_text(APPS)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    sess = root / "sessions"
    sess.mkdir()
    proc = subprocess.Popen(["php", "-d", f"session.save_path={sess}", "-S", f"127.0.0.1:{port}", "-t", str(root)],
                            env={**os.environ, "BROKER_SECRET_DEMOAPP": BROKER_SECRET},
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            httpx.get(base + "/saml2/none")
            break
        except httpx.TransportError:
            time.sleep(0.1)
    yield base
    proc.terminate()
    proc.wait()


@pytest.fixture
def app_client(client, broker):
    cfg = client.app.state.predik_auth
    client.app.state.predik_auth = replace(cfg, broker_url=broker + "/saml2/broker.php")
    yield client
    client.app.state.predik_auth = cfg


def test_full_login_through_php_broker(app_client, broker):
    php = httpx.Client(base_url=broker)  # the user's browser on reports.predikdata.com
    nxt = "/?REPORT_ID=a&CLIENT_CODE=b&VARIANT=1"

    r = app_client.get("/", params={"REPORT_ID": "a", "CLIENT_CODE": "b", "VARIANT": "1"}, follow_redirects=False)
    r = app_client.get(r.headers["location"], follow_redirects=False)           # /auth/login
    assert r.headers["location"].startswith(broker + "/saml2/broker.php?app=demoapp")

    r = php.get(r.headers["location"])                                          # broker: no SAML session yet
    assert r.status_code == 302 and r.headers["location"] == "/saml2/login.php"
    r = php.get("/saml2/login.php")                                             # "Identity Center" + ACS
    r = php.get(r.headers["location"])                                          # back to the broker
    cb = urlparse(r.headers["location"])
    assert r.status_code == 302 and f"{cb.scheme}://{cb.netloc}{cb.path}" == "https://testserver/auth/callback"
    assert r.headers["cache-control"] == "no-store"

    r = app_client.get(f"{cb.path}?{cb.query}", follow_redirects=False)       # app validates the PHP token
    assert r.status_code == 302 and r.headers["location"] == nxt
    assert app_client.get(nxt, follow_redirects=False).status_code == 200

    assert app_client.get("/api/me").json() == {"user": "ana.perez@predikdata.com"}


def test_already_logged_in_on_reports_is_silent(app_client, broker):
    php = httpx.Client(base_url=broker)
    php.get("/saml2/login.php", follow_redirects=False)  # existing SAML session on reports.predikdata.com
    r = app_client.get("/auth/login", follow_redirects=False)
    r = php.get(r.headers["location"])
    assert "/auth/callback?token=" in r.headers["location"]  # no extra login prompt


@pytest.mark.parametrize("query,status", [
    ({"app": "nope", "state": "x" * 20}, 400),
    ({"app": APP_ID, "state": "bad state!"}, 400),
    ({"app": "weak", "state": "x" * 20}, 500),
])
def test_broker_rejects_bad_requests(broker, query, status):
    assert httpx.get(broker + "/saml2/broker.php", params=query).status_code == status


def test_broker_never_redirects_outside_the_app(broker):
    php = httpx.Client(base_url=broker)
    php.get("/saml2/login.php", follow_redirects=False)
    r = php.get("/saml2/broker.php", params={"app": APP_ID, "state": "x" * 20, "next": "//evil.com"})
    loc = urlparse(r.headers["location"])
    assert loc.netloc == "testserver" and "next=%2F" in loc.query and "evil" not in loc.query


def test_php_link_signature_matches_python(tmp_path):
    from predik_auth import verify_link
    script = tmp_path / "s.php"
    script.write_text(f"""<?php require '{ROOT / "broker" / "predik_link.php"}';
echo predik_app_link('https://mm.test', 'secret-xyz', 'rep 1', 'cli&2', 1, 3600);""")
    url = subprocess.run(["php", str(script)], capture_output=True, text=True, check=True).stdout
    q = dict(httpx.URL(url).params)
    assert verify_link("secret-xyz", q["SIG"], [q["REPORT_ID"], q["CLIENT_CODE"], q["VARIANT"]], q["EXP"])
    assert q["CLIENT_CODE"] == "cli&2" and q["REPORT_ID"] == "rep 1"
