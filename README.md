# predik-auth — login obligatorio para apps de Predik

Reutiliza el login SAML (AWS IAM Identity Center) que ya existe en `reports.predikdata.com`, para apps
en otros hosts (`marketmodel.predikdata.com`, ...). Usa un **broker central en PHP**: hay una sola app
SAML en Identity Center y los usuarios son los mismos de AWS.

```
navegador ──> app /                    sin sesión
          <── 302 /auth/login?next=/?REPORT_ID=...
          ──> app /auth/login           genera state (cookie pa_state, 10 min)
          <── 302 reports.predikdata.com/saml2/broker.php?app=marketmodel&state=..&next=..
          ──> broker.php                sin $_SESSION['saml_user'] → /saml2/login.php → Identity Center
                                        (el mismo flujo de las otras apps; si ya hay sesión, no pide nada)
          <── 302 app/auth/callback?token=v1.<claims>.<HMAC>&next=..   (token válido 60 s)
          ──> app /auth/callback        valida firma, aud, exp y state == cookie
          <── 302 next + cookie pa_session (firmada, HttpOnly, Secure, SameSite=Lax, 12 h)
```

**Bypass (el único):** un *link firmado* (`SIG` = HMAC de los parámetros + `EXP`) abre **solo ese
reporte** sin login, como `interno_no_user@predikdata.com`. Reemplaza el chequeo por `Referer`, que se
puede falsificar con un header.

## Seguridad

- **Token del broker:** está firmado con un secreto *por app*, lleva `aud` = id de la app, expira a los 60 s
  y va atado al `state` de la cookie del navegador. Así no sirve en otra app ni en otro navegador (evita el login CSRF).
- **Callback:** la URL de callback la fija `settings/broker_apps.php`; nunca se toma de la petición.
- **`next`:** solo se aceptan rutas relativas (`/x`) y se rechazan `//host` y `/\host`. Así no hay open redirect.
- **Sesión:** es una cookie firmada y sin estado del lado del servidor. Funciona con varias instancias
  (o procesos) sin Redis ni base de datos.
- **Producción:** con `APP_ENV=production`, la app **no arranca** si faltan los secretos o si `AUTH_MODE=dev`.

## Agregar el login a otra app (FastAPI)

1. Agrega la librería a `requirements.txt` (fija la versión con un tag). Solo depende de `fastapi`:
   ```text
   predik-auth @ git+https://github.com/jcardenascentral/predik-auth@v1.0.0
   ```
2. En la app:
   ```python
   from predik_auth import AuthConfig, install, current_user, login_redirect

   app = FastAPI()
   install(app, AuthConfig.from_env())        # /auth/login, /auth/callback, /auth/logout

   @app.get("/")
   def index(request: Request):
       if not current_user(request):           # email del usuario o None
           return login_redirect(request)
       ...

   @app.get("/api/algo")
   def algo(request: Request):
       if not current_user(request):
           raise HTTPException(401)
   ```
3. Configura las variables de entorno. Los secretos vienen de SSM y deben tener al menos 32 caracteres:
   `openssl rand -hex 32`.

   | Variable | Valor |
   |---|---|
   | `AUTH_APP_ID` | id de la app en el broker (`marketmodel`) |
   | `AUTH_BROKER_URL` | `https://reports.predikdata.com/saml2/broker.php` (default) |
   | `AUTH_BROKER_SECRET` | el mismo valor que en `broker_apps.php` para esa app |
   | `AUTH_SESSION_SECRET` | firma la cookie de sesión (propio de la app) |
   | `AUTH_SESSION_TTL_SECONDS` | default 43200 (12 h) |
   | `AUTH_ALLOWED_EMAIL_DOMAINS` | opcional: `predikdata.com` (si está vacío, entra cualquier usuario del Identity Center) |
   | `AUTH_MODE=dev` | solo desarrollo local: sin login, el usuario es `AUTH_DEV_USER` |

4. En el broker, agrega la app a `saml2/settings/broker_apps.php`:
   ```php
   'otra-app' => ['callback' => 'https://otra-app.predikdata.com/auth/callback',
                  'secret'   => getenv('BROKER_SECRET_OTRA_APP')],
   ```

## Instalar el broker (una vez, en reports.predikdata.com)

1. Copia `broker/broker.php` a `saml2/broker.php`, junto a `login.php` y `acs.php`.
2. Copia `broker/broker_apps.example.php` a `saml2/settings/broker_apps.php` y define
   `BROKER_SECRET_MARKETMODEL` en el entorno de PHP. Este archivo no va en git.
3. Hay que verificar que `acs.php`, tras un login correcto, redirija a `$_SESSION['redirect_uri']`.
   Es el mismo supuesto del snippet actual; el broker lo usa para volver a sí mismo.
4. Para links sin login desde los reportes, usa `broker/predik_link.php`:
   `predik_app_link($base, $secret, $report_id, $client_code, $variant, 86400)`.
   El `$secret` es el `LINK_SIGNING_SECRET` de la app.

## Versiones

Cada cambio se publica con un tag (`v1.0.1`, `v1.1.0`...). Las apps suben de versión en un PR, y su CI
prueba el login antes de desplegar. Un fix de seguridad = un tag nuevo + un PR por app.

## Tests

```bash
pip install -e ".[test]" && pytest -q
```

`tests/test_auth.py` cubre el flujo con una app FastAPI mínima, los tokens alterados o vencidos, el open
redirect y la configuración.

`tests/test_broker_php.py` (requiere `php`) levanta el `broker.php` real con `php -S`, simula el ACS y prueba el login
completo de punta a punta. También prueba que la firma de links de PHP y la de Python coinciden.
