<?php
/**
 * Predik SSO broker - lets apps on other hosts (marketmodel.predikdata.com, ...) reuse the SAML login
 * (AWS IAM Identity Center) of reports.predikdata.com.
 *
 * Deploy as https://reports.predikdata.com/saml2/broker.php, next to login.php / acs.php.
 *
 *   GET broker.php?app=<app id>&state=<random from the app>&next=<path in the app>
 *
 * 1. No SAML session yet -> same flow as the other apps (/saml2/login.php, back here afterwards).
 * 2. With a session -> redirects to the app's registered callback with a token valid for 60 s:
 *      v1.<base64url(json)>.<base64url(HMAC-SHA256(app secret, "v1." + base64url(json)))>
 *    claims: typ=broker, sub=email, aud=app id, state, iat, exp.
 *
 * The callback URL comes from settings/broker_apps.php, never from the request (no open redirect).
 */
if (isset($_COOKIE['CENTRALAMERICADATA_ADMIN'])) {
    session_id($_COOKIE['CENTRALAMERICADATA_ADMIN']);
}
session_start([
    'cookie_lifetime' => 86400
]);

$apps = require __DIR__ . '/settings/broker_apps.php';

function broker_fail($status, $msg)
{
    http_response_code($status);
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    echo $msg;
    exit;
}

function broker_b64url($bin)
{
    return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
}

$app_id = isset($_GET['app']) ? (string)$_GET['app'] : '';
$state = isset($_GET['state']) ? (string)$_GET['state'] : '';
$next = isset($_GET['next']) ? (string)$_GET['next'] : '/';

if (!isset($apps[$app_id])) {
    broker_fail(400, 'Unknown app');
}
$app = $apps[$app_id];
if (empty($app['callback']) || !is_string($app['secret'] ?? null) || strlen($app['secret']) < 32) {
    broker_fail(500, 'Broker misconfigured for this app');
}
if (!preg_match('/^[A-Za-z0-9_-]{16,128}$/', $state)) {
    broker_fail(400, 'Bad state');
}
// Only a path inside the app (the app validates it again).
if ($next === '' || $next[0] !== '/' || strlen($next) > 4096
    || (strlen($next) > 1 && ($next[1] === '/' || $next[1] === '\\'))) {
    $next = '/';
}

if (!isset($_SESSION['saml_user'])) {
    $_SESSION['redirect_uri'] = $_SERVER['REQUEST_URI'];
    header('Location: /saml2/login.php');
    exit;
}

$email = $_SESSION['saml_user']['attributes']['email'][0] ?? '';
if ($email === '') {
    broker_fail(403, 'The SAML session has no email attribute');
}

$now = time();
$payload = broker_b64url(json_encode([
    'typ' => 'broker',
    'sub' => strtolower($email),
    'aud' => $app_id,
    'state' => $state,
    'iat' => $now,
    'exp' => $now + 60,
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
$token = 'v1.' . $payload . '.' . broker_b64url(hash_hmac('sha256', 'v1.' . $payload, $app['secret'], true));

header('Cache-Control: no-store');
header('Referrer-Policy: no-referrer');
header('Location: ' . $app['callback'] . '?' . http_build_query(['token' => $token, 'next' => $next], '', '&', PHP_QUERY_RFC3986));
exit;
