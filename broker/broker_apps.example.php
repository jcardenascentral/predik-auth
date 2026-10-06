<?php
/**
 * Apps allowed to log in through broker.php. Copy to saml2/settings/broker_apps.php (NOT in git).
 *
 * One entry per app:
 *   - callback: the app's /auth/callback URL (fixed here, never taken from the request).
 *   - secret:   the same value as AUTH_BROKER_SECRET in that app (>= 32 chars, one per app).
 *               Market Model: SSM parameter /market-model/auth-broker-secret.
 */
return [
    'marketmodel' => [
        'callback' => 'https://marketmodel.predikdata.com/auth/callback',
        'secret'   => getenv('BROKER_SECRET_MARKETMODEL'),
    ],
    // 'otra-app' => [
    //     'callback' => 'https://otra-app.predikdata.com/auth/callback',
    //     'secret'   => getenv('BROKER_SECRET_OTRA_APP'),
    // ],
];
