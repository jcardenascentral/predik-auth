<?php
/**
 * Signed links: let a report open an app WITHOUT login, only for that report's scope.
 * Same algorithm as predik_auth.sign_link (Python): hex HMAC-SHA256 of "part1|part2|...|exp".
 *
 *   require_once 'predik_link.php';
 *   $url = predik_app_link('https://siteselector.predikdata.com', getenv('SITESELECTOR_LINK_SECRET'),
 *                          $report_id, $client_code, $variant, 86400);
 */

function predik_sign_link($secret, array $parts, $exp = null)
{
    if ($exp !== null) {
        $parts[] = (string)(int)$exp;
    }
    return hash_hmac('sha256', implode('|', $parts), $secret);
}

/** Link to any Predik app. $ttl seconds of validity (null = never expires; not recommended). */
function predik_app_link($base_url, $secret, $report_id, $client_code, $variant, $ttl = 86400)
{
    $exp = $ttl === null ? null : time() + (int)$ttl;
    $params = [
        'REPORT_ID' => $report_id,
        'CLIENT_CODE' => $client_code,
        'VARIANT' => (string)$variant,
    ];
    if ($exp !== null) {
        $params['EXP'] = $exp;
    }
    $params['SIG'] = predik_sign_link($secret, [$report_id, $client_code, (string)$variant], $exp);
    return rtrim($base_url, '/') . '/?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
}

/** Kept for the existing Market Model reports. */
function predik_market_model_link($base_url, $secret, $report_id, $client_code, $variant, $ttl = 86400)
{
    return predik_app_link($base_url, $secret, $report_id, $client_code, $variant, $ttl);
}
