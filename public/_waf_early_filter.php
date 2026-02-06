<?php

/**
 * WAF Early Filter - runs before Silverstripe framework loads
 *
 * Include this from public/index.php BEFORE the framework bootstrap:
 *
 *     // Early WAF filter (before framework loads)
 *     $wafFilter = dirname(__DIR__) . '/vendor/restruct/silverstripe-waf/public/_waf_early_filter.php';
 *     if (file_exists($wafFilter)) {
 *         require_once $wafFilter;
 *     }
 *
 * Features:
 * - Pattern-based URL blocking (WordPress, webshells, config files)
 * - Random PHP probe detection
 * - Fail2ban-compatible logging
 * - Minimal overhead (no framework dependencies)
 *
 * @package Restruct\SilverStripe\Waf
 */

// Skip if disabled via environment
if (getenv('WAF_EARLY_FILTER_DISABLED') === 'true') {
    return;
}

// ============================================================================
// CONFIGURATION
// Can be overridden via environment variables
// ============================================================================

$blockedPatterns = [
    // WordPress probes
    '/wp-admin',
    '/wp-login',
    '/wp-content',
    '/wp-includes',
    '/xmlrpc.php',
    '/wp-config',

    // PHP backdoor/webshell paths
    '/eval-stdin.php',
    '/alfacgiapi',
    '/alfa-rex',
    '/shell.php',
    '/c99.php',
    '/r57.php',
    '/wso.php',
    '/b374k',
    '/webadmin.php',

    // Config/sensitive file probes
    '/.env',
    '/.git',
    '/.svn',
    '/.htpasswd',
    '/.htaccess',
    '/config.php',
    '/configuration.php',
    '/LocalSettings.php',
    '/web.config',
    '/settings.php',
    '/config.inc.php',
    '/db.php',
    '/database.php',

    // Other CMS probes
    '/administrator/index.php',
    '/phpmyadmin',
    '/pma/',
    '/myadmin/',
    '/adminer',
    '/manager/html',

    // Path traversal attempts
    '../',
    '..%2f',
    '..%252f',
    '%2e%2e/',
    '%252e%252e/',
];

// Pattern for random PHP file probes (common webshell naming)
$suspiciousPhpPattern = '/^\/[a-z0-9_]{2,8}\.php$/i';

// Legitimate short PHP files (whitelist)
$legitimatePhpFiles = [
    '/index.php',
];

// Whitelisted IPs (comma-separated via environment, or array here)
$whitelistedIps = [];
if ($envWhitelist = getenv('WAF_WHITELIST_IPS')) {
    $whitelistedIps = array_map('trim', explode(',', $envWhitelist));
}

// ============================================================================
// FILTER LOGIC
// ============================================================================

$uri = $_SERVER['REQUEST_URI'] ?? '';
$uriPath = parse_url($uri, PHP_URL_PATH) ?? '';
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';

// Skip whitelisted IPs
if (in_array($ip, $whitelistedIps, true)) {
    return;
}

// Check blocked URL patterns
foreach ($blockedPatterns as $pattern) {
    if (stripos($uri, $pattern) !== false) {
        wafLogAndBlock('blocked_pattern', $pattern, $ip, $uri, $userAgent);
    }
}

// Check for random PHP file probes
if (preg_match($suspiciousPhpPattern, $uriPath)) {
    if (!in_array($uriPath, $legitimatePhpFiles, true)) {
        wafLogAndBlock('php_probe', $uriPath, $ip, $uri, $userAgent);
    }
}

// Check for empty user-agent (most scanners)
// Uncomment to enable - may block some legitimate tools
// if (empty($userAgent)) {
//     wafLogAndBlock('empty_useragent', 'empty', $ip, $uri, $userAgent);
// }

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Log the blocked request and return 403
 *
 * Log format is fail2ban-compatible:
 * [WAF] BLOCKED reason=X pattern=X ip=X uri=X
 */
function wafLogAndBlock(
    string $reason,
    string $pattern,
    string $ip,
    string $uri,
    string $userAgent
): never {
    // Sanitize for logging (prevent log injection)
    $safeUri = preg_replace('/[^\x20-\x7E]/', '', substr($uri, 0, 200));
    $safePattern = preg_replace('/[^\x20-\x7E]/', '', substr($pattern, 0, 100));
    $safeUserAgent = preg_replace('/[^\x20-\x7E]/', '', substr($userAgent, 0, 200));

    // Log in fail2ban-compatible format
    error_log(sprintf(
        '[WAF] BLOCKED reason=%s pattern="%s" ip=%s uri="%s" ua="%s"',
        $reason,
        $safePattern,
        $ip,
        $safeUri,
        $safeUserAgent
    ));

    // Return 403 Forbidden (or 404 to be less revealing)
    http_response_code(403);

    // Minimal response to save bandwidth
    header('Content-Type: text/plain; charset=utf-8');
    header('Connection: close');
    header('Cache-Control: no-store, no-cache, must-revalidate');

    exit('Forbidden');
}
