<?php

/**
 * WAF Early Filter - runs before Silverstripe framework loads
 *
 * Include this from public/index.php BEFORE the framework bootstrap:
 *
 *     $wafFilter = dirname(__DIR__) . '/vendor/restruct/silverstripe-waf/_waf_early_filter.php';
 *     if (file_exists($wafFilter)) {
 *         require_once $wafFilter;
 *     }
 *
 * Features:
 * - Pattern-based URL blocking (WordPress, webshells, config files, scanners)
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
// Override via environment: WAF_DETECT_PATH_PROBES=false, etc.
// ============================================================================

$config = [
    'detect_path_probes' => getenv('WAF_DETECT_PATH_PROBES') !== 'false',
    'detect_php_probes'  => getenv('WAF_DETECT_PHP_PROBES') !== 'false',
];

// ============================================================================
// BLOCKED PATH PATTERNS (organized by category)
// ============================================================================

$blockedPaths = [
    // WordPress probes
    '/wp-admin', '/wp-login', '/wp-content', '/wp-includes',
    '/xmlrpc.php', '/wp-config', '/wp-cron.php', '/wp-json',
    '/wp-load.php', '/wp-settings.php', '/wp-trackback.php',

    // Joomla probes
    '/administrator/index.php', '/administrator/manifests',
    '/components/com_', '/modules/mod_', '/plugins/system',
    '/htaccess.txt',

    // Drupal probes
    '/sites/default/files', '/sites/all/modules',
    '/misc/drupal.js', '/core/install.php',
    '/update.php', '/cron.php',

    // Magento probes
    '/downloader/', '/app/etc/local.xml', '/var/export/',
    '/skin/adminhtml/', '/js/mage/',

    // Laravel probes
    '/storage/logs/', '/bootstrap/cache/', '/.env.backup',
    '/artisan', '/storage/framework/',

    // PHP backdoors/webshells
    '/eval-stdin.php', '/alfacgiapi', '/alfa-rex',
    '/shell.php', '/c99.php', '/r57.php', '/wso.php',
    '/b374k', '/webadmin.php', '/FilesMan',
    '/WSO.php', '/mini.php', '/leaf.php',
    '/indoxploit', '/adminer.php', '/0x.php',

    // Config/sensitive files
    '/.env', '/.git', '/.svn', '/.hg',
    '/.htpasswd', '/.htaccess', '/.DS_Store',
    '/config.php', '/configuration.php', '/LocalSettings.php',
    '/web.config', '/settings.php', '/config.inc.php',
    '/db.php', '/database.php', '/conn.php', '/connect.php',
    '/config.yml', '/config.yaml', '/parameters.yml',
    '/.aws/', '/.ssh/', '/.bash_history',
    '/id_rsa', '/id_dsa', '/.npmrc', '/.dockerenv',
    '/composer.json', '/composer.lock', '/package.json',
    '/Gemfile', '/Gemfile.lock', '/Rakefile',
    '/.travis.yml', '/.gitlab-ci.yml', '/Jenkinsfile',
    '/phpunit.xml', '/phpcs.xml', '/.phpcs.xml',
    '/codeception.yml', '/behat.yml',

    // Database tools
    '/phpmyadmin', '/pma/', '/myadmin/', '/mysql/',
    '/adminer', '/dbadmin/', '/phpMyAdmin/',
    '/sql/', '/database/', '/db/',

    // Server management
    '/manager/html', '/manager/status',
    '/server-status', '/server-info',
    '/cgi-bin/', '/fcgi-bin/',
    '/cpanel', '/plesk', '/webmin',

    // Common scanner paths
    '/admin.php', '/login.php', '/test.php', '/info.php',
    '/phpinfo.php', '/i.php', '/pi.php', '/php.php',
    '/debug.php', '/console/', '/telescope/',
    '/_profiler/', '/_wdt/', '/elmah.axd',
    '/trace.axd', '/glimpse.axd',

    // Backup files
    '.bak', '.backup', '.old', '.orig',
    '.save', '.swp', '.tmp', '~',
    '.sql', '.tar', '.tar.gz', '.zip',
    '.rar', '.7z', '.gz', '.tgz',

    // API/debug endpoints
    '/api/debug', '/api/test',
    '/__debug__/', '/_debug/', '/debug/',
    '/actuator/', '/metrics', '/health',

    // Path traversal
    '../', '..%2f', '..%252f',
    '%2e%2e/', '%252e%252e/',
    '..\\', '..%5c', '..%255c',
    '%c0%ae', '%c1%9c',
];

// ============================================================================
// WHITELISTED IPs
// ============================================================================

$whitelistedIps = [];
if ($envWhitelist = getenv('WAF_WHITELIST_IPS')) {
    $whitelistedIps = array_map('trim', explode(',', $envWhitelist));
}

// Legitimate short PHP files (for random probe detection)
$legitimatePhpFiles = [
    '/index.php',
];

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

// 1. Path-based blocking
if ($config['detect_path_probes']) {
    $uriLower = strtolower($uri);
    foreach ($blockedPaths as $pattern) {
        if (stripos($uriLower, strtolower($pattern)) !== false) {
            wafLogAndBlock('path_probe', $pattern, $ip, $uri, $userAgent);
        }
    }
}

// 2. Random PHP file probe detection
if ($config['detect_php_probes']) {
    if (preg_match('/^\/[a-z0-9_]{2,8}\.php$/i', $uriPath)) {
        if (!in_array($uriPath, $legitimatePhpFiles, true)) {
            wafLogAndBlock('php_probe', $uriPath, $ip, $uri, $userAgent);
        }
    }
}

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

    // Return 403 Forbidden
    http_response_code(403);

    // Minimal response to save bandwidth
    header('Content-Type: text/plain; charset=utf-8');
    header('Connection: close');
    header('Cache-Control: no-store, no-cache, must-revalidate');

    exit('Forbidden');
}
