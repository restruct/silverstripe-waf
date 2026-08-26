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
 * - Self-contained IP banning for repeat offenders (optional, no framework needed)
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
// EARLY BANNING (self-contained fail2ban alternative)
// ============================================================================
// Tracks violations per IP using lightweight per-IP files. After threshold
// violations, bans the IP for all URLs (not just pattern matches).
//
// Config is read from a shared JSON file written by the middleware (from YAML).
// Falls back to defaults matching the YAML config if the file doesn't exist yet.
//
// Toggle via env: WAF_EARLY_BAN=false to disable, WAF_EARLY_BAN=true to enable.

// Data directory — unique per project, derived from module path
$wafDataDir = sys_get_temp_dir() . '/waf_' . substr(md5(__DIR__), 0, 8);

// Read config from shared file (written by middleware from YAML config values)
$earlyBanConfig = ['enabled' => true, 'threshold' => 10, 'duration' => 3600];
$wafConfigFile = $wafDataDir . '/config.json';
if (file_exists($wafConfigFile)) {
    $loadedConfig = json_decode(@file_get_contents($wafConfigFile), true);
    if (is_array($loadedConfig)) {
        $earlyBanConfig['enabled'] = $loadedConfig['early_ban_enabled'] ?? true;
        $earlyBanConfig['threshold'] = (int) ($loadedConfig['ban_threshold'] ?? 10);
        $earlyBanConfig['duration'] = (int) ($loadedConfig['ban_duration'] ?? 3600);
    }
}

// Env var override for enable/disable
if (getenv('WAF_EARLY_BAN') === 'false') {
    $earlyBanConfig['enabled'] = false;
} elseif (getenv('WAF_EARLY_BAN') === 'true') {
    $earlyBanConfig['enabled'] = true;
}


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

// 0. Early ban check — blocks ALL URLs from repeat offenders
//    Cost: one file_exists (~0.01ms) when enabled, 0ms when disabled
if ($earlyBanConfig['enabled'] && is_dir($wafDataDir)) {
    $banFile = $wafDataDir . '/ban_' . md5($ip);
    if (file_exists($banFile)) {
        $expires = (int) @file_get_contents($banFile);
        if ($expires > time()) {
            wafLogAndBlock('early_ban', 'Repeat offender', $ip, $uri, $userAgent);
        }
        // Expired — clean up
        @unlink($banFile);
    }
}

// 1. Path-based blocking — typed, anchored matching against the URL *path* only.
//    The query string is deliberately NOT part of the match target (waf#3: the old
//    unanchored stripos over the full REQUEST_URI blocked legitimate content like
//    /vacatures/healthcare-* via the '/health' pattern, and site-search query strings).
//    Inventory + semantics live in _waf_matching.php (shared with tests + exporter).
if ($config['detect_path_probes']) {
    require_once __DIR__ . '/_waf_matching.php';
    $matched = wafMatchBlockedPath($uriPath);
    if ($matched !== null) {
        wafLogAndBlock('path_probe', $matched['pattern'], $ip, $uri, $userAgent);
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

    // Track violation for early banning (skip for ban blocks to avoid double-counting)
    if ($reason !== 'early_ban') {
        wafTrackViolation($ip);
    }

    // Return 403 Forbidden
    http_response_code(403);

    // Minimal response to save bandwidth
    header('Content-Type: text/plain; charset=utf-8');
    header('Connection: close');
    header('Cache-Control: no-store, no-cache, must-revalidate');

    exit('Forbidden');
}

/**
 * Track a violation and ban IP if threshold reached
 *
 * Uses per-IP files to avoid cross-IP contention.
 * File format: "count:first_seen_timestamp"
 */
function wafTrackViolation(string $ip): void
{
    global $earlyBanConfig, $wafDataDir;

    if (!$earlyBanConfig['enabled']) {
        return;
    }

    if (!is_dir($wafDataDir)) {
        @mkdir($wafDataDir, 0755, true);
    }

    $violFile = $wafDataDir . '/viol_' . md5($ip);

    // Read current violation data
    $count = 0;
    $firstSeen = time();
    $data = @file_get_contents($violFile);

    if ($data !== false) {
        $parts = explode(':', $data, 2);
        $count = (int) ($parts[0] ?? 0);
        $firstSeen = (int) ($parts[1] ?? time());

        // Reset if violation window expired (older than ban duration)
        if ($firstSeen < time() - $earlyBanConfig['duration']) {
            $count = 0;
            $firstSeen = time();
        }
    }

    $count++;

    // Ban if threshold reached
    if ($count >= $earlyBanConfig['threshold']) {
        $banFile = $wafDataDir . '/ban_' . md5($ip);
        @file_put_contents($banFile, (string) (time() + $earlyBanConfig['duration']));
        @unlink($violFile);

        error_log(sprintf(
            '[WAF] EARLY_BAN ip=%s violations=%d duration=%d',
            $ip,
            $count,
            $earlyBanConfig['duration']
        ));
    } else {
        @file_put_contents($violFile, $count . ':' . $firstSeen);
    }

    // Occasional cleanup of expired files (1 in 100 chance)
    if (mt_rand(1, 100) === 1) {
        wafCleanupExpired($wafDataDir, $earlyBanConfig['duration']);
    }
}

/**
 * Clean up expired ban and violation files
 */
function wafCleanupExpired(string $dir, int $maxAge): void
{
    $cutoff = time() - $maxAge;
    $files = @scandir($dir);
    if (!$files) {
        return;
    }

    foreach ($files as $file) {
        // Skip dot files and the config file (written by middleware)
        if ($file[0] === '.' || $file === 'config.json') {
            continue;
        }
        $path = $dir . '/' . $file;
        if (@filemtime($path) < $cutoff) {
            @unlink($path);
        }
    }
}
