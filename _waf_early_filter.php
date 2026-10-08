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
//$wafDataDir = sys_get_temp_dir() . '/waf_' . substr(md5(__DIR__), 0, 8);
// Since waf#9 only a dir private to this process user (0700, ours, not a symlink): the old 0755 dir in
// the shared temp dir let anyone on the host read these files or plant their own. WAF_DATA_DIR (real
// env var) moves it. Null when it does not exist yet or is not private: then nothing is read from it.
require_once __DIR__ . '/_waf_datadir.php';
$wafDataDir = wafEarlyDataDir(__DIR__, false);

// Read config from shared file (written by middleware from YAML config values)
$earlyBanConfig = ['enabled' => true, 'threshold' => 10, 'duration' => 3600];
$wafConfigFile = $wafDataDir !== null ? $wafDataDir . '/config.json' : null;
if ($wafConfigFile !== null && file_exists($wafConfigFile)) {
    $loadedConfig = json_decode(@file_get_contents($wafConfigFile), true);
    if (is_array($loadedConfig)) {
        $earlyBanConfig['enabled'] = $loadedConfig['early_ban_enabled'] ?? true;
        $earlyBanConfig['threshold'] = (int) ($loadedConfig['ban_threshold'] ?? 10);
        $earlyBanConfig['duration'] = (int) ($loadedConfig['ban_duration'] ?? 3600);
        // Trusted proxies as the framework resolved them (SS_TRUSTED_PROXY_IPS, usually from .env)
        $wafConfigTrustedProxies = (string) ($loadedConfig['trusted_proxy_ips'] ?? '');
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
// The client address: REMOTE_ADDR, or the forwarded address when REMOTE_ADDR is a trusted proxy.
// Behind a reverse proxy or CDN, REMOTE_ADDR is the proxy, so bans and violation counts would hit
// the proxy and with it every visitor behind it. The header is only believed from a proxy listed in
// SS_TRUSTED_PROXY_IPS, as TrustedProxyMiddleware does: anyone can send X-Forwarded-For.
// That list is normally in .env, which the framework loads after this file has run. So: a real
// environment variable first (web server or FPM config), else the copy the middleware writes into
// config.json on an earlier request, else nothing trusted - REMOTE_ADDR, never the header blindly.
$wafTrustedProxies = (string) getenv('SS_TRUSTED_PROXY_IPS');
if (trim($wafTrustedProxies) === '') {
    $wafTrustedProxies = $wafConfigTrustedProxies ?? '';
}
$ip = wafClientIp($_SERVER, $wafTrustedProxies);
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';

// Skip whitelisted IPs
if (in_array($ip, $whitelistedIps, true)) {
    return;
}

// 0. Early ban check — blocks ALL URLs from repeat offenders
//    Cost: one file_exists (~0.01ms) when enabled, 0ms when disabled
//if ($earlyBanConfig['enabled'] && is_dir($wafDataDir)) {
if ($earlyBanConfig['enabled'] && $wafDataDir !== null) {
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
 * The client IP for this request: the forwarded address when REMOTE_ADDR is a trusted proxy, otherwise
 * REMOTE_ADDR ('unknown' when there is none). Mirrors TrustedProxyMiddleware on Silverstripe 5 and 6:
 * the same headers in the same order (Client-IP, then X-Forwarded-For) and the same choice from a list
 * (see wafIpFromHeaderValue()), so the early filter and the middleware ban the same visitor.
 */
function wafClientIp(array $server, string $trustedProxies): string
{
    $remoteAddr = (string) ($server['REMOTE_ADDR'] ?? '');
    if ($remoteAddr === '') {
        return 'unknown';
    }
    if (!wafIsTrustedProxy($remoteAddr, $trustedProxies)) {
        return $remoteAddr;
    }
    foreach (['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR'] as $header) {
        $value = trim((string) ($server[$header] ?? ''));
        if ($value === '') {
            continue;
        }
        $forwarded = wafIpFromHeaderValue($value);
        if ($forwarded !== null) {
            return $forwarded;
        }
    }
    return $remoteAddr;
}

/**
 * Whether $ip is in the trusted proxy list, read like TrustedProxyMiddleware::isTrustedProxy():
 * empty or 'none' trusts nobody, '*' trusts everyone, otherwise a comma-separated list of addresses
 * and CIDR ranges (IPv4 and IPv6).
 */
function wafIsTrustedProxy(string $ip, string $trustedProxies): bool
{
    $trustedProxies = trim($trustedProxies);
    if ($trustedProxies === '' || $trustedProxies === 'none') {
        return false;
    }
    if ($trustedProxies === '*') {
        return true;
    }
    foreach (preg_split('/\s*,\s*/', $trustedProxies) as $entry) {
        if ($entry !== '' && wafIpMatches($ip, $entry)) {
            return true;
        }
    }
    return false;
}

/**
 * Whether $ip is the address $entry, or falls in the CIDR range $entry. The framework uses Symfony's
 * IpUtils::checkIp() for this; this file runs before the autoloader, so it compares the packed bytes.
 */
function wafIpMatches(string $ip, string $entry): bool
{
    [$subnet, $bits] = str_contains($entry, '/') ? explode('/', $entry, 2) : [$entry, null];
    $ipBytes = @inet_pton($ip);
    $subnetBytes = @inet_pton($subnet);
    // Unparseable, or IPv4 against IPv6: no match
    if ($ipBytes === false || $subnetBytes === false || strlen($ipBytes) !== strlen($subnetBytes)) {
        return false;
    }
    $maxBits = strlen($ipBytes) * 8;
    # No ctype_digit(): ctype is an optional extension (shared on e.g. Debian/Ubuntu builds), and a fatal
    # here, before the framework, would take every proxied request down. PCRE is always compiled in.
    //$bits = $bits === null ? $maxBits : (ctype_digit($bits) ? (int) $bits : -1);
    $bits = $bits === null ? $maxBits : (preg_match('/^\d{1,3}$/', $bits) ? (int) $bits : -1);
    if ($bits < 0 || $bits > $maxBits) {
        return false;
    }
    // Whole bytes first, then the remaining bits of the next byte under a mask
    $fullBytes = intdiv($bits, 8);
    if (substr($ipBytes, 0, $fullBytes) !== substr($subnetBytes, 0, $fullBytes)) {
        return false;
    }
    $remainder = $bits % 8;
    if ($remainder === 0) {
        return true;
    }
    $mask = chr((0xFF << (8 - $remainder)) & 0xFF);
    return ($ipBytes[$fullBytes] & $mask) === ($subnetBytes[$fullBytes] & $mask);
}

/**
 * The address to use from a forwarding header, chosen as TrustedProxyMiddleware::getIPFromHeaderValue()
 * does: the first public address in the list, else the first non-private one, else the first valid one.
 * (Silverstripe 5 uses these filter_var flags; Silverstripe 6 the equivalent Symfony Ip constraints.)
 */
function wafIpFromHeaderValue(string $headerValue): ?string
{
    $ips = preg_split('/\s*,\s*/', $headerValue);
    $filters = [FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE, FILTER_FLAG_NO_PRIV_RANGE, 0];
    foreach ($filters as $flags) {
        foreach ($ips as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP, $flags) !== false) {
                return $ip;
            }
        }
    }
    return null;
}

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

    //if (!is_dir($wafDataDir)) {
    //    @mkdir($wafDataDir, 0755, true);
    //}
    # First violation on a fresh install: create the private dir (0700). No private dir to be had
    # (refused, or not writable): no early ban, the block itself still happened.
    if ($wafDataDir === null) {
        $wafDataDir = wafEarlyDataDir(__DIR__, true);
        if ($wafDataDir === null) {
            return;
        }
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
        //@file_put_contents($banFile, (string) (time() + $earlyBanConfig['duration']));
        # 0600 and atomic (temp file + rename): a concurrent ban check never reads a half-written file
        wafWriteDataFile($wafDataDir, basename($banFile), (string) (time() + $earlyBanConfig['duration']));
        @unlink($violFile);

        error_log(sprintf(
            '[WAF] EARLY_BAN ip=%s violations=%d duration=%d',
            $ip,
            $count,
            $earlyBanConfig['duration']
        ));
    } else {
        //@file_put_contents($violFile, $count . ':' . $firstSeen);
        wafWriteDataFile($wafDataDir, basename($violFile), $count . ':' . $firstSeen);
    }

    // Occasional cleanup of expired files (1 in 100 chance)
    if (mt_rand(1, 100) === 1) {
        wafCleanupExpired($wafDataDir, $earlyBanConfig['duration']);
    }
}

/**
 * Clean up expired ban and violation files
 *
 * Only the filter's own names (ban_<md5>, viol_<md5>, and .tmp-<hex> files of an interrupted write) are
 * ever deleted (waf#9 review): everything else, config.json included, is left alone, whatever its age.
 */
function wafCleanupExpired(string $dir, int $maxAge): void
{
    $cutoff = time() - $maxAge;
    $files = @scandir($dir);
    if (!$files) {
        return;
    }

    foreach ($files as $file) {
        //// Skip dot files and the config file (written by middleware)
        //if ($file[0] === '.' || $file === 'config.json') {
        //    # ...except a temp file wafWriteDataFile() left behind when a write was interrupted
        //    if (!str_starts_with($file, '.tmp-')) {
        //        continue;
        //    }
        //}
        # An allowlist, not a skip list: a skip list deleted any other file older than ban_duration,
        # which in a dir that also held other things (WAF_DATA_DIR pointing at the project) was theirs
        if (!wafIsDataFileName($file) && !wafIsDataTempFileName($file)) {
            continue;
        }
        $path = $dir . '/' . $file;
        if (@filemtime($path) < $cutoff) {
            @unlink($path);
        }
    }
}
