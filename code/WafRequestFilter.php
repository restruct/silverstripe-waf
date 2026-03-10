<?php

/**
 * WAF Request Filter - runs within Silverstripe 3 framework
 *
 * Implements the RequestFilter interface to intercept all requests.
 *
 * Features:
 * - Rate limiting per IP (with soft progressive delays)
 * - IP blocklist checking (threat intelligence feeds)
 * - User-agent filtering
 * - Auto-banning after violations
 * - Configurable logging (file/cache/database)
 *
 * Check order (optimized for performance):
 * 1. Whitelist (O(1) - skip all checks for trusted IPs)
 * 2. Ban check (O(1) cache lookup)
 * 3. Blocklist (O(1) with per-IP result caching, O(log n) first lookup)
 * 4. User-agent (fast regex)
 * 5. Rate limit (O(1) cache increment)
 *
 * SS3 backport: implements RequestFilter instead of HTTPMiddleware.
 */
class WafRequestFilter extends SS_Object implements RequestFilter
{
    // ========================================================================
    // Configuration (set via YAML)
    // ========================================================================

    private static $enabled = true;

    // Rate limiting
    private static $rate_limit_enabled = true;
    private static $rate_limit_requests = 100;
    private static $rate_limit_window = 60;

    // Soft rate limiting (progressive delays before hard block)
    private static $soft_rate_limit_enabled = true;
    private static $soft_rate_limit_threshold = 50;  # Start delaying at this % of hard limit
    private static $soft_rate_limit_max_delay = 3000; # Max delay in milliseconds

    // Auto-ban
    private static $auto_ban_enabled = true;
    private static $ban_threshold = 10;
    private static $ban_duration = 3600;

    // Logging
    private static $log_blocked_requests = true;

    // Whitelists
    private static $whitelisted_ips = array();
    private static $whitelisted_user_agents = array();

    // Blocklists
    private static $blocked_user_agents = array();

    // Error pages - use styled ErrorPage for rate limit responses
    private static $use_styled_error_pages = true;

    // ========================================================================
    // RequestFilter Interface
    // ========================================================================

    /**
     * Pre-request handler - runs WAF checks before the request is processed
     *
     * @param SS_HTTPRequest $request
     * @param Session $session
     * @param DataModel $model
     * @return bool|SS_HTTPResponse Return false or an SS_HTTPResponse to short-circuit
     */
    public function preRequest(SS_HTTPRequest $request, Session $session, DataModel $model)
    {
        // Skip if disabled
        if (!$this->config()->get('enabled')) {
            return true;
        }

        $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
        $userAgent = $request->getHeader('User-Agent');
        if ($userAgent === null) {
            $userAgent = '';
        }
        $uri = $request->getURL(true);

        // Skip whitelisted IPs
        if ($this->isWhitelistedIp($ip)) {
            return true;
        }

        // Check if IP is banned (cache or database)
        if ($this->isBanned($ip)) {
            $this->sendBlocked($request, $ip, $uri, $userAgent, 'banned', 'IP is banned');
            return false;
        }

        // Check IP against threat intelligence blocklists
        if ($this->isBlocklistedIp($ip)) {
            $this->recordViolation($ip, 'blocklist');
            $this->sendBlocked($request, $ip, $uri, $userAgent, 'blocklist', 'IP on threat blocklist');
            return false;
        }

        // Check user-agent against whitelist first
        if (!$this->isWhitelistedUserAgent($userAgent)) {
            // Check user-agent against blocklist
            if ($this->isBlockedUserAgent($userAgent)) {
                $this->recordViolation($ip, 'bad_useragent');
                $this->sendBlocked($request, $ip, $uri, $userAgent, 'bad_useragent', 'Blocked user-agent');
                return false;
            }
        }

        // Rate limiting
        if ($this->config()->get('rate_limit_enabled')) {
            $requestCount = $this->getRequestCount($ip);
            $hardLimit = $this->config()->get('rate_limit_requests');

            // Hard rate limit
            if ($requestCount >= $hardLimit) {
                $this->recordViolation($ip, 'rate_limit');
                $this->sendTooManyRequests($request, $ip, $uri, $userAgent);
                return false;
            }

            // Soft rate limiting (progressive delay)
            if ($this->config()->get('soft_rate_limit_enabled')) {
                $this->applySoftRateLimit($requestCount, $hardLimit);
            }

            $this->recordRequest($ip);
        }

        // Request passed all checks
        return true;
    }

    /**
     * Post-request handler (no-op)
     *
     * @param SS_HTTPRequest $request
     * @param SS_HTTPResponse $response
     * @param DataModel $model
     * @return bool
     */
    public function postRequest(SS_HTTPRequest $request, SS_HTTPResponse $response, DataModel $model)
    {
        return true;
    }

    // ========================================================================
    // IP Checking
    // ========================================================================

    /**
     * @param string $ip
     * @return bool
     */
    protected function isWhitelistedIp($ip)
    {
        $whitelist = $this->config()->get('whitelisted_ips');
        if (!is_array($whitelist)) {
            $whitelist = array();
        }

        // Also check environment variable
        $envWhitelist = getenv('WAF_WHITELIST_IPS');
        if ($envWhitelist) {
            $whitelist = array_merge($whitelist, array_map('trim', explode(',', $envWhitelist)));
        }

        foreach ($whitelist as $entry) {
            // Exact match
            if ($entry === $ip) {
                return true;
            }
            // CIDR match (e.g., "10.0.0.0/8")
            if (strpos($entry, '/') !== false && $this->ipMatchesCidr($ip, $entry)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if IP matches a CIDR range (for whitelist)
     *
     * @param string $ip
     * @param string $cidr
     * @return bool
     */
    protected function ipMatchesCidr($ip, $cidr)
    {
        if (strpos($cidr, '/') === false) {
            return false;
        }

        list($subnet, $bits) = explode('/', $cidr);
        $bits = (int) $bits;

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
            && filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ipLong = ip2long($ip);
            $subnetLong = ip2long($subnet);
            $mask = -1 << (32 - $bits);
            return ($ipLong & $mask) === ($subnetLong & $mask);
        }

        return false;
    }

    /**
     * @param string $ip
     * @return bool
     */
    protected function isBanned($ip)
    {
        return $this->getStorageService()->isBanned($ip);
    }

    /**
     * @param string $ip
     * @return bool
     */
    protected function isBlocklistedIp($ip)
    {
        try {
            /** @var WafIpBlocklistService $service */
            $service = Injector::inst()->get('WafIpBlocklistService');
            return $service->isBlocked($ip);
        } catch (Exception $e) {
            // Don't block on service failure
            return false;
        }
    }

    // ========================================================================
    // User-Agent Checking
    // ========================================================================

    /**
     * @param string $userAgent
     * @return bool
     */
    protected function isWhitelistedUserAgent($userAgent)
    {
        if (empty($userAgent)) {
            return false;
        }

        $patterns = $this->config()->get('whitelisted_user_agents');
        if (!is_array($patterns)) {
            return false;
        }

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param string $userAgent
     * @return bool
     */
    protected function isBlockedUserAgent($userAgent)
    {
        $patterns = $this->config()->get('blocked_user_agents');
        if (!is_array($patterns)) {
            return false;
        }

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                return true;
            }
        }

        return false;
    }

    // ========================================================================
    // Rate Limiting
    // ========================================================================

    /**
     * @param string $ip
     * @return int
     */
    protected function getRequestCount($ip)
    {
        $cache = $this->getCache();
        $key = 'rate_' . md5($ip);
        $count = $cache->load($key);
        return ($count !== false) ? (int) $count : 0;
    }

    /**
     * @param string $ip
     */
    protected function recordRequest($ip)
    {
        $cache = $this->getCache();
        $key = 'rate_' . md5($ip);
        $count = $cache->load($key);
        $count = ($count !== false) ? (int) $count : 0;

        $cache->save((string) ($count + 1), $key, array(), $this->config()->get('rate_limit_window'));
    }

    /**
     * Apply soft rate limiting - progressive delay as request count increases
     *
     * Example with defaults (threshold 50%, max_delay 3000ms, hard_limit 100):
     * - 50 requests: 0ms delay
     * - 75 requests: 1500ms delay
     * - 99 requests: 2940ms delay
     *
     * @param int $requestCount
     * @param int $hardLimit
     */
    protected function applySoftRateLimit($requestCount, $hardLimit)
    {
        $thresholdPercent = $this->config()->get('soft_rate_limit_threshold');
        $maxDelay = $this->config()->get('soft_rate_limit_max_delay');

        $softThreshold = (int) ($hardLimit * $thresholdPercent / 100);

        // No delay if under threshold
        if ($requestCount <= $softThreshold) {
            return;
        }

        // Calculate progressive delay
        $range = $hardLimit - $softThreshold;
        $excess = $requestCount - $softThreshold;
        $ratio = min(1.0, $excess / $range);

        $delayMs = (int) ($ratio * $maxDelay);

        if ($delayMs > 0) {
            // Log soft limiting (at debug level to avoid log spam)
            if ($delayMs >= 1000) {
                error_log(sprintf(
                    '[WAF] SOFT_LIMIT ip=%s requests=%d delay=%dms',
                    isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown',
                    $requestCount,
                    $delayMs
                ));
            }

            // Apply delay (usleep takes microseconds)
            usleep($delayMs * 1000);
        }
    }

    // ========================================================================
    // Violation & Banning
    // ========================================================================

    /**
     * @param string $ip
     * @param string $reason
     */
    protected function recordViolation($ip, $reason)
    {
        // Record for high-load detection
        $this->getStorageService()->recordViolation();

        if (!$this->config()->get('auto_ban_enabled')) {
            return;
        }

        $cache = $this->getCache();
        $violationKey = 'violations_' . md5($ip);
        $violations = $cache->load($violationKey);
        $violations = ($violations !== false) ? (int) $violations : 0;
        $violations++;

        // Log for fail2ban
        error_log(sprintf(
            '[WAF] VIOLATION reason=%s ip=%s count=%d',
            $reason,
            $ip,
            $violations
        ));

        // Auto-ban if threshold exceeded
        $threshold = $this->config()->get('ban_threshold');
        $banDuration = $this->config()->get('ban_duration');

        if ($violations >= $threshold) {
            $this->banIp($ip, $banDuration, "Auto-banned after {$violations} violations");
        } else {
            // Store violation count (expires after 1 hour)
            $cache->save((string) $violations, $violationKey, array(), 3600);
        }
    }

    /**
     * @param string $ip
     * @param int $duration
     * @param string $reason
     */
    protected function banIp($ip, $duration, $reason)
    {
        $this->getStorageService()->banIp($ip, $duration, $reason);

        // Log for fail2ban
        error_log(sprintf(
            '[WAF] BANNED ip=%s duration=%d reason="%s"',
            $ip,
            $duration,
            $reason
        ));
    }

    // ========================================================================
    // Response Helpers
    // ========================================================================

    /**
     * Send 403 Forbidden response and log the blocked request
     *
     * In SS3 RequestFilter, we can't return a response object from preRequest.
     * Instead we send headers directly and exit, or output the response manually.
     *
     * @param SS_HTTPRequest $request
     * @param string $ip
     * @param string $uri
     * @param string $userAgent
     * @param string $reason
     * @param string $detail
     */
    protected function sendBlocked($request, $ip, $uri, $userAgent, $reason, $detail)
    {
        $this->logBlockedRequest($ip, $uri, $userAgent, $reason, $detail);

        $response = new SS_HTTPResponse('Forbidden', 403);
        $response->addHeader('Content-Type', 'text/plain');
        $response->addHeader('Cache-Control', 'no-store');
        $response->output();
        exit;
    }

    /**
     * Send 429 Too Many Requests response
     *
     * @param SS_HTTPRequest $request
     * @param string $ip
     * @param string $uri
     * @param string $userAgent
     */
    protected function sendTooManyRequests($request, $ip, $uri, $userAgent)
    {
        $this->logBlockedRequest($ip, $uri, $userAgent, 'rate_limit', 'Rate limit exceeded');

        $retryAfter = (string) $this->config()->get('rate_limit_window');

        // Try to use styled ErrorPage for friendlier response to legitimate users
        if ($this->config()->get('use_styled_error_pages') && class_exists('ErrorPage')) {
            $errorPage = ErrorPage::get()->filter('ErrorCode', 429)->first();
            if ($errorPage) {
                $response = ModelAsController::controller_for($errorPage)->handleRequest(
                    new SS_HTTPRequest('GET', '/'),
                    DataModel::inst()
                );
                $response->setStatusCode(429);
                $response->addHeader('Retry-After', $retryAfter);
                $response->addHeader('Cache-Control', 'no-store');
                $response->output();
                exit;
            }
        }

        // Fallback to plain text
        $response = new SS_HTTPResponse('Too Many Requests', 429);
        $response->addHeader('Content-Type', 'text/plain');
        $response->addHeader('Retry-After', $retryAfter);
        $response->addHeader('Cache-Control', 'no-store');
        $response->output();
        exit;
    }

    /**
     * @param string $ip
     * @param string $uri
     * @param string $userAgent
     * @param string $reason
     * @param string $detail
     */
    protected function logBlockedRequest($ip, $uri, $userAgent, $reason, $detail)
    {
        // Log to error log (fail2ban compatible)
        if ($this->config()->get('log_blocked_requests')) {
            error_log(sprintf(
                '[WAF] BLOCKED reason=%s detail="%s" ip=%s uri="%s"',
                $reason,
                substr($detail, 0, 100),
                $ip,
                substr($uri, 0, 200)
            ));
        }

        // Log to storage (file or database depending on mode)
        $this->getStorageService()->logBlockedRequest($ip, $uri, $userAgent, $reason, $detail);
    }

    // ========================================================================
    // Utilities
    // ========================================================================

    /**
     * @return Zend_Cache_Core
     */
    protected function getCache()
    {
        return SS_Cache::factory('waf');
    }

    /**
     * @return WafStorageService
     */
    protected function getStorageService()
    {
        return Injector::inst()->get('WafStorageService');
    }
}
